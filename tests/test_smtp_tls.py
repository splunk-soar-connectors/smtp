# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import datetime
import os
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src import smtp_client
from src.app import Asset


class SMTPTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp_dir.cleanup)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SMTP unit test CA")])
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        cls.bundle = Path(cls.temp_dir.name) / "ca.pem"
        cls.bundle.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def setUp(self):
        self.asset = Asset(server="smtp.invalid", ssl_config="StartTLS", auth_type="Passwordless")
        self.soar = Mock()
        self.connection = Mock()

    def test_soar_bundle_is_loaded_for_ssl_and_starttls(self):
        for method in ("SSL", "StartTLS"):
            with self.subTest(method=method):
                self.asset.ssl_config = method
                with patch.dict(os.environ, {"REQUESTS_CA_BUNDLE": str(self.bundle)}):
                    with patch.object(smtp_client.smtplib, "SMTP", return_value=self.connection):
                        with patch.object(smtp_client.smtplib, "SMTP_SSL", return_value=self.connection) as smtp_ssl:
                            smtp_client.connect_smtp(self.asset, "Passwordless", self.soar)
                            if method == "SSL":
                                context = smtp_ssl.call_args.kwargs["context"]
                            else:
                                context = self.connection.starttls.call_args.kwargs["context"]
                self.assertEqual(context.cert_store_stats()["x509_ca"], 1)
                self.assertEqual(context.get_ca_certs()[0]["subject"], ((("commonName", "SMTP unit test CA"),),))
                self.assertTrue(context.check_hostname)
                self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_missing_or_empty_bundle_uses_default_trust(self):
        real_create = ssl.create_default_context
        for value in (None, ""):
            with self.subTest(bundle=value):
                with patch.dict(os.environ):
                    os.environ.pop("REQUESTS_CA_BUNDLE", None)
                    if value is not None:
                        os.environ["REQUESTS_CA_BUNDLE"] = value
                    with patch.object(smtp_client.ssl, "create_default_context", wraps=real_create) as create:
                        with patch.object(smtp_client.smtplib, "SMTP", return_value=self.connection):
                            smtp_client.connect_smtp(self.asset, "Passwordless", self.soar)
                    create.assert_called_once_with(cafile=None)

    def test_disabled_verification_is_preserved_for_both_tls_modes(self):
        self.asset.verify_server_cert = False
        for method in ("SSL", "StartTLS"):
            with self.subTest(method=method):
                self.asset.ssl_config = method
                with patch.dict(os.environ, {"REQUESTS_CA_BUNDLE": str(self.bundle)}):
                    with patch.object(smtp_client.smtplib, "SMTP", return_value=self.connection):
                        with patch.object(smtp_client.smtplib, "SMTP_SSL", return_value=self.connection) as smtp_ssl:
                            smtp_client.connect_smtp(self.asset, "Passwordless", self.soar)
                            context = (
                                smtp_ssl.call_args.kwargs["context"] if method == "SSL" else self.connection.starttls.call_args.kwargs["context"]
                            )
                self.assertFalse(context.check_hostname)
                self.assertEqual(context.verify_mode, ssl.CERT_NONE)

    def test_invalid_configured_bundle_fails_without_falling_back(self):
        invalid = Path(self.temp_dir.name) / "invalid.pem"
        invalid.write_text("not a certificate")
        for bundle in (str(invalid), str(invalid.with_name("missing.pem"))):
            with self.subTest(bundle=bundle):
                with patch.dict(os.environ, {"REQUESTS_CA_BUNDLE": bundle}):
                    with patch.object(smtp_client.smtplib, "SMTP") as smtp:
                        with self.assertRaises((ssl.SSLError, FileNotFoundError)):
                            smtp_client.connect_smtp(self.asset, "Passwordless", self.soar)
                        smtp.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
