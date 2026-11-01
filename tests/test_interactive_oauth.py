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
import base64
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from soar_sdk.auth.client import (
    AuthorizationRequiredError,
    ConfigurationChangedError,
    TokenExpiredError,
    TokenRefreshError,
)
from soar_sdk.exceptions import ActionFailure

from src import smtp_client
from src.actions import send_email as email, send_htmlemail as html, send_rawemail as raw, test_connectivity as connectivity
from src.app import Asset


class InteractiveOAuthTests(unittest.TestCase):
    def setUp(self):
        self.asset = Asset(
            server="smtp.invalid",
            ssl_config="None",
            auth_type="OAuth",
            username="sender@example.com",
            client_id="client-id",
            client_secret="test-secret",  # pragma: allowlist secret
            auth_url="https://oauth.invalid/authorize",
            token_url="https://oauth.invalid/token",
        )
        self.soar = Mock()
        self.connection = Mock()
        self.connection.docmd.return_value = (235, b"Authenticated")
        self.connection.sendmail.return_value = {}
        self.flow = Mock()
        self.flow.get_token.return_value = SimpleNamespace(access_token="stored-token")  # pragma: allowlist secret
        self.flow.wait_for_authorization.return_value = SimpleNamespace(access_token="authorized-token")
        self.start_patch = patch.object(smtp_client.smtplib, "SMTP", return_value=self.connection)
        self.flow_patch = patch("src.app.authorization_flow", return_value=self.flow)
        self.start_patch.start()
        self.flow_patch.start()
        self.addCleanup(self.start_patch.stop)
        self.addCleanup(self.flow_patch.stop)

    def assert_no_interaction(self):
        self.flow.get_authorization_url.assert_not_called()
        self.flow.wait_for_authorization.assert_not_called()

    def test_send_actions_fail_promptly_without_authorization(self):
        cases = [
            (email.send_email, email.SendEmailParams(to="ok@example.com", body="Hello")),
            (html.send_htmlemail, html.SendHtmlemailParams(to="ok@example.com", html_body="<p>Hello</p>", should_sanitize_template=False)),
            (raw.send_rawemail, raw.SendRawemailParams(raw_email="From: sender@example.com\nTo: ok@example.com\n\nHello")),
        ]
        for action, params in cases:
            with self.subTest(action=action.__name__):
                self.connection.reset_mock()
                self.flow.get_token.side_effect = AuthorizationRequiredError("No token")
                with self.assertRaisesRegex(ActionFailure, "Run Test Connectivity"):
                    action.__wrapped__(params, self.soar, self.asset)
                self.assert_no_interaction()
                self.connection.sendmail.assert_not_called()
                self.connection.quit.assert_called_once()

    def test_expired_revoked_and_changed_credentials_fail_without_interaction(self):
        for error_type in (TokenExpiredError, TokenRefreshError, ConfigurationChangedError):
            with self.subTest(error=error_type.__name__):
                self.flow.get_token.side_effect = error_type("Authorization unavailable")
                with self.assertRaisesRegex(ActionFailure, "Run Test Connectivity"):
                    smtp_client.connect_smtp(self.asset, "OAuth", self.soar)
                self.assert_no_interaction()

    def test_existing_or_automatically_refreshed_token_is_used(self):
        conn = smtp_client.connect_smtp(self.asset, "OAuth", self.soar)
        self.assertIs(conn, self.connection)
        self.flow.get_token.assert_called_once_with()
        self.assert_no_interaction()
        expected = base64.b64encode(b"user=sender@example.com\x01auth=Bearer stored-token\x01\x01").decode()
        self.connection.docmd.assert_called_once_with("AUTH", f"XOAUTH2 {expected}")

    def test_connectivity_can_authorize_and_send_test_email(self):
        self.flow.get_token.side_effect = AuthorizationRequiredError("No token")
        self.flow.get_authorization_url.return_value = "https://oauth.invalid/authorize"
        connectivity.test_connectivity.__wrapped__(self.soar, self.asset)
        self.flow.get_authorization_url.assert_called_once_with()
        self.flow.wait_for_authorization.assert_called_once()
        self.connection.sendmail.assert_called_once()
        self.connection.quit.assert_called_once()
        self.soar.set_message.assert_called_once()

    def test_connectivity_can_reauthorize_after_refresh_or_config_failure(self):
        for error_type in (TokenExpiredError, TokenRefreshError, ConfigurationChangedError):
            with self.subTest(error=error_type.__name__):
                self.flow.reset_mock()
                self.flow.get_token.side_effect = error_type("Authorization unavailable")
                smtp_client.connect_smtp(self.asset, "OAuth", self.soar, allow_interactive=True)
                self.flow.wait_for_authorization.assert_called_once()

    def test_automatic_auth_falls_back_without_starting_oauth(self):
        self.asset.auth_type = "Automatic"
        self.asset.password = "test-password"  # pragma: allowlist secret
        self.flow.get_token.side_effect = AuthorizationRequiredError("No token")
        result = email.send_email.__wrapped__(email.SendEmailParams(to="ok@example.com", body="Hello"), self.soar, self.asset)
        self.assertTrue(result.get_status())
        self.assert_no_interaction()
        self.connection.login.assert_called_once_with("sender@example.com", "test-password")
        self.connection.sendmail.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
