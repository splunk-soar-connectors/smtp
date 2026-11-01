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

import smtplib
from email.message import EmailMessage

from soar_sdk.abstract import SOARClient
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from ..app import Asset, app
from ..smtp_client import close_smtp, connect_smtp


logger = getLogger()


def _send_test_email(connection: smtplib.SMTP, asset: Asset) -> None:
    sender = asset.sender_address or asset.username
    if not sender:
        raise ActionFailure("A sender address or username must be configured to send the test email.")

    message = EmailMessage()
    message["From"] = sender
    message["To"] = sender
    message["Subject"] = "Test SMTP config"
    message.set_content("This is a test mail, sent by the SOAR device,\nto test connectivity to the SMTP Asset.")
    mail_options = ["SMTPUTF8"] if asset.allow_smtputf8 else []
    refused = connection.sendmail(sender, [sender], message.as_string(), mail_options=mail_options)
    if refused:
        raise ActionFailure(f"SMTP refused test email recipient(s): {refused}")


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Validate the asset configuration for connectivity. This action logs into the device and sends a test email to check the connection and credentials"""
    logger.progress(f"Connecting to {asset.server}")
    auth_types = ["OAuth", "Basic", "Passwordless"] if asset.auth_type == "Automatic" else [asset.auth_type]
    errors = []

    for auth_type in auth_types:
        logger.progress(f"Trying {auth_type} authentication")
        connection = None
        try:
            connection = connect_smtp(asset, auth_type, soar, allow_interactive=True)
            if auth_type != "Passwordless":
                logger.progress("Sending test email")
                _send_test_email(connection, asset)
            soar.set_message(f"Connectivity test succeeded using {auth_type} authentication.")
            return
        except Exception as exc:
            errors.append(f"{auth_type}: {exc}")
            if asset.auth_type != "Automatic":
                raise ActionFailure(f"Connectivity test failed using {auth_type} authentication: {exc}") from exc
        finally:
            if connection:
                close_smtp(connection)

    raise ActionFailure("Connectivity test failed. " + "; ".join(errors))


# The SDK decorator defaults to read-only; this connectivity test sends mail.
test_connectivity.meta.read_only = False
