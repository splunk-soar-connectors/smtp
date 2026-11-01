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

from __future__ import annotations

import base64
import os
import re
import smtplib
import ssl
from typing import TYPE_CHECKING

from soar_sdk.abstract import SOARClient
from soar_sdk.auth.client import (
    AuthorizationRequiredError,
    ConfigurationChangedError,
    TokenExpiredError,
    TokenRefreshError,
)
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger


if TYPE_CHECKING:
    from .app import Asset


logger = getLogger()


def clean_from_field(value: str) -> str:
    match = re.match(r"^(.*?)<mailto:(.*?)>$", value.strip())
    if match:
        return f"{match.group(1).strip()} {match.group(2).strip()}"
    return value


def connect_smtp(asset: Asset, auth_type: str, soar: SOARClient, *, allow_interactive: bool = False) -> smtplib.SMTP:
    context = ssl.create_default_context(cafile=os.environ.get("REQUESTS_CA_BUNDLE") or None)
    if asset.verify_server_cert is False:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    smtp_class = smtplib.SMTP_SSL if asset.ssl_config == "SSL" else smtplib.SMTP
    kwargs = {"context": context} if smtp_class is smtplib.SMTP_SSL else {}
    connection = smtp_class(asset.server, **kwargs) if asset.port is None else smtp_class(asset.server, asset.port, **kwargs)
    try:
        connection.ehlo()
        if asset.ssl_config == "StartTLS":
            connection.starttls(context=context)
            connection.ehlo()

        if auth_type == "OAuth":
            from .app import authorization_flow

            required = {
                "username": asset.username,
                "client_id": asset.client_id,
                "client_secret": asset.client_secret,
                "auth_url": asset.auth_url,
                "token_url": asset.token_url,
            }
            missing = [name for name, value in required.items() if not value]
            if missing:
                raise ActionFailure(f"OAuth authentication requires: {', '.join(missing)}")

            flow = authorization_flow(asset, soar.get_asset_id())
            try:
                token = flow.get_token()
            except (AuthorizationRequiredError, ConfigurationChangedError, TokenExpiredError, TokenRefreshError) as exc:
                if not allow_interactive:
                    raise ActionFailure("OAuth authorization is unavailable. Run Test Connectivity to authorize this asset.") from exc
                url = flow.get_authorization_url()
                logger.progress(f"Authorize SMTP access in a separate browser tab: {url}")
                token = flow.wait_for_authorization(on_progress=lambda i: logger.info(f"Waiting for authorization... ({i})"))

            auth_string = f"user={asset.username}\x01auth=Bearer {token.access_token}\x01\x01"
            response_code, response_message = connection.docmd("AUTH", f"XOAUTH2 {base64.b64encode(auth_string.encode()).decode()}")
            if response_code != 235:
                raise smtplib.SMTPAuthenticationError(response_code, response_message)
        elif auth_type == "Basic":
            if not asset.username or not asset.password:
                raise ActionFailure("Basic authentication requires a username and password.")
            connection.login(asset.username, asset.password)
        elif auth_type != "Passwordless":
            raise ActionFailure(f"Unsupported authentication type: {auth_type}")
        return connection
    except Exception:
        try:
            connection.quit()
        except Exception:
            connection.close()
        raise


def close_smtp(connection: smtplib.SMTP) -> None:
    try:
        connection.quit()
    except Exception:
        connection.close()
