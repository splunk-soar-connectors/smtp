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

import hmac

from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset
from soar_sdk.auth import AuthorizationCodeFlow
from soar_sdk.webhooks.models import WebhookRequest, WebhookResponse

from .oauth_migration import migrate_legacy_oauth_state


class Asset(BaseAsset):
    server: str = AssetField(description="Server IP/Hostname", required=True)
    port: int | None = AssetField(description="Port", default=None)
    auth_type: str | None = AssetField(
        description="Authentication type to use for connectivity",
        default="Automatic",
        value_list=["Automatic", "OAuth", "Basic", "Passwordless"],
    )
    username: str | None = AssetField(description="Username (or email address)", default=None)
    password: str | None = AssetField(description="Password (For Basic Auth)", sensitive=True, default=None)
    client_id: str | None = AssetField(description="OAuth Client ID (For OAuth)", default=None)
    client_secret: str | None = AssetField(description="OAuth Client Secret (For OAuth)", sensitive=True, default=None)
    auth_url: str | None = AssetField(description="OAuth Authorization URL (For OAuth)", default=None)
    token_url: str | None = AssetField(description="OAuth Token URL (For OAuth)", default=None)
    scopes: str | None = AssetField(description="OAuth API Scope (space-separated)(For OAuth)", default=None)
    sender_address: str | None = AssetField(description="Sender Address", default=None)
    ssl_config: str = AssetField(
        description="SSL Method",
        required=True,
        default="StartTLS",
        value_list=["None", "SSL", "StartTLS"],
    )
    verify_server_cert: bool | None = AssetField(description="Verify the SMTP server TLS certificate", default=True)
    allow_smtputf8: bool | None = AssetField(
        description="Enable SMTPUTF8 support (Check this only if the SMTP server supports SMTPUTF8 option)",
        default=True,
    )
    encoding: bool | None = AssetField(description="Enable Unicode support", default=True)


app = App(
    name="SMTP",
    app_type="email",
    logo="logo_splunk.svg",
    logo_dark="logo_splunk_dark.svg",
    product_vendor="Generic",
    product_name="SMTP",
    publisher="Splunk",
    appid="45bb6f37-4478-499b-b4a3-51ecfa62b78c",
    fips_compliant=True,
    asset_cls=Asset,
).enable_webhooks(default_requires_auth=False)


def authorization_flow(asset: Asset, asset_id: str) -> AuthorizationCodeFlow:
    migrate_legacy_oauth_state(asset)
    extra_auth_params = {"access_type": "offline"}
    if "gmail" in asset.server.lower():
        extra_auth_params["prompt"] = "consent"
    return AuthorizationCodeFlow(
        asset.auth_state,
        asset_id,
        client_id=asset.client_id or "",
        client_secret=asset.client_secret,
        authorization_endpoint=asset.auth_url or "",
        token_endpoint=asset.token_url or "",
        redirect_uri=app.get_webhook_url("oauth_callback"),
        scope=asset.scopes,
        use_pkce=False,
        extra_auth_params=extra_auth_params,
    )


@app.webhook("oauth_callback", allowed_methods=["GET"])
def oauth_callback(request: WebhookRequest[Asset]) -> WebhookResponse:
    query = {key: values[0] if values else "" for key, values in request.query.items()}
    if "error" in query:
        return WebhookResponse.text_response(f"Authorization failed: {query.get('error_description', query['error'])}", status_code=400)
    if not query.get("code"):
        return WebhookResponse.text_response("Missing authorization code", status_code=400)

    flow = authorization_flow(request.asset, str(request.asset_id))
    state = query.get("state", "")
    pending = flow.client.get_pending_session()
    if pending is None or not pending.state or not hmac.compare_digest(pending.state, state):
        return WebhookResponse.text_response("Invalid or expired authorization state", status_code=400)

    flow.set_authorization_code(query["code"])
    return WebhookResponse.text_response("Code received. Please close this window, the action will continue to get new token.")


from . import actions  # noqa: F401


if __name__ == "__main__":
    app.cli()
