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

from typing import TYPE_CHECKING

from soar_sdk.shims.phantom.encryption_helper import encryption_helper


if TYPE_CHECKING:
    from .app import Asset


MIGRATION_KEY = "smtp_legacy_oauth_migrated"


def migrate_legacy_oauth_state(asset: Asset) -> None:
    """Temporary upgrade bridge from legacy SMTP token state to SDK auth state."""
    auth_state = asset.auth_state
    current_state = auth_state.get_all()
    current_oauth = current_state.get("oauth")
    if current_state.get(MIGRATION_KEY):
        return
    if isinstance(current_oauth, dict) and current_oauth.get("token"):
        return

    legacy_state = auth_state.backend.load_state() or {}
    if not isinstance(legacy_state, dict):
        return
    legacy_token = legacy_state.get("oauth_token")
    if not isinstance(legacy_token, dict):
        return
    legacy_client_id = legacy_state.get("client_id")
    if legacy_client_id and legacy_client_id != asset.client_id:
        return

    access_token = legacy_token.get("access_token")
    refresh_token = legacy_token.get("refresh_token")
    if legacy_state.get("is_encrypted"):
        if access_token:
            access_token = encryption_helper.decrypt(access_token, auth_state.asset_id)
        if refresh_token:
            refresh_token = encryption_helper.decrypt(refresh_token, auth_state.asset_id)
    if not access_token and not refresh_token:
        return

    sdk_token = {
        "access_token": access_token or "",
        "token_type": legacy_token.get("token_type") or "Bearer",
    }
    if refresh_token:
        sdk_token["refresh_token"] = refresh_token
        sdk_token["expires_at"] = 0
    elif legacy_token.get("expires_at") is not None:
        sdk_token["expires_at"] = legacy_token["expires_at"]
    if scope := legacy_token.get("scope"):
        sdk_token["scope"] = scope

    migrated_state = dict(current_state)
    migrated_state["oauth"] = {"token": sdk_token, "client_id": asset.client_id}
    migrated_state[MIGRATION_KEY] = True
    auth_state.put_all(migrated_state)
