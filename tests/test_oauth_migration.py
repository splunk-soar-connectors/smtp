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
import copy
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from src.app import app, authorization_flow
from src.oauth_migration import MIGRATION_KEY, migrate_legacy_oauth_state


class MemoryAuthState:
    def __init__(self, legacy=None, current=None):
        self.current = copy.deepcopy(current or {})
        self.backend = Mock()
        self.backend.load_state.return_value = copy.deepcopy(legacy or {})
        self.asset_id = "123"
        self.put_all = Mock(side_effect=self.save)

    def get_all(self):
        return copy.deepcopy(self.current)

    def save(self, value):
        self.current = copy.deepcopy(value)


class OAuthMigrationTests(unittest.TestCase):
    def make_asset(self, legacy=None, current=None, server="smtp.gmail.com"):
        return SimpleNamespace(
            auth_state=MemoryAuthState(legacy, current),
            client_id="client-id",
            client_secret="test-secret",  # pragma: allowlist secret
            auth_url="https://accounts.example/authorize",
            token_url="https://accounts.example/token",
            scopes="mail",
            server=server,
        )

    def test_plaintext_migration_preserves_state_and_is_idempotent(self):
        legacy = {
            "client_id": "client-id",
            "oauth_token": {
                "access_token": "old-access",
                "refresh_token": "old-refresh",
                "scope": "mail",
            },
        }
        asset = self.make_asset(legacy, {"unrelated": {"keep": True}})
        migrate_legacy_oauth_state(asset)
        state = asset.auth_state.current
        self.assertEqual(
            state["oauth"]["token"],
            {
                "access_token": "old-access",
                "refresh_token": "old-refresh",
                "expires_at": 0,
                "scope": "mail",
                "token_type": "Bearer",
            },
        )
        self.assertEqual(state["unrelated"], {"keep": True})
        self.assertEqual(asset.auth_state.backend.load_state.return_value, legacy)
        migrate_legacy_oauth_state(asset)
        asset.auth_state.put_all.assert_called_once()
        state["oauth"]["token"] = None
        migrate_legacy_oauth_state(asset)
        self.assertIsNone(state["oauth"]["token"])
        asset.auth_state.put_all.assert_called_once()

    def test_encrypted_tokens_use_asset_salt(self):
        asset = self.make_asset(
            {
                "is_encrypted": True,
                "oauth_token": {
                    "access_token": "cipher-access",
                    "refresh_token": "cipher-refresh",
                },
            }
        )
        with patch("src.oauth_migration.encryption_helper.decrypt", side_effect=["clear-access", "clear-refresh"]) as decrypt:
            migrate_legacy_oauth_state(asset)
        self.assertEqual(decrypt.call_args_list[0].args, ("cipher-access", "123"))
        self.assertEqual(decrypt.call_args_list[1].args, ("cipher-refresh", "123"))
        self.assertEqual(asset.auth_state.current["oauth"]["token"]["refresh_token"], "clear-refresh")

    def test_decryption_failure_leaves_state_untouched(self):
        asset = self.make_asset({"is_encrypted": True, "oauth_token": {"access_token": "cipher"}})
        with patch("src.oauth_migration.encryption_helper.decrypt", side_effect=ValueError("decrypt failed")):
            with self.assertRaises(ValueError):
                migrate_legacy_oauth_state(asset)
        asset.auth_state.put_all.assert_not_called()

    def test_existing_sdk_tokens_are_not_overwritten(self):
        current = {"oauth": {"token": {"access_token": "sdk-token"}, "client_id": "client-id"}}
        asset = self.make_asset({"oauth_token": {"access_token": "legacy-token"}}, current)
        migrate_legacy_oauth_state(asset)
        self.assertEqual(asset.auth_state.current, current)
        asset.auth_state.backend.load_state.assert_not_called()
        asset.auth_state.put_all.assert_not_called()

    def test_absent_malformed_empty_and_different_client_state_are_skipped(self):
        for legacy in (
            {},
            {"oauth_token": "invalid"},
            {"oauth_token": {}},
            {"client_id": "another-client", "oauth_token": {"access_token": "legacy-token"}},
        ):
            with self.subTest(legacy=legacy):
                asset = self.make_asset(legacy)
                migrate_legacy_oauth_state(asset)
                asset.auth_state.put_all.assert_not_called()

    def test_refresh_only_legacy_token_is_migrated(self):
        asset = self.make_asset({"oauth_token": {"refresh_token": "refresh-only"}})
        migrate_legacy_oauth_state(asset)
        self.assertEqual(asset.auth_state.current["oauth"]["token"]["access_token"], "")
        self.assertEqual(asset.auth_state.current["oauth"]["token"]["expires_at"], 0)

    def test_access_only_legacy_token_retains_known_expiry(self):
        asset = self.make_asset({"oauth_token": {"access_token": "access-only", "expires_at": 123}})
        migrate_legacy_oauth_state(asset)
        self.assertEqual(asset.auth_state.current["oauth"]["token"]["expires_at"], 123)

    def test_authorization_url_requests_offline_and_gmail_consent(self):
        for server, consent in [("smtp.gmail.com", True), ("SMTP.GMAIL.COM", True), ("smtp.office365.com", False)]:
            with self.subTest(server=server):
                asset = self.make_asset(server=server)
                with patch.object(app, "get_webhook_url", return_value="https://soar.example/callback"):
                    flow = authorization_flow(asset, "123")
                query = parse_qs(urlsplit(flow.get_authorization_url()).query)
                self.assertEqual(query["access_type"], ["offline"])
                self.assertEqual(query.get("prompt"), ["consent"] if consent else None)
                self.assertEqual(query["scope"], ["mail"])
                self.assertTrue(query["state"])

    def test_migrated_refresh_token_is_usable_by_real_sdk_flow(self):
        asset = self.make_asset(
            {
                "client_id": "client-id",
                "oauth_token": {
                    "access_token": "old-access",
                    "refresh_token": "old-refresh",
                },
            }
        )
        with patch.object(app, "get_webhook_url", return_value="https://soar.example/callback"):
            flow = authorization_flow(asset, "123")
        response = Mock()
        response.json.return_value = {"access_token": "fresh-access", "expires_in": 3600}
        with patch.object(flow.client._http_client, "post", return_value=response) as post:
            token = flow.get_token()
        self.assertEqual(token.access_token, "fresh-access")
        self.assertEqual(post.call_args.kwargs["data"]["refresh_token"], "old-refresh")
        self.assertEqual(asset.auth_state.current["oauth"]["token"]["access_token"], "fresh-access")
        self.assertEqual(asset.auth_state.current["oauth"]["token"]["refresh_token"], "old-refresh")
        self.assertTrue(asset.auth_state.current[MIGRATION_KEY])


if __name__ == "__main__":
    unittest.main(verbosity=2)
