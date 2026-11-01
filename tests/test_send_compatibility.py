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
import io
import json
import unittest
from email import message_from_string
from types import SimpleNamespace
from unittest.mock import Mock, patch

from src.actions import send_email as email, send_htmlemail as html, send_rawemail as raw
from src.app import Asset, app


class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.asset = Asset(server="smtp.invalid", ssl_config="None", auth_type="Passwordless", username="sender@example.com")
        self.soar = Mock()
        self.cases = [
            (email, email.send_email, email.SendEmailParams(**{"from": "sender@example.com", "to": "ok@example.com", "body": "hello"})),
            (
                html,
                html.send_htmlemail,
                html.SendHtmlemailParams(
                    **{"from": "sender@example.com", "to": "ok@example.com", "html_body": "<p>Hello</p>", "should_sanitize_template": False}
                ),
            ),
            (raw, raw.send_rawemail, raw.SendRawemailParams(raw_email="From: sender@example.com\nTo: ok@example.com\n\nHello")),
        ]

    def test_partial_refusals_all_actions_and_sdk_adapter(self):
        for module, action, params in self.cases:
            with self.subTest(action=action.__name__):
                conn = Mock()
                conn.sendmail.return_value = {"bad@example.com": (550, b"No such user\xff")}
                with patch.object(module, "connect_smtp", return_value=conn):
                    result = action.__wrapped__(params, self.soar, self.asset)
                self.assertFalse(result.get_status())
                self.assertEqual(
                    result.get_data(), [{"refused_recipients": {"bad@example.com": {"status_code": 550, "response": "No such user\ufffd"}}}]
                )
                self.assertEqual(result.get_summary(), {"refused_recipients": ["bad@example.com"]})
                self.assertIn("bad@example.com", result.get_message())
                if module is not raw:
                    self.assertEqual(result.get_param()["from"], "sender@example.com")
                    self.assertNotIn("from_address", result.get_param())
                manager = Mock()
                self.assertFalse(app._adapt_action_result(result, manager, params))
                manager.add_result.assert_called_once_with(result)
                conn.quit.assert_called_once()

    def test_success_empty_data_and_sender_alias_all_actions(self):
        for module, action, params in self.cases:
            with self.subTest(action=action.__name__):
                conn = Mock()
                conn.sendmail.return_value = {}
                with patch.object(module, "connect_smtp", return_value=conn):
                    result = action.__wrapped__(params, self.soar, self.asset)
                self.assertTrue(result.get_status())
                self.assertEqual(result.get_data(), [])
                if module is not raw:
                    self.assertIn("from", result.get_param())
                    self.assertNotIn("from_address", result.get_param())

    def test_custom_subject_and_bcc_all_composed_actions(self):
        for module, action, params in self.cases[:2]:
            with self.subTest(action=action.__name__):
                params.subject = "parameter subject"
                params.headers = json.dumps({"sUbJeCt": "custom subject", "bCc": "hidden@example.com"})
                params.bcc = "envelope@example.com"
                conn = Mock()
                conn.sendmail.return_value = {}
                with patch.object(module, "connect_smtp", return_value=conn):
                    action.__wrapped__(params, self.soar, self.asset)
                _sender, recipients, wire = conn.sendmail.call_args.args
                parsed = message_from_string(wire)
                self.assertEqual(parsed.get_all("Subject"), ["custom subject"])
                self.assertIsNone(parsed["Bcc"])
                self.assertIn("envelope@example.com", recipients)

    def test_raw_cc_bcc_only_and_quoted_display_names(self):
        msg = message_from_string(
            'From: sender@example.com\nCc: "Doe, Jane" <jane@example.com>\nBcc: secret@example.com\nBcc: other@example.com\n\nhello'
        )
        _sender, recipients = raw._get_recipients(msg)
        self.assertEqual(recipients, ["jane@example.com", "secret@example.com", "other@example.com"])
        self.assertIsNone(msg["Bcc"])
        msg = message_from_string('From: sender@example.com\nTo: "Doe, Jane" <jane@example.com>\n\nhello')
        self.assertEqual(raw._get_recipients(msg)[1], ["jane@example.com"])

    def test_text_and_rfc822_attachments(self):
        text = "Caf\u00e9 \u2615"
        nested = "From: nested@example.com\nTo: target@example.com\nSubject: nested\n\nNested body"
        files = {
            "text": SimpleNamespace(name="unicode.txt", open=lambda *args: io.StringIO(text)),
            "message": SimpleNamespace(name="forward.eml", open=lambda *args: io.StringIO(nested)),
        }
        self.soar.vault.get_attachment.side_effect = lambda **kwargs: [files[kwargs["vault_id"]]]
        params = email.SendEmailParams(to="ok@example.com", body="hello", attachments="text,message")
        message, _, invalid, _ = email._build_message(params, self.asset, "sender@example.com", self.soar)
        parsed = message_from_string(message.as_string())
        parts = parsed.get_payload()
        self.assertEqual(invalid, [])
        self.assertEqual(parts[1].get_content_charset(), "utf-8")
        self.assertEqual(parts[1].get_payload(decode=True).decode("utf-8"), text)
        self.assertEqual(parts[2].get_content_type(), "message/rfc822")
        self.assertEqual(parts[2].get_payload()[0]["Subject"], "nested")

    def test_attachment_read_errors_fail_instead_of_silently_skipping(self):
        attachment = Mock(name="broken")
        attachment.name = "broken.txt"
        attachment.open.side_effect = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid")
        self.soar.vault.get_attachment.return_value = [attachment]
        params = email.SendEmailParams(to="ok@example.com", body="hello", attachments="broken")
        from soar_sdk.exceptions import ActionFailure

        with self.assertRaises(ActionFailure):
            email._build_message(params, self.asset, "sender@example.com", self.soar)


if __name__ == "__main__":
    unittest.main(verbosity=2)
