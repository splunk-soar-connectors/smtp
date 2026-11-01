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

import json
import unittest
from pathlib import Path

from src.app import app


class ResultColumnTests(unittest.TestCase):
    def test_send_columns_match_legacy_without_new_data_fields(self):
        legacy_path = Path(__file__).resolve().parents[1] / "legacy" / "smtp.json"
        legacy = json.loads(legacy_path.read_text())
        actions = app.get_actions()
        for old in legacy["actions"]:
            identifier = old["identifier"]
            if identifier == "test_connectivity":
                continue
            with self.subTest(action=identifier):
                new = actions[identifier].meta.model_dump()
                expected = {
                    field["data_path"]: (field["column_name"], field["column_order"]) for field in old["output"] if "column_name" in field
                }
                actual = {field["data_path"]: (field["column_name"], field["column_order"]) for field in new["output"] if "column_name" in field}
                self.assertEqual(actual, expected)
                self.assertEqual(new["render"]["type"], "table")
                self.assertEqual(actions[identifier].meta.output.model_fields, {})
                paths = [field["data_path"] for field in new["output"]]
                self.assertEqual(len(paths), len(set(paths)))

    def test_connectivity_metadata_matches_legacy(self):
        legacy_path = Path(__file__).resolve().parents[1] / "legacy" / "smtp.json"
        legacy = json.loads(legacy_path.read_text())
        old = next(action for action in legacy["actions"] if action["identifier"] == "test_connectivity")
        new = app.get_actions()["test_connectivity"].meta.model_dump()
        for field in ("action", "identifier", "type", "read_only", "description", "versions"):
            with self.subTest(field=field):
                self.assertEqual(new[field], old[field])

    def test_connectivity_metadata_is_unaffected(self):
        meta = app.get_actions()["test_connectivity"].meta.model_dump()
        self.assertFalse(any("column_name" in field for field in meta["output"]))


if __name__ == "__main__":
    unittest.main()
