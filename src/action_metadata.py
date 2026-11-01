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

from typing import Any

from soar_sdk.meta.actions import ActionMeta
from soar_sdk.types import Action


class ResultTableMeta(ActionMeta):
    """Label result-level columns without adding rows to action data."""

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        data = super().model_dump(*args, **kwargs)
        columns = {
            "action_result.status": ("Status", 0),
            "action_result.message": ("Message", 1),
        }
        for field in data["output"]:
            if column := columns.get(field["data_path"]):
                field["column_name"], field["column_order"] = column
        return data


def result_table_columns(action: Action) -> Action:
    action.meta = ResultTableMeta(**{name: getattr(action.meta, name) for name in ActionMeta.model_fields})
    return action
