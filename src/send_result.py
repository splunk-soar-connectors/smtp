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

from soar_sdk.action_results import ActionResult
from soar_sdk.params import Params

from .consts import SMTP_ERROR_SMTP_SEND_EMAIL


def send_result(params: Params, message: str, refused: dict | None = None) -> ActionResult:
    result = ActionResult(not bool(refused), message, param=params.model_dump(by_alias=True, exclude_unset=True))
    if refused:
        details = {}
        for recipient, (status_code, response) in refused.items():
            if isinstance(response, bytes):
                response = response.decode(errors="replace")
            details[recipient] = {"status_code": status_code, "response": str(response)}
        result.add_data({"refused_recipients": details})
        result.set_summary({"refused_recipients": sorted(details)})
        result.set_status(False, f"{SMTP_ERROR_SMTP_SEND_EMAIL}. Server refused the following recipients: {', '.join(sorted(details))}")
    return result
