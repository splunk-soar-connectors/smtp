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

from email import message_from_string
from email.message import Message
from email.utils import getaddresses

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..action_metadata import result_table_columns
from ..app import Asset, app
from ..consts import (
    SMTP_ERROR_SMTP_SEND_EMAIL,
    SMTP_ERROR_SMTPUTF8_CONFIG,
    SMTP_ERROR_TO_FROM_UNAVAILABLE,
    SMTP_SUCC_SMTP_EMAIL_SENT,
)
from ..send_result import send_result
from ..smtp_client import close_smtp, connect_smtp


logger = getLogger()


class SendRawemailParams(Params):
    raw_email: str = Param(
        description="Fully specified email message including all headers",
        required=True,
    )


class SendRawemailOutput(ActionOutput):
    pass


def _get_recipients(message: Message) -> tuple[str, list[str]]:
    sender = message.get("from", "")
    if not sender:
        raise ActionFailure(SMTP_ERROR_TO_FROM_UNAVAILABLE.format("sender (from)"))
    recipient_headers = []
    for name in ("to", "cc", "bcc"):
        recipient_headers.extend(message.get_all(name, []))
    recipients = [address for _, address in getaddresses(recipient_headers) if address]
    if not recipients:
        raise ActionFailure(SMTP_ERROR_TO_FROM_UNAVAILABLE.format("recipient (to)"))
    if "Bcc" in message:
        del message["Bcc"]
    return sender, recipients


@result_table_columns
@app.action(
    description="Takes a fully specified email and sends it unmodified to the smtp server. Sender and Recipient(s) will be extracted from message headers; Suggest using the standard email package to build message and export with the .as_string() method",
    action_type="generic",
    read_only=False,
    render_as="table",
    params_class=SendRawemailParams,
    output_class=SendRawemailOutput,
)
def send_rawemail(params: SendRawemailParams, soar: SOARClient, asset: Asset):
    logger.progress("Sending raw email")
    auth_types = ["OAuth", "Basic", "Passwordless"] if asset.auth_type == "Automatic" else [asset.auth_type]
    errors = []
    connection = None
    for candidate in auth_types:
        try:
            connection = connect_smtp(asset, candidate, soar)
            break
        except Exception as exc:
            errors.append(f"{candidate}: {exc}")
            if asset.auth_type != "Automatic":
                raise ActionFailure(f"Authentication failed using {candidate}: {exc}") from exc
    if connection is None:
        raise ActionFailure("Authentication failed for all configured methods. " + "; ".join(errors))

    try:
        raw_email = params.raw_email.replace("\\n", "\n")
        message = message_from_string(raw_email)
        sender, recipients = _get_recipients(message)
        mail_options = ["SMTPUTF8"] if asset.allow_smtputf8 else []
        refused = connection.sendmail(sender, recipients, message.as_string(), mail_options=mail_options)
        if refused:
            return send_result(params, "", refused)
    except UnicodeEncodeError as exc:
        raise ActionFailure(f"{SMTP_ERROR_SMTP_SEND_EMAIL}. {SMTP_ERROR_SMTPUTF8_CONFIG}") from exc
    except ActionFailure:
        raise
    except Exception as exc:
        raise ActionFailure(f"{SMTP_ERROR_SMTP_SEND_EMAIL}. {exc}") from exc
    finally:
        close_smtp(connection)

    soar.set_message(SMTP_SUCC_SMTP_EMAIL_SENT)
    logger.info(SMTP_SUCC_SMTP_EMAIL_SENT)
    return send_result(params, SMTP_SUCC_SMTP_EMAIL_SENT)
