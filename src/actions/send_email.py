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
import mimetypes
import re
from email import encoders, message_from_file
from email.message import Message
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.message import MIMEMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from bs4 import BeautifulSoup
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..action_metadata import result_table_columns
from ..app import Asset, app
from ..send_result import send_result
from ..smtp_client import clean_from_field, close_smtp, connect_smtp


logger = getLogger()


class SendEmailParams(Params):
    from_address: str | None = Param(
        alias="from",
        description="Sender Address",
        required=False,
        primary=True,
        default=None,
        cef_types=["email"],
    )
    to: str = Param(
        description="List of recipients email addresses",
        required=True,
        primary=True,
        allow_list=True,
        cef_types=["email"],
    )
    cc: str | None = Param(
        description="List of recipients email addresses to include on cc line",
        required=False,
        primary=True,
        allow_list=True,
        default=None,
        cef_types=["email"],
    )
    bcc: str | None = Param(
        description="List of recipients email addresses to include on bcc line",
        required=False,
        primary=True,
        allow_list=True,
        default=None,
        cef_types=["email"],
    )
    subject: str | None = Param(description="Message Subject", required=False, default=None)
    body: str = Param(description="Message body", required=True)
    attachments: str | None = Param(
        description="Vault IDs of files to attach",
        required=False,
        primary=True,
        allow_list=True,
        default=None,
        cef_types=["vault id"],
    )
    headers: str | None = Param(description="Custom email headers (formatted as JSON)", required=False, default=None)


class SendEmailOutput(ActionOutput):
    pass


def _is_html(body: str) -> bool:
    body_lower = body.lower()
    return bool(re.match(r"^<!doctype\s+html.*?>", body_lower) or re.match(r"^<html.*?>", body_lower))


def _recipients(value: str | None) -> list[str]:
    if not value:
        return []
    return [recipient for item in value.split(",") if (recipient := item.strip())]


def _add_vault_attachments(message: Message, soar: SOARClient, ids: str | None) -> list[str]:
    invalid_ids = []
    for vault_id in _recipients(ids):
        try:
            attachments = soar.vault.get_attachment(vault_id=vault_id, container_id=soar.get_executing_container_id())
            if not attachments:
                attachments = soar.vault.get_attachment(vault_id=vault_id)
            if not attachments:
                invalid_ids.append(vault_id)
                continue
            attachment = attachments[0]
            filename = Path(attachment.name).name
            content_type, encoding = mimetypes.guess_type(filename)
            if content_type is None or encoding is not None:
                content_type = "application/octet-stream"
            maintype, subtype = content_type.split("/", 1)
            try:
                if maintype == "text":
                    with attachment.open() as file_obj:
                        part = MIMEText(file_obj.read(), _subtype=subtype)
                elif maintype == "message":
                    with attachment.open() as file_obj:
                        part = MIMEMessage(message_from_file(file_obj), _subtype=subtype)
                elif maintype == "image":
                    with attachment.open("rb") as file_obj:
                        part = MIMEImage(file_obj.read(), _subtype=subtype)
                else:
                    with attachment.open("rb") as file_obj:
                        part = MIMEBase(maintype, subtype)
                        part.set_payload(file_obj.read())
                    encoders.encode_base64(part)
            except Exception as exc:
                raise ActionFailure(f"Failed to read attachment {vault_id}: {exc}") from exc
            part.add_header("Content-Disposition", "attachment", filename=filename)
            message.attach(part)
        except ActionFailure:
            raise
        except Exception:
            invalid_ids.append(vault_id)
    return invalid_ids


def _build_message(params: SendEmailParams, asset: Asset, sender: str, soar: SOARClient) -> tuple[Message, list[str], list[str], str]:
    if params.headers:
        try:
            headers = json.loads(params.headers)
            if not isinstance(headers, dict):
                raise ValueError
        except Exception as exc:
            raise ActionFailure(f"Unable to parse headers as a JSON object: {params.headers}") from exc
    else:
        headers = {}

    charset = "utf-8" if asset.encoding else "us-ascii"
    if _is_html(params.body):
        message = MIMEMultipart("alternative")
        message.attach(MIMEText(BeautifulSoup(params.body, "html.parser").get_text(), "plain", charset))
        message.attach(MIMEText(params.body, "html", charset))
    elif params.attachments:
        message = MIMEMultipart()
        message.attach(MIMEText(params.body, "plain", charset))
    else:
        message = MIMEText(params.body, "plain", charset)
    for name, value in headers.items():
        if name.lower() != "bcc":
            message[name] = value

    if params.subject is not None and "Subject" not in message:
        message["Subject"] = params.subject

    to_list = _recipients(params.to)
    if not to_list:
        raise ActionFailure("At least one recipient must be specified in 'to'.")
    cc_list = _recipients(params.cc)
    bcc_list = _recipients(params.bcc)

    if "From" in message and params.from_address:
        del message["From"]
        message["From"] = sender
    elif "From" in message:
        sender = str(message["From"])
    else:
        message["From"] = sender

    message["To"] = ", ".join(to_list)
    if cc_list:
        message["CC"] = ",".join(cc_list)

    invalid_ids = _add_vault_attachments(message, soar, params.attachments)
    return message, to_list + cc_list + bcc_list, invalid_ids, sender


@result_table_columns
@app.action(
    description="Sends an email",
    action_type="generic",
    read_only=False,
    render_as="table",
    verbose="""Some points to note: <ul> <li>Only files present in the <b>vault</b> can be attached to the email.</li> <li>To send HTML emails, specify a HTML formatted text (i.e. <html>....</html>) in the <b>body</b> parameter. The app sends a multipart email containing plain and html <i>Content-Type</i>.</li> <li>The <b>to</b> parameter supports comma separated email addresses.</li> <li>If the "Subject" is provided in the <b>subject</b> and the <b>headers</b> parameter, then the "Subject" provided in the <b>headers</b> parameter will be preferred and the action will run accordingly.</li> <li> In the playbooks, if you don't provide any value for 'from' field in actions, it will take value from the platform email setting. If in the email settings also it is empty, it will consider the username parameter provided in the asset configuration as the sender's email address</li> </ul>.""",
    params_class=SendEmailParams,
    output_class=SendEmailOutput,
)
def send_email(params: SendEmailParams, soar: SOARClient, asset: Asset):
    logger.progress("Sending email")
    sender_value = params.from_address if params.from_address is not None else (asset.sender_address or asset.username or "")
    sender = clean_from_field(sender_value)
    if not sender:
        raise ActionFailure("Error: failed to get email sender")

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
        message, recipients, invalid_ids, sender = _build_message(params, asset, sender, soar)
        mail_options = ["SMTPUTF8"] if asset.allow_smtputf8 else []
        refused = connection.sendmail(sender, recipients, message.as_string(), mail_options=mail_options)
        if refused:
            return send_result(params, "", refused)
    except UnicodeEncodeError as exc:
        raise ActionFailure("SMTPUTF8 must be enabled to send Unicode recipients.") from exc
    except ActionFailure:
        raise
    except Exception as exc:
        raise ActionFailure(f"SMTP email send failed: {exc}") from exc
    finally:
        close_smtp(connection)

    message_text = "Email sent"
    if invalid_ids:
        message_text += f". The following attachments are invalid and were not sent: {', '.join(invalid_ids)}"
    soar.set_message(message_text)
    logger.info(message_text)
    return send_result(params, message_text)
