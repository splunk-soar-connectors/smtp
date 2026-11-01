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
from email import encoders, message_from_file
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
from ..consts import (
    BLEACH_SAFE_HTML_ATTRIBUTES,
    SMTP_BLEACH_ALLOWED_PROTOCOLS,
    SMTP_ERROR_SMTP_SEND_EMAIL,
    SMTP_ERROR_SMTPUTF8_CONFIG,
    SMTP_SUCC_SMTP_EMAIL_SENT,
    SMTP_UNICODE_ERROR_MESSAGE,
)
from ..send_result import send_result
from ..smtp_client import clean_from_field, close_smtp, connect_smtp


logger = getLogger()


class SendHtmlemailParams(Params):
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
    headers: str | None = Param(
        description="Serialized json dictionary. Additional email headers to be added to the message",
        required=False,
        default=None,
    )
    html_body: str = Param(description="Html rendering of message", required=True)
    text_body: str | None = Param(description="Text rendering of message", required=False, default=None)
    attachment_json: str | None = Param(
        description='Serialized json list of attachments, including images. Any additional attachments specified will be update this list. Each attachment requires a vault id and an optional unique content-id. The content-id is required if the html refers to the attachment. The format of the json is a list of dictionaries. Each dictionary will contain a vault_id key and optionally a content_id key. ie. [{"vault_id": "first_vault id", "content_id": "a_unique_content_id"}, {"vault_id": "second_vault_id"}]',
        required=False,
        default=None,
    )
    attachment1: str | None = Param(description="Vault id for attachment", required=False, default=None)
    content_id1: str | None = Param(
        description="Optional content-id for attachment, typically used in image link referrals",
        required=False,
        default=None,
    )
    attachment2: str | None = Param(description="Vault id for attachment", required=False, default=None)
    content_id2: str | None = Param(
        description="Optional content-id for attachment, typically used in image link referrals",
        required=False,
        default=None,
    )
    attachment3: str | None = Param(description="Vault id for attachment", required=False, default=None)
    content_id3: str | None = Param(
        description="Optional content-id for attachment, typically used in image link referrals",
        required=False,
        default=None,
    )
    attachment4: str | None = Param(description="Vault id for attachment", required=False, default=None)
    content_id4: str | None = Param(
        description="Optional content-id for attachment, typically used in image link referrals",
        required=False,
        default=None,
    )
    attachment5: str | None = Param(description="Vault id for attachment", required=False, default=None)
    content_id5: str | None = Param(
        description="Optional content-id for attachment, typically used in image link referrals",
        required=False,
        default=None,
    )
    should_sanitize_template: bool = Param(
        description="Normalize the HTML body using Tidy, then strip unsupported tags and attributes using Bleach",
        required=False,
        default=True,
    )


class SendHtmlemailOutput(ActionOutput):
    pass


def _parse_headers(raw_headers: str | None) -> dict:
    if not raw_headers:
        return {}
    try:
        headers = json.loads(raw_headers)
    except Exception as exc:
        raise ActionFailure("Error: custom email headers field is not valid json") from exc
    if not isinstance(headers, dict):
        raise ActionFailure("Error: custom email headers field is not a dictionary")
    return headers


def _parse_attachments(params: SendHtmlemailParams) -> list[dict]:
    if params.attachment_json:
        try:
            attachments = json.loads(params.attachment_json)
        except Exception as exc:
            raise ActionFailure("Error: attachment json field is not valid json") from exc
        if not isinstance(attachments, list):
            raise ActionFailure("Error: attachment json field is not a list")
        if not any(isinstance(item, dict) and item.get("vault_id") for item in attachments):
            raise ActionFailure('Error: attachment json field does not contain any dictionaries with the "vault_id" key')
        attachments = [dict(item) if isinstance(item, dict) else item for item in attachments]
    else:
        attachments = []

    for index in range(1, 6):
        attachments.append(
            {
                "vault_id": getattr(params, f"attachment{index}"),
                "content_id": getattr(params, f"content_id{index}"),
            }
        )
    return [item for item in attachments if isinstance(item, dict) and item.get("vault_id")]


def _load_vault_file(soar: SOARClient, vault_id: str):
    attachments = soar.vault.get_attachment(vault_id=vault_id, container_id=soar.get_executing_container_id())
    if not attachments:
        attachments = soar.vault.get_attachment(vault_id=vault_id)
    return attachments[0] if attachments else None


def _make_attachment(soar: SOARClient, vault_id: str, content_id: str | None):
    try:
        attachment = _load_vault_file(soar, vault_id)
    except Exception as exc:
        raise ActionFailure(f"Error: failed to find vault ID: {vault_id}") from exc
    if attachment is None or not attachment.path:
        raise ActionFailure(f"Error: failed to find vault id: {vault_id}")

    filename = Path(attachment.name).name
    content_type, _ = mimetypes.guess_type(attachment.name)
    if content_type is None:
        content_type = "application/octet-stream"
    maintype, subtype = content_type.split("/", 1)

    try:
        if maintype == "text":
            with attachment.open() as file_obj:
                message = MIMEText(file_obj.read(), _subtype=subtype)
        elif maintype == "message":
            with attachment.open() as file_obj:
                message = MIMEMessage(message_from_file(file_obj), _subtype=subtype)
        elif maintype == "image":
            with attachment.open("rb") as file_obj:
                message = MIMEImage(file_obj.read(), _subtype=subtype)
        else:
            with attachment.open("rb") as file_obj:
                message = MIMEBase(maintype, subtype)
                message.set_payload(file_obj.read())
            encoders.encode_base64(message)
    except Exception as exc:
        raise ActionFailure(f"Error: failed to read the file for the vault ID: {vault_id}") from exc

    if content_id:
        normalized_id = content_id.strip().lstrip("<").rstrip(">").strip()
        message.add_header("Content-ID", f"<{normalized_id}>")
    else:
        message.add_header("Content-Disposition", "attachment", filename=filename)
    return message


def _recipients(value: str | None) -> list[str]:
    if not value:
        return []
    return [recipient for item in value.split(",") if (recipient := item.strip())]


def _sanitize_html(html: str) -> str:
    import bleach
    from bleach.css_sanitizer import CSSSanitizer
    from bleach_allowlist import all_styles, all_tags, generally_xss_unsafe
    from pytidyhtml5 import OptionId, tidy_document

    safe_html_tags = list((set(all_tags) - set(generally_xss_unsafe)) | {"html", "head", "body"})
    html = tidy_document(
        html,
        options={
            OptionId.word2000: True,
            OptionId.drop_prop_attrs: True,
            OptionId.html_out: True,
            OptionId.mark: False,
            OptionId.drop_empty_paras: False,
            OptionId.drop_empty_elems: False,
        },
        encoding="unicode",
        body_only=True,
        quiet=True,
    )
    return bleach.clean(
        text=html,
        tags=safe_html_tags,
        attributes=BLEACH_SAFE_HTML_ATTRIBUTES,
        css_sanitizer=CSSSanitizer(allowed_css_properties=all_styles),
        protocols=list(bleach.ALLOWED_PROTOCOLS) + SMTP_BLEACH_ALLOWED_PROTOCOLS,
        strip=True,
    )


@result_table_columns
@app.action(
    description="Sends a html email with optional text rendering. Attachments are allowed a Content-ID tag for reference within the html",
    action_type="generic",
    read_only=False,
    render_as="table",
    verbose="""If the <b>from</b> parameter is not provided, then the action will consider the <b>username</b> parameter provided in the asset configuration as the sender's email address.<br><br>If the "Subject" is provided in the <b>subject</b> and the <b>headers</b> parameter, then the "Subject" provided in the <b>headers</b> parameter will be preferred and the action will run accordingly.""",
    params_class=SendHtmlemailParams,
    output_class=SendHtmlemailOutput,
)
def send_htmlemail(params: SendHtmlemailParams, soar: SOARClient, asset: Asset):
    logger.progress("Sending HTML email")
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
        sender_value = params.from_address if params.from_address is not None else (asset.sender_address or asset.username or "")
        email_from = clean_from_field(sender_value)
        email_to = _recipients(params.to)
        email_cc = _recipients(params.cc)
        email_bcc = _recipients(params.bcc)
        if not email_from:
            raise ActionFailure("Error: failed to get email sender")
        if not email_to:
            raise ActionFailure("Error: failed to get email recipients")

        if params.should_sanitize_template:
            try:
                email_html = _sanitize_html(params.html_body)
            except Exception as exc:
                raise ActionFailure("Error: failed to sanitize HTML body") from exc
        else:
            email_html = params.html_body

        email_headers = _parse_headers(params.headers)
        attachment_json = _parse_attachments(params)
        message_encoding = "utf-8" if asset.encoding else "ascii"
        root = MIMEMultipart("related")
        root["to"] = ",".join(email_to)
        if email_cc:
            root["cc"] = ", ".join(email_cc)
            email_to.extend(email_cc)
        if params.subject and not any(name.lower() == "subject" for name in email_headers):
            root["subject"] = params.subject
        for name, value in email_headers.items():
            if name.lower() != "bcc":
                root[name] = value

        email_text = params.text_body
        if not email_text:
            email_text = BeautifulSoup(email_html, "html.parser").get_text(separator=" ")

        if "From" in root and params.from_address:
            del root["From"]
            root["From"] = clean_from_field(params.from_address)
        elif "From" in root:
            email_from = str(root["From"])
        else:
            root["From"] = email_from

        message = MIMEMultipart("alternative")
        try:
            message.attach(MIMEText(email_text, "plain", message_encoding))
            message.attach(MIMEText(email_html, "html", message_encoding))
        except Exception as exc:
            raise ActionFailure(f"{SMTP_UNICODE_ERROR_MESSAGE}. {exc}") from exc
        root.attach(message)

        for item in attachment_json:
            root.attach(_make_attachment(soar, item["vault_id"], item.get("content_id")))

        recipients = email_to + email_bcc
        mail_options = ["SMTPUTF8"] if asset.allow_smtputf8 else []
        refused = connection.sendmail(email_from, recipients, root.as_string(), mail_options=mail_options)
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
