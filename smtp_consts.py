# File: smtp_consts.py
#
# Copyright (c) 2014-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
SMTP_SUCC_SMTP_CONNECTIVITY_TO_SERVER = "Connected to server"
SMTP_SUCC_SMTP_EMAIL_SENT = "Email sent"
SMTP_ERROR_SMTP_CONNECTIVITY_TO_SERVER = "Connection to server failed"
SMTP_ERROR_SMTP_SEND_EMAIL = "Email send failed"
SMTP_SUCC_CONNECTIVITY_TEST = "Test Connectivity Passed"
SMTP_ERROR_CONNECTIVITY_TEST = "Test Connectivity Failed"

SMTP_PROG_UNABLE_TO_ATTACH_FILE = "Unable to attach file {}"
SMTP_MSG_SKIP_AUTH_NO_USERNAME_PASSWORD = "Skipping authentication, since Username or Password not configured"  # pragma: allowlist secret
SMTP_ERROR_PARSE_HEADERS = 'Unable to parse headers as a dictionary: {}'
SMTP_UNICODE_ERROR_MSG = "Error occurred while associating the email content in the email message object. \
If you are dealing with the Unicode characters,please mark the asset configuration parameter 'Enable Unicode \
support' as true, if not done already and try again."
SMTP_JSON_ATTACHMENTS = "attachments"
SMTP_JSON_BODY = "body"
SMTP_JSON_HEADERS = "headers"
SMTP_JSON_FROM = "from"
SMTP_JSON_PORT = "port"
SMTP_JSON_SUBJECT = "subject"
SMTP_JSON_TO = "to"
SMTP_JSON_CC = "cc"
SMTP_JSON_BCC = "bcc"
SMTP_JSON_USE_SSL = "use_ssl"
SMTP_JSON_TOTAL_SCANS = "total_scans"
SMTP_JSON_TOTAL_POSITIVES = "total_positives"
SMTP_JSON_TOTAL_GUESTS = "total_guests"
SMTP_JSON_TOTAL_GUESTS_RUNNING = "total_guests_running"
SMTP_JSON_SSL_CONFIG = "ssl_config"
SSL_CONFIG_NONE = "None"
SSL_CONFIG_SSL = "SSL"
SSL_CONFIG_STARTTLS = "StartTLS"
SMTP_ENCODING = "encoding"
SMTP_ALLOW_SMTPUTF8 = "allow_smtputf8"

SMTP_SENDING_TEST_MAIL = "Sending test mail"
SMTP_DONE = "Done..."

SMTP_ERROR_SSL_CONFIG_SSL = "Possible misconfiguration. \
The current SSL configuration value requires the server to speak SSL from the beginning of the connection."
SMTP_ERROR_STARTTLS_CONFIG = "Possible misconfiguration. \
The current SSL configuration value requires the server to support the startTLS command issued after a connection is made."
SMTP_ERROR_SMTPUTF8_CONFIG = "Unable to encode the Unicode characters. Possible misconfiguration. \
Either the server does not support SMTPUT8 or the 'Enable SMTPUTF8 support' asset configuration parameter is set to False"
SMTP_ERROR_TO_FROM_UNAVAILABLE = "Error: Failed to send the email. The {} is unavailable. Please check the action parameters"
SMTP_ERROR_CONNECTIVITY_TO_SERVER = "Error connecting to server"
SMTP_ERROR_LOGGING_IN_TO_SERVER = "Error logging in to server"
SMTP_REQUIRED_PARAM_OAUTH = "ERROR: {0} is a required parameter for OAuth Authentication, please specify one."
SMTP_REQUIRED_PARAM_BASIC = "ERROR: {0} is a required parameter for Basic Authentication, please specify one."
SMTP_STATE_FILE_CORRUPT_ERROR = "Error occurred while loading the state file due to its unexpected format. " \
    "Resetting the state file with the default format. Please try again."

# Constants relating to '_get_error_message_from_exception'
ERROR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
TYPE_ERROR_MSG = "Error occurred while connecting to the server. Please check the asset configuration and|or the action parameters"
PARSE_ERROR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

DEFAULT_REQUEST_TIMEOUT = 30  # 30 seconds


SMTP_STATE_IS_ENCRYPTED = 'is_encrypted'

# For encryption and decryption
SMTP_ENCRYPT_TOKEN = "Encrypting the {} token"
SMTP_DECRYPT_TOKEN = "Decrypting the {} token"
SMTP_ENCRYPTION_ERROR = "Error occurred while encrypting the state file"
SMTP_DECRYPTION_ERROR = "Error occurred while decrypting the state file"
