**Unreleased**

* Migrated all SMTP actions to the Splunk SOAR SDK. Requires SOAR 7.0 or later and Python 3.13.
* Preserved legacy OAuth tokens during upgrade and restored offline authorization for Google SMTP.
* Restricted interactive OAuth authorization to Test Connectivity; send actions retain automatic token refresh.
* Preserved recipient refusal details, MIME attachments, result datapaths, table columns, and configured CA trust.
* Corrected custom Subject precedence, Bcc header removal, and raw-email recipient parsing.
