[comment]: # "Auto-generated SOAR connector documentation"
# SMTP

Publisher: Splunk  
Connector Version: 2\.3\.2  
Product Vendor: Generic  
Product Name: SMTP  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.4\.0  

This app provides the ability to send email using SMTP

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a SMTP asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**server** |  required  | string | Server IP/Hostname
**port** |  optional  | numeric | Port
**username** |  optional  | string | Username \(or email address\)
**password** |  optional  | password | Password \(For Basic Auth\)
**client\_id** |  optional  | string | OAuth Client ID \(For OAuth\)
**client\_secret** |  optional  | password | OAuth Client Secret \(For OAuth\)
**auth\_url** |  optional  | string | OAuth Authorization URL
**token\_url** |  optional  | string | OAuth Token URL
**scopes** |  optional  | string | OAuth API Scope \(space\-separated\)
**sender\_address** |  optional  | string | Sender Address
**ssl\_config** |  required  | string | SSL Method
**allow\_smtputf8** |  optional  | boolean | Enable SMTPUTF8 support \(Check this only if the SMTP server supports SMTPUTF8 option\)
**encoding** |  optional  | boolean | Enable Unicode support

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity\. This action logs into the device and sends a test email to check the connection and credentials  
[send email](#action-send-email) - Sends an email  
[send rawemail](#action-send-rawemail) - Takes a fully specified email and sends it unmodified to the smtp server\. Sender and Recipient\(s\) will be extracted from message headers; Suggest using the standard email package to build message and export with the \.as\_string\(\) method  
[send htmlemail](#action-send-htmlemail) - Sends a html email with optional text rendering\. Attachments are allowed a Content\-ID tag for reference within the html  

## action: 'test connectivity'
Validate the asset configuration for connectivity\. This action logs into the device and sends a test email to check the connection and credentials

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'send email'
Sends an email

Type: **generic**  
Read only: **False**

Some points to note\: <ul> <li>Only files present in the <b>vault</b> can be attached to the email\.</li> <li>To send HTML emails, specify a HTML formatted text \(i\.e\. <html>\.\.\.\.</html>\) in the <b>body</b> parameter\. The app sends a multipart email containing plain and html <i>Content\-Type</i>\.</li> <li>The <b>to</b> parameter supports comma separated email addresses\.</li> <li>If the "Subject" is provided in the <b>subject</b> and the <b>headers</b> parameter, then the "Subject" provided in the <b>headers</b> parameter will be preferred and the action will run accordingly\.</li> <li> In the playbooks, if you don't provide any value for 'from' field in actions, it will take value from the platform email setting\. If in the email settings also it is empty, it will consider the username parameter provided in the asset configuration as the sender's email address</li> </ul>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**from** |  optional  | From field | string |  `email` 
**to** |  required  | List of recipients email addresses | string |  `email` 
**cc** |  optional  | List of recipients email addresses to include on cc line | string |  `email` 
**bcc** |  optional  | List of recipients email addresses to include on bcc line | string |  `email` 
**subject** |  optional  | Message Subject | string | 
**body** |  required  | Message body | string | 
**attachments** |  optional  | Vault IDs of files to attach | string |  `vault id` 
**headers** |  optional  | Custom email headers \(formatted as JSON\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.attachments | string |  `vault id`  |   ab2b2ccfba08ea538ef22f521caa01c3c2b17ccf 
action\_result\.parameter\.bcc | string |  `email`  |   test1\@testdomain\.com 
action\_result\.parameter\.body | string |  |   Test body 
action\_result\.parameter\.cc | string |  `email`  |   test2\@testdomain\.com 
action\_result\.parameter\.from | string |  `email`  |   sender\@testdomain\.com 
action\_result\.parameter\.headers | string |  |   \{"Subject"\: "Test1", "To"\: "test3\@testdomain\.com"\} 
action\_result\.parameter\.subject | string |  |   Test 
action\_result\.parameter\.to | string |  `email`  |   receiver\@testdomain\.com 
action\_result\.data | string |  |  
action\_result\.summary | string |  |  
action\_result\.message | string |  |   Email sent 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'send rawemail'
Takes a fully specified email and sends it unmodified to the smtp server\. Sender and Recipient\(s\) will be extracted from message headers; Suggest using the standard email package to build message and export with the \.as\_string\(\) method

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**raw\_email** |  required  | Fully specified email message including all headers | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.raw\_email | string |  |   to\: receiver\@testdomain\.com\\n from\:sender\@testdomain\.com\\n subject\: Test\\n\\nBody Text  to\: receiver\@testdomain\.com\\n from\:sender\@testdomain\.com\\n Content\-type\: text/html\\nsubject\: HTML Test\\n<html><body><h2>This is test</h2><br>This is unicode data\.</body></html>  to\: receiver1\@testdomain\.com,receiver2\@testdomain\.com\\nfrom\: sender\@testdomain\.com\\nsubject\: CommaSeparated Recipients Test\\n\\nThis is test data\. 
action\_result\.data | string |  |  
action\_result\.summary | string |  |  
action\_result\.message | string |  |   Email sent 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'send htmlemail'
Sends a html email with optional text rendering\. Attachments are allowed a Content\-ID tag for reference within the html

Type: **generic**  
Read only: **False**

If the <b>from</b> parameter is not provided, then the action will consider the <b>username</b> parameter provided in the asset configuration as the sender's email address\.<br><br>If the "Subject" is provided in the <b>subject</b> and the <b>headers</b> parameter, then the "Subject" provided in the <b>headers</b> parameter will be preferred and the action will run accordingly\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**from** |  optional  | From field | string |  `email` 
**to** |  required  | List of recipients email addresses | string |  `email` 
**cc** |  optional  | List of recipients email addresses to include on cc line | string |  `email` 
**bcc** |  optional  | List of recipients email addresses to include on bcc line | string |  `email` 
**subject** |  optional  | Message Subject | string | 
**headers** |  optional  | Serialized json dictionary\. Additional email headers to be added to the message | string | 
**html\_body** |  required  | Html rendering of message | string | 
**text\_body** |  optional  | Text rendering of message | string | 
**attachment\_json** |  optional  | Serialized json list of attachments, including images\. Any additional attachments specified will be update this list\. Each attachment requires a vault id and an optional unique content\-id\. The content\-id is required if the html refers to the attachment\. The format of the json is a list of dictionaries\. Each dictionary will contain a vault\_id key and optionally a content\_id key\. ie\. \[\{"vault\_id"\: "first\_vault id", "content\_id"\: "a\_unique\_content\_id"\}, \{"vault\_id"\: "second\_vault\_id"\}\] | string | 
**attachment1** |  optional  | Vault id for attachment | string | 
**content\_id1** |  optional  | Optional content\-id for attachment, typically used in image link referrals | string | 
**attachment2** |  optional  | Vault id for attachment | string | 
**content\_id2** |  optional  | Optional content\-id for attachment, typically used in image link referrals | string | 
**attachment3** |  optional  | Vault id for attachment | string | 
**content\_id3** |  optional  | Optional content\-id for attachment, typically used in image link referrals | string | 
**attachment4** |  optional  | Vault id for attachment | string | 
**content\_id4** |  optional  | Optional content\-id for attachment, typically used in image link referrals | string | 
**attachment5** |  optional  | Vault id for attachment | string | 
**content\_id5** |  optional  | Optional content\-id for attachment, typically used in image link referrals | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.attachment1 | string |  |   ab2b2ccfba08ea538ef22f521caa01c3c2b17ccf 
action\_result\.parameter\.attachment2 | string |  |   ab2e2ccfba08ea538ef22f529caa01c3c2b17ccf 
action\_result\.parameter\.attachment3 | string |  |   ab2e2ccfba08ea538ef22f529caa01c3c2b17ccf 
action\_result\.parameter\.attachment4 | string |  |   ab2e2ccfba08ea538ef22f529caa01c3c2b17ccf 
action\_result\.parameter\.attachment5 | string |  |   ab2e2ccfba08ea538ef22f529caa01c3c2b17ccf 
action\_result\.parameter\.attachment\_json | string |  |  
action\_result\.parameter\.bcc | string |  `email`  |   test1\@testdomain\.com 
action\_result\.parameter\.cc | string |  `email`  |   test2\@testdomain\.com 
action\_result\.parameter\.content\_id1 | string |  |  
action\_result\.parameter\.content\_id2 | string |  |  
action\_result\.parameter\.content\_id3 | string |  |  
action\_result\.parameter\.content\_id4 | string |  |  
action\_result\.parameter\.content\_id5 | string |  |  
action\_result\.parameter\.from | string |  `email`  |   sender\@testdomain\.com 
action\_result\.parameter\.headers | string |  |   \{"Subject"\: "Test1", "To"\: "test3\@testdomain\.com"\} 
action\_result\.parameter\.html\_body | string |  |   <html><h2>HTML heading</h2><body>HTML body\.</body></html> 
action\_result\.parameter\.subject | string |  |   Test 
action\_result\.parameter\.text\_body | string |  |   This is text body\. 
action\_result\.parameter\.to | string |  `email`  |   receiver\@testdomain\.com 
action\_result\.data | string |  |  
action\_result\.summary | string |  |  
action\_result\.message | string |  |   Email sent 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1 