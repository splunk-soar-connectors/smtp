[comment]: # "Auto-generated SOAR connector documentation"
# SMTP

Publisher: Splunk  
Connector Version: 2\.3\.2  
Product Vendor: Generic  
Product Name: SMTP  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.4\.0  

This app provides the ability to send email using SMTP

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2023 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## General Point

-   Points to consider while configuring the asset

      

    -   OAuth authentication: To use the OAuth mechanism, following parameters are required
        -   Username
        -   Client ID
        -   Client Secret
        -   OAuth Authorization URL
        -   OAuth Token URL
    -   Basic authentication: If only username and password are provided the app will use basic
        authentication
    -   Passwordless authentication: If the SMTP sever supports passwordless authentication and the
        user doesn't provide required parameters for Oauth and Basic authentication, it will go for
        Passwordless authentication

-   The priority of authentication flow is in decreasing order as follows
    -   OAuth
    -   Basic
    -   Passwordless

-   Attachments and HTML formatting are supported

-   The asset configuration parameter **Enable SMTPUTF8 support (Check this only if the SMTP server
    supports SMTPUTF8 option)** should be disabled if the SMTP server does not support the SMTPUTF8
    configuration option. For the SMTP servers supporting SMTPUTF8, please enable this parameter. If
    this parameter is kept disabled for the SMTP servers supporting SMTPUTF8, all the actions having
    Unicode characters in TO, CC or BCC attributes will fail due to encoding issues in Python 3
    installation of the app due to a known SDK behavior.

-   The **username** and **password** fields for an SMTP Asset are optional because some SMTP
    servers do not require any authentication to accept mail. The **ssl_config** and **port** fields
    are related, but only the field **port** is optional. This is because each of the ssl_config
    options has an associated default port number, and you only have to specify the port if you want
    to override that default. For example, the default SMTP port for StartTLS-style encryption is
    587, but it's also possible to do start TLS on port 25. So in that case, you may want to select
    StartTLS and specify port 25. The default port numbers are listed in this table:

|         SSL Method    | Port |
|-----------------------|------|
|          **None**     | 25   |
|          **SSL**      | 465  |
|          **StartTLS** | 587  |



**NOTE :** While running the test connectivity with OAuth, username value is compulsory to pass. The
username value is required because its used to generate new token, every time test connectivity is
run.



  





To obtain the required parameters, please check the document of the service provider





Here we have attached links for the most used mail services to find parameters values:





  



GOOGLE





[Setting up OAuth2.0](https://support.google.com/cloud/answer/6158849?hl=en) [Using OAuth2.0 to
access google
API's](https://developers.google.com/identity/protocols/oauth2#1.-obtain-oauth-2.0-credentials-from-the-dynamic_data.setvar.console_name-.)



  



MICROSOFT





[Authentication for
SMTP](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth)
[Authorization code flow for
OAuth2.0](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)







  

## Playbook Backward Compatibility

-   The behavior of the following action has been modified. Hence, it is requested to the end-user
    to please update their existing playbooks by re-inserting the corresponding action blocks or by
    providing appropriate values to these action parameters to ensure the correct functioning of the
    playbooks created on the earlier versions of the app.

      

    -   Send RawEmail - To run this action, provide the **raw_email** parameter as a string
        separated using the new line character ('\\n' between headers like to, from, cc, bcc,
        subject) ('\\n\\n' before providing the body text or HTML after the headers). The example
        value for the same has been provided in the **Examples for Send RawEmail** section below.
        The action can also be executed using the playbook.  
        To run the action using playbook, the user can also provide the **raw_email** parameter as a
        multi-line string, i.e., any string enclosed within three double-quotes ("""some-string""")
        or three single-quotes ('''some-string''')

## Actions Key Points

-   Send Email

      

    -   For email consisting of HTML body to be processed correctly as HTML, it must start with
        either "\<!DOCTYPE html" declaration or "&lthtml" and the tag should end with ">"

-   Send Email and Send HTMLEmail

      

    -   For emails consisting of Unicode characters, set the **encoding** asset configuration flag
        to true.

-   Send RawEmail

      

    -   The **encoding** asset configuration flag does not apply to this action.

## Examples for Send RawEmail

-   The **raw_email** action parameter can be provided in the following ways.

      

    -   Example 1  
        **raw_email** =
        to:receiver@testdomain.com\\nfrom:sender@testdomain.com\\nsubject:Test\\n\\nThis is body
        text
    -   Example 2:  
        **raw_email** =
        to:receiver@testdomain.com\\nfrom:sender@testdomain.com\\nContent-type:text/html\\nsubject:HTML
        Test\\n\\n\<html>\<body>\<h2>This is test\</h2>\<br>This is some üñîçøðé
        data.\</body>\</html>
    -   Example 3:  
        **raw_email** =
        to:receiver1@testdomain.com,receiver2@testdomain.com\\nfrom:sender@testdomain.com\\nsubject:CommaSeparated
        Recipients Test\\n\\nThis is test data.


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