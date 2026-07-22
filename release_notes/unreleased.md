**Unreleased**

* Restricted SMTP authentication dispatch to the supported authentication types.
* Added certificate validation for SMTP TLS connections and made STARTTLS fail closed.
* Reported partially refused email recipients as delivery errors.
* Preserved HTML sanitization when sending HTML email.
* Marked test connectivity as non-read-only because it sends a test email.
