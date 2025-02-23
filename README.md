# u2json-log-emailer
u2json-log-emailer works within the Snort and u2json pipeline to send email alerts.

### Description
This script aggregates the json-format network logs into most common statistics of source IP, alert message, and user-agent to generate email alerts. It functions as an alternative to using paid email alert functionality built into SIEMs like Splunk.

By default, this script will send an alert consisting of 60 seconds of logs every hour (if there was activity). It will also send a daily report at Midnight.

### Setup
[Snort](https://www.snort.org/)
[u2json](https://github.com/jasonish/py-idstools/blob/master/idstools/scripts/u2json.py)

This script works **only** with Snort and u2json working together to output logs into [Unified2](https://www.snort.org/faq/readme-unified2) format and parse them into a json log file.

A [sid-msg-map](https://github.com/jasonish/py-idstools/blob/master/idstools/scripts/gensidmsgmap.py) should then be used to map your Snort rule SIDs to their corresponding alert messages, allowing them to be displayed within the email.

The config.json in this repo should be updated to fit your environment.
- The log file/folder should point to where your u2json logs are being stored
- The email interval determines how long the script will wait between email alerts, by default it is set to 1 hour
- The email service, from, to, server, and port all are used within the Python smtplib library to get the email sent. If using Gmail, you can simply update email_from and email_to. If using a different inbox provider, you must determine the service name, server, and port that works for them

This script uses the [Keyring](https://pypi.org/project/keyring/) library to securely use your email account password to send the email via SMTP. Keyring pulls these credentials from the Windows Credential Manager. You will want to make sure this credential exists by adding it as a generic credential, or using the Keyring website example to add it via keyring.setpassword()
- If using Gmail, you will need to setup your account to use an [App Password](https://support.google.com/mail/answer/185833?hl=en)

### Usage
python main.py
