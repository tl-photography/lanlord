# Plugin `email`

Sends lanlord's notifications by mail, through an SMTP server with `starttls`, `tls` or `none`, optionally with a user
and password file in the data directory (mode `0600`); a password is never sent with `none`. Public servers are
checked against the usual certificate authorities, built into lanlord. The Plugins page has a "Send test
notification" button.
