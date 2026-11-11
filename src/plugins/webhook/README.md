# Plugin `webhook`

Sends lanlord's notifications: it posts `{"title", "text", "source"}` as JSON to a URL.

It takes an optional token file in the data directory (mode `0600`), sent as bearer token; with a token, the address
must use `https://` (plain `http://` only to the own host). Public servers are checked against the usual certificate
authorities, built into lanlord. The Plugins page has a "Send test notification" button.
