# Plugin `mqtt`

Sends lanlord's notifications: it publishes `{"title", "text", "source"}` as JSON with QoS 1 to a topic, optionally
with a user and password file in the data directory (mode `0600`). With TLS, a broker with a self-signed certificate
needs its SHA-256 fingerprint; public servers are checked against the usual certificate authorities, built into
lanlord. The Plugins page has a "Send test notification" button.
