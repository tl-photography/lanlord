# Plugin `pihole`

Reports the devices in Pi-hole's network table, if switched on, and applies client groups per lanlord group.

lanlord uses the REST API of Pi-hole v6. It adds a Pi-hole group for every lanlord group of a device with a fixed
address, and a client for that address in `Default` and that group. Blocklists assigned to a group then apply to its
devices. Clients lanlord adds have the comment `lanlord: <device>`; lanlord changes and removes only those. Groups are
never deleted, other clients never touched: a device whose address already has another client is listed as left out.

Pi-hole has no rollback: lanlord makes the changes one by one, reads Pi-hole again and reports anything missing.

"Report devices" adds the devices of Pi-hole's network table to a scan. Leave it off when Pi-hole runs in a container
behind NAT: it then sees no real MAC addresses, only its virtual interfaces.

The plugin needs the HTTPS address, the name of a file in the data directory with an app password (mode `0600`;
create it in Pi-hole under Settings, Web interface / API, "Configure app password") and the SHA-256 fingerprint of
Pi-hole's certificate:

```sh
openssl s_client -connect pi.hole:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```
