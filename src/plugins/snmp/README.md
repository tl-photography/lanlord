# Plugin `snmp`

For a managed switch: lanlord reads with SNMP v2c which VLAN each port is in, and reports a device on a port of another
VLAN than its group. Only ports with exactly one device count. It changes nothing on the switch. Put the read
community in a file in the data directory, mode 0600. SNMP v2c is not encrypted, so limit it to the LAN.
