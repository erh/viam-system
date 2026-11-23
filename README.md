# viam-system

## cmdsensor
```
{
    "cmd" : "<path to command>",
    "args" : [ "a1", "a2" ]
}
```

## apt

Makes sure a list of debian packages is installed on the machine.
Missing packages are installed in the background at startup (and on reconfigure).
`Readings` reports the installed version of each package, or `missing`.

```
{
    "packages" : [ "curl", "htop" ],
    "update" : true
}
```

- `packages` (required): debian package names to keep installed
- `update` (optional): run `apt-get update` before installing missing packages

`DoCommand` with `{"install": true}` re-runs the install check.

## network

Generic component for bounded local-network diagnostics. No external binaries required.

Configuration:

```json
{"allowed_cidrs":["192.168.1.0/24"],"timeout_ms":750,"max_hosts":256}
```

If `allowed_cidrs` is omitted, TCP and HTTP probes are restricted to private or link-local addresses. For stricter deployments, configure an explicit CIDR allowlist. Scan is restricted to IPv4 prefixes /20 through /32, at most 256 hosts by default (configurable up to 4096), with 32 concurrent hosts and up to 16 TCP ports. All probes are bounded by a timeout. Do not scan networks you do not administer.

DoCommand examples:

```json
{"command":"interfaces"}
{"command":"neighbors"}
{"command":"dns","host":"example.com"}
{"command":"tcp","host":"192.168.1.20","port":80}
{"command":"http","host":"192.168.1.20","port":80,"path":"/"}
{"command":"scan","subnet":"192.168.1.0/24","ports":[80,443,8080]}
```

`scan` reports hosts with open TCP ports, not all powered-on hosts. `neighbors` currently uses Linux /proc/net/arp. HTTP probes use GET, cap response bodies at 2048 bytes, disable redirects and proxies, and connect to a validated IP. mDNS/SSDP discovery and device-specific identification are future enhancements.
