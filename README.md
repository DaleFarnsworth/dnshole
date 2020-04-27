## Redirect domains for ad and malware sites to a black hole

## Introduction
dnshole fetches lists of ad and malware domains, merges them, and
adds them to the local /etc/hosts file with an ip address that
references localhost.

The machine's dns search order should give priority to the hosts
file over remote dns resolution.  This typically done by editing
the /etc/nsswitch.conf file's host entry.  Example:
```
hosts:	files mdns4_minimal [NOTFOUND=return] dns
```

If the local network DHCP server is modified so that it points the
local machines dns resolvers at the machine with the modified hosts file,
all of the local machines can benefit from reduced fetches of ads and
malware.

## Usage
```
Usage: dnshole: [flags]
Flags:
  -config string
    	Configuration file name (default "/etc/dnshole.conf")
  -help
    	Show this usage description.
  -output string
    	Output file name, "-" means stdout
```

if an output file name is not specified on the command line, /etc/hosts is
overwritten.

## Author
Dale Farnsworth

<dale@farnsworth.org>
