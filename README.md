# FakeSIP

Disguise your UDP traffic as SIP protocol to evade DPI detection, using Netfilter Queue (NFQUEUE).

[[ 中文文档 ]](https://github.com/MikeWang000000/FakeSIP/wiki)


## Quick Start

```
fakesip -i eth0
```


## Usage

```
Usage: fakesip [options]

Interface Options:
  -a                 work on all network interfaces (ignores -i)
  -i <interface>     work on specified network interface

Payload Options:
  -b <file>          use UDP payload from binary file
  -u <uri>           use specified SIP URI

Filter Options:
  -l <file>          load IP/port allow/deny filter rules from <file>

General Options:
  -0                 process inbound packets
  -1                 process outbound packets
  -4                 process IPv4 connections
  -6                 process IPv6 connections
  -d                 run as a daemon
  -k                 kill the running process
  -s                 enable silent mode
  -w <file>          write log to <file> instead of stderr

Advanced Options:
  -f                 skip firewall rules
  -g                 disable hop count estimation
  -m <mark>          fwmark for bypassing the queue
  -n <number>        netfilter queue number
  -r <repeat>        duplicate generated packets for <repeat> times
  -t <ttl>           TTL for generated packets
  -x <mask>          set the mask for fwmark
  -y <pct>           raise TTL dynamically to <pct>% of estimated hops
  -z                 use iptables commands instead of nft

```


## IP/Port Filter

Use `-l <file>` to restrict which UDP packets are disguised by FakeSIP. The
filter does not block real traffic: packets outside the filter are accepted
without generating fake SIP packets.

Filter file format:

```
# action type value
allow ip 1.2.3.4
allow ip 1.2.3.0/24
allow ip 2001:db8::/32
deny ip 203.0.113.9
allow port 443
allow port 5000-6000
deny port 12345
```

Rules are loaded once at startup. `deny` rules have the highest priority.
Source or destination IP/port can match a rule. If any IP allow rules exist, a
packet must match at least one IP allow rule. If any port allow rules exist, a
packet must match at least one port allow rule. When both IP and port allow
rules exist, both conditions must match.

The default nftables path uses sets to skip non-matching packets before
NFQUEUE. The iptables fallback preserves the same behavior but uses linear
rules, so nftables is recommended for large rule lists.


## License

GNU General Public License v3.0
