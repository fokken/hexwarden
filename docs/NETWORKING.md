# Networking and passive traffic analysis

[Back to README](../README.md) · [Linux installation](../README.md#installation-linux)

## Setup

Network inventory uses ADB. Passive capture additionally needs host `tshark` and device-side `tcpdump` and `timeout`:

```sh
sudo apt install tshark
```

`tshark` reads saved PCAPs here and needs no host live-capture privileges. Installing `tcpdump` on the computer does not install it on Android. Device capture needs a compatible device-side binary and permissions, usually existing root access. Hexwarden does not install device tools or acquire root.

## Network inventory

```sh
hexwarden scan --modules network
```

The network module collects interface addresses, link state, IPv4/IPv6 routes and policy rules, socket listeners, process identities and package UIDs. When `ss` exposes PIDs, listener records are correlated with `ps` and `pm list packages -U`; a `netstat` fallback is retained when `ss` is unavailable but cannot provide the same attribution. It also summarizes firewall chain policies and records default routes, interface roles and forwarding state. A wildcard bind remains a review candidate until its owning process, routes, firewall and reachable interfaces are checked together.

## Passive capture

```sh
# Capture all interfaces for 30 seconds using existing device root access
hexwarden scan --modules network passive_network --root --capture-seconds 30

# Capture one interface with a 256-byte snapshot per packet
hexwarden scan --modules passive_network --root --capture-seconds 60 \
  --capture-interface wlan0 --capture-snaplen 256
```

Passive analysis is opt-in with `--capture-seconds`. The complete capture is retained as `traffic.pcap` together with `capture-metadata.json`, even when `timeout` returns its normal stop code. Use `--capture-interface wlan0` to limit capture to one interface and `--capture-snaplen 256` to limit packet bytes; the default snap length `0` keeps full packets for manual review. The capture is then passed to `tshark`, which looks for application payloads in common cleartext protocols including HTTP, FTP, Telnet, SMTP, POP, IMAP, IRC, LDAP, MQTT, XMPP, SIP and RTSP. Findings retain protocol names and frame numbers but omit packet Info fields and payload contents, which may contain secrets. STARTTLS, QUIC, proprietary protocols and encrypted traffic still require manual review.

Capture is opt-in. Keep the default snapshot length when full packet contents are needed for manual review; a smaller snapshot truncates each packet. Raw PCAPs can contain sensitive data. See the [report guide](REPORT_FORMAT.md) for evidence references and coverage states.
