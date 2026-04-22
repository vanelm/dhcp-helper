# dhcp-helper

Passive DHCP listener that captures DHCP DISCOVER and REQUEST packets in promiscuous mode across all VLANs (802.1Q aware) and forwards the raw DHCP payload to [ursa-profiler](https://github.com/ursacloud/ursa)'s UDP listener for device fingerprinting.

## Features

- **Promiscuous capture** on one or more interfaces via libpcap
- **802.1Q VLAN tag extraction** — tracks statistics per VLAN
- **BPF-filtered** — only DHCP traffic enters userspace (`udp and (port 67 or port 68)`)
- **Lightweight forwarding** — sends raw DHCP bytes as UDP unicast to the profiler
- **Three run modes**: foreground (Ctrl+C), daemon (`-d`), Docker container
- **Live statistics** via Unix socket — query with `dhcp-helper stats`

## Build

Requires `libpcap-dev` (build) and `libpcap` (runtime).

```bash
# Native
apt-get install libpcap-dev
go build -ldflags "-s -w -X main.version=$(git describe --tags --always)" -o dhcp-helper .

# Docker
docker build --build-arg VERSION=$(git describe --tags --always) -t dhcp-helper .
```

## Usage

```
dhcp-helper -i <interfaces> -t <host:port> [flags]
dhcp-helper stats [-s <socket>] [-json]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-i` | *(required)* | Comma-separated network interfaces to capture |
| `-t` | *(required)* | Profiler DHCP listener address (`host:port`) |
| `-d` | `false` | Daemonize (fork to background) |
| `-s` | `/var/run/dhcp-helper.sock` | Unix socket path for stats IPC |
| `-p` | `/var/run/dhcp-helper.pid` | PID file path (daemon mode) |
| `-l` | `/var/log/dhcp-helper.log` | Log file path (daemon mode) |
| `-snap` | `1600` | pcap snapshot length in bytes |
| `-V` | | Print version and exit |

### Examples

```bash
# Foreground — capture on two interfaces, forward to profiler
dhcp-helper -i eth0,eth1 -t 10.0.0.5:6767

# Daemon mode
dhcp-helper -i eth0 -t profiler:6767 -d

# Check live statistics
dhcp-helper stats

# JSON output (for scripting)
dhcp-helper stats -json
```

### Stats output

```
Uptime: 2h15m30s  |  Total forwarded: 4821

  eth0          forwarded=3200     errors=0     last=2026-04-14T12:30:00Z
    native         1200
    VLAN 10        1450
    VLAN 20        550
  eth1          forwarded=1621     errors=2     last=2026-04-14T12:29:55Z
    VLAN 100       1621
```

## Deployment

### Docker

```bash
docker run -d \
  --name dhcp-helper \
  --net=host \
  --cap-add=NET_RAW \
  dhcp-helper -i eth0 -t profiler:6767
```

> `--net=host` is required so the container can see host network interfaces.

### systemd

```bash
# Install binary
cp dhcp-helper /usr/local/bin/

# Install service
cp dhcp-helper.service /etc/systemd/system/
cp dhcp-helper.default /etc/default/dhcp-helper

# Edit config
vi /etc/default/dhcp-helper

# Enable and start
systemctl daemon-reload
systemctl enable --now dhcp-helper

# Check stats
dhcp-helper stats -s /run/dhcp-helper.sock
```

The service runs with `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities — no root required after initial setup.

## How it works

1. Opens each specified interface in **promiscuous mode** with a BPF filter for DHCP traffic
2. For each captured packet, extracts the **802.1Q VLAN ID** if a Dot1Q tag is present
3. Validates the UDP payload is a **BOOTREQUEST** (op=1) with the DHCP magic cookie
4. Parses DHCP options to confirm message type is **DISCOVER** (1) or **REQUEST** (3)
5. Forwards the **raw DHCP payload** via UDP to the profiler's DHCP listener
6. The profiler extracts Option 55 (fingerprint), Option 60 (vendor), Option 12 (hostname), and the client MAC for device identification

## Profiler integration

The target (`-t`) must point to the profiler service's DHCP listener (default port `6767`, configured via `URSA_PROFILER_DHCP_LISTEN`). The profiler expects raw DHCP packet bytes — no wrapping or framing needed.

## License

See repository root.
