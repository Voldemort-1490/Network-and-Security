# pVPN — Multi-Mode Proxy-VPN Infrastructure

Portable, multi-mode private VPN infrastructure deployed on an AWS EC2 instance (Ubuntu 24.04 LTS), engineered to maintain persistent, encrypted connectivity across restrictive network environments — home Wi-Fi, corporate/enterprise Wi-Fi, mobile hotspots (CGNAT), and public networks.

Built on **WireGuard** (kernel-space UDP tunneling), **Squid Proxy** (application-layer filtering), **iptables** (NAT + dynamic packet redirection), and **client-side routing metric overrides** for seamless roaming between interfaces.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Server Setup](#server-setup)
3. [Client Configurations](#client-configurations)
4. [Firewall Evasion: Port Redirection](#firewall-evasion-port-redirection)
5. [Network Mobility](#network-mobility)
6. [Troubleshooting Log](#troubleshooting-log)
7. [Verification Commands](#verification-commands)
8. [Lessons Learned](#lessons-learned)

---

## Architecture

```
                  +-------------------------------------------------------------------+
                  |                          AWS EC2 INSTANCE                         |
                  |                                                                   |
                  |  +--------------------+        +-------------------------------+  |
                  |  |  UDP Port 53 /     |        |  iptables NAT / PREROUTING    |  |
                  |  |  UDP Port 51820    | -----> |  Redirect 53/443 -> 51820     |  |
                  |  +--------------------+        +---------------+---------------+  |
                  |                                                |                  |
                  |                                                v                  |
                  |                                 +------------------------------+  |
+---------------+ |                                 | WireGuard Interface (wg0)    |  |
| Windows Client| |                                 | Subnet: 10.0.0.1/24          |  |
| WireGuard App | |                                 +--------------+---------------+  |
+-------+-------+ |                                                |                  |
        |         |                                                v                  |
        |         | +--------------------+          +------------------------------+  |
        +---------> | Squid Proxy Server | <------- | Kernel IPv4 Forwarding       |  |
                  | | 10.0.0.1:3128      |          | net.ipv4.ip_forward = 1      |  |
                  | +--------------------+          +--------------+---------------+  |
                  |                                                |                  |
                  |                                                v                  |
                  |                                 +------------------------------+  |
                  |                                 | Physical Adapter (ens5)      |  |
                  |                                 | MASQUERADE -> AWS Gateway    |  |
                  |                                 +--------------+---------------+  |
                  +------------------------------------------------|------------------+
                                                                   v
                                                             Public Internet
```

| Component | Role |
|---|---|
| WireGuard (`wg0`) | Encrypted tunnel endpoint, kernel-space, UDP |
| Squid Proxy | Application-layer proxy bound to tunnel subnet |
| iptables (`nat` table) | PREROUTING port redirection + POSTROUTING masquerade |
| `net.ipv4.ip_forward` | Enables the EC2 instance to route between interfaces |
| Windows client metrics | Interface priority control for multi-adapter roaming |

---

## Server Setup

### 1. Persistent IPv4 Forwarding

```bash
sudo tee /etc/sysctl.d/99-ip-forward.conf << 'EOF'
net.ipv4.ip_forward = 1
EOF
sudo sysctl --system
cat /proc/sys/net/ipv4/ip_forward   # expect: 1
```

A dedicated `sysctl.d` drop-in is used instead of editing `/etc/sysctl.conf` directly, so the setting survives package upgrades and is easy to audit independently.

### 2. Install WireGuard & Generate Keys

```bash
sudo apt-get update && sudo apt-get install -y wireguard iptables-persistent

umask 077
wg genkey | tee server_private.key | wg pubkey > server_public.key
wg genkey | tee client_private.key | wg pubkey > client_public.key
```

`umask 077` ensures key files are created with `600` permissions from the moment they're written — never world- or group-readable.

### 3. Server Config — `/etc/wireguard/wg0.conf`

Interface names (`ens5`, `eth0`, …) are **not hardcoded**. AWS can reassign the default interface name after maintenance events, so the config resolves it dynamically at runtime:

```ini
[Interface]
Address = 10.0.0.1/24
SaveConfig = false
ListenPort = 51820
PrivateKey = <SERVER_PRIVATE_KEY>

# Unified PostUp: forwarding, NAT masquerade, stealth port redirection
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $(ip route list default | awk '/default/ {print $5}') -j MASQUERADE; iptables -t nat -A PREROUTING -i $(ip route list default | awk '/default/ {print $5}') -p udp --dport 53 -j REDIRECT --to-ports 51820; iptables -t nat -A PREROUTING -i $(ip route list default | awk '/default/ {print $5}') -p udp --dport 443 -j REDIRECT --to-ports 51820

# Unified PostDown: mirror-image cleanup
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $(ip route list default | awk '/default/ {print $5}') -j MASQUERADE; iptables -t nat -D PREROUTING -i $(ip route list default | awk '/default/ {print $5}') -p udp --dport 53 -j REDIRECT --to-ports 51820; iptables -t nat -D PREROUTING -i $(ip route list default | awk '/default/ {print $5}') -p udp --dport 443 -j REDIRECT --to-ports 51820

[Peer]
PublicKey = <CLIENT_PUBLIC_KEY>
AllowedIPs = 10.0.0.2/32
```

> **Note:** all `PostUp`/`PostDown` commands must live on a *single* line, chained with `;`. Two separate `PostUp =` keys in the same file will either silently overwrite each other or fail to parse — WireGuard does not merge repeated keys.

```bash
sudo systemctl enable --now wg-quick@wg0
```

### 4. AWS-Side Adjustments (outside the OS)

| Setting | Value | Why |
|---|---|---|
| Inbound SG rule | Custom UDP 51820, source `0.0.0.0/0` | Standard WireGuard handshake port |
| Inbound SG rule | UDP 53, source `0.0.0.0/0` | Evasion fallback (DNS-disguised) |
| Inbound SG rule | UDP 443, source `0.0.0.0/0` | Evasion fallback (QUIC-disguised) |
| Source/Destination Check | **Disabled** | Without this, the AWS hypervisor drops any packet whose inner source IP (`10.0.0.2`) doesn't match the ENI's assigned private IP — this silently kills all forwarded tunnel traffic even when every OS-level setting is correct |

---

## Client Configurations

### A. Full-VPN Mode (`Full-VPN.conf`)

All egress traffic routes through the tunnel.

```ini
[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY>
Address = 10.0.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = <AWS_ELASTIC_IP>:53
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 15
```

> Pushing a bare `0.0.0.0/0` can create a routing loop that swallows the SSH control session itself the instant the tunnel comes up. Fix: split the default route (`0.0.0.0/1`, `128.0.0.0/1`) or explicitly exclude the server's own public IP with a `/32` route.

### B. Split-Tunnel / Proxy-Only Mode (`Split-Proxy.conf`)

Only tunnel-subnet and proxy-bound traffic is routed through WireGuard; the local gateway continues to handle general internet traffic.

```ini
[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY>
Address = 10.0.0.2/24

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = <AWS_ELASTIC_IP>:53
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 15
```

---

## Firewall Evasion: Port Redirection

Corporate/enterprise Wi-Fi networks routinely block outbound `51820/UDP` (the standard WireGuard port) but must leave `53/UDP` (DNS) open, and rarely block `443/UDP` (QUIC/HTTP3).

The server intercepts inbound traffic on ports 53/443 at the `PREROUTING` stage of the NAT table — before any routing decision is made — and silently redirects it to the real WireGuard listener:

```bash
sudo iptables -t nat -A PREROUTING -i ens5 -p udp --dport 53 -j REDIRECT --to-ports 51820
```

| Flag | Meaning |
|---|---|
| `-t nat` | Operate on the NAT table (address/port rewriting) |
| `-A PREROUTING` | Apply the instant a packet hits the NIC, before OS routing |
| `-i ens5` | Only match traffic inbound on the primary interface |
| `-p udp --dport 53` | Match UDP packets addressed to port 53 |
| `-j REDIRECT --to-ports 51820` | Rewrite the destination port to WireGuard's real listener |

**Client side:** point the WireGuard `Endpoint` at `<server>:53` (or `:443`). The client's own outbound traffic isn't touched by the client-side firewall's port policy for 53/443, so the encrypted handshake rides out disguised as DNS or QUIC.

> **Known limitation:** this only defeats *port-based* filtering. Networks running Deep Packet Inspection (DPI) can fingerprint WireGuard's high-entropy binary payload riding on port 53 (which should only ever carry plaintext-structured DNS queries) and drop it anyway. See [Troubleshooting Log](#troubleshooting-log), TS-07.

---

## Network Mobility

### CGNAT Keepalive

Mobile carriers enforce aggressive NAT timeout policies (~20–30s) on idle UDP mappings. `PersistentKeepalive = 15` sends an unencrypted 32-byte packet every 15 seconds purely to keep the intermediate NAT/firewall state table alive — it carries no tunnel payload.

### Windows Interface Metrics

When Windows has more than one active adapter (Wi-Fi + Ethernet, or Wi-Fi + WireGuard), it routes out of whichever interface has the **lowest** metric.

```powershell
# Prioritize any WireGuard virtual adapter
Set-NetIPInterface -InterfaceAlias "wg*" -InterfaceMetric 5

# De-prioritize all physical adapters
Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | ForEach-Object {
    Set-NetIPInterface -InterfaceAlias $_.Name -InterfaceMetric 25
}
```

```powershell
# Revert to Windows automatic metric management
Get-NetIPInterface | Set-NetIPInterface -AutomaticMetric Enabled
```

> WireGuard's native Windows config parser does **not** accept a `Metric =` key inside `[Interface]` — it will refuse to start with `Invalid key for [Interface] section: "metric"`. Metric overrides must always be applied externally via PowerShell, never inside the `.conf` file.

> **Side effect:** static metrics persist even after the tunnel is deactivated. If the WireGuard adapter (metric 5) goes down while Wi-Fi is stuck at metric 25, Windows' NCSI can report "No Internet" on a perfectly healthy Wi-Fi connection, because it's still treating the dead virtual adapter as the preferred route. Always revert to `AutomaticMetric Enabled` when not actively tunneling.

---

## Troubleshooting Log

| ID | Symptom | Root Cause | Resolution |
|---|---|---|---|
| TS-01 | Handshake reports success, but `Received: 0 Bytes` | AWS hypervisor dropped forwarded packets — inner source IP (`10.0.0.2`) didn't match the ENI's private IP | Disabled **Source/Destination Check** in the EC2 console |
| TS-02 | SSH session freezes the instant Full-VPN mode is activated | `AllowedIPs = 0.0.0.0/0` routed the active SSH control socket back into the not-yet-established tunnel | Split default route (`0.0.0.0/1`, `128.0.0.0/1`) or excluded the server's public IP as a `/32` |
| TS-03 | `wg-quick@wg0` fails on server reboot | Hardcoded `ens5` no longer matched the interface name after a reboot/maintenance event | Replaced with `$(ip route list default \| awk '/default/ {print $5}')` in `PostUp`/`PostDown` |
| TS-04 | Client stuck on "Sending handshake initiation" on corporate Wi-Fi | Local firewall blocking outbound `51820/UDP` | Redirected `53/UDP` → `51820` via `PREROUTING`, pointed client `Endpoint` at `:53` |
| TS-05 | WireGuard GUI error: `Invalid key for [Interface] section: "metric"` | Windows client parser doesn't support an in-file `Metric` key | Applied metric overrides externally via `Set-NetIPInterface` (PowerShell) |
| TS-06 | Windows shows "No Internet" on Wi-Fi even with VPN off | Static low physical-adapter metrics left no valid fallback route once the virtual adapter dropped | `Get-NetIPInterface \| Set-NetIPInterface -AutomaticMetric Enabled` + `ipconfig /flushdns` |
| TS-07 | Previously-stable tunnel suddenly can't complete handshake; `wg show` on server shows no recent handshake despite server being healthy | Client ISP began DPI-filtering UDP/53 — flagging WireGuard's high-entropy payload as non-DNS traffic and silently dropping it | Diagnosed with `tcpdump -n -i any udp port 53` on the server (empty capture = blocked upstream, not server-side); switched client `Endpoint` to `:443` or native `:51820` |
| TS-08 | "No Internet" on home Wi-Fi with WireGuard fully disconnected | Leftover static interface metrics from a previous session left Windows without an automatic fallback gateway | Reset metrics to automatic, flushed DNS, `netsh winsock reset` + `netsh int ip reset`, reboot |

**Diagnostic order for a dead handshake:**

1. `sudo wg show` on the server — check `latest handshake:` timestamp.
2. `sudo tcpdump -n -i any udp port 53 or udp port 51820` on the server while activating the client.
   - **Nothing captured** → blocked upstream (client ISP/Wi-Fi or AWS Security Group), not a server problem.
   - **Packets arrive, no reply** → public key mismatch or bad peer config.
   - **Packets arrive and reply, client still times out** → local `iptables` PREROUTING rule was flushed (e.g. by a reboot without `iptables-persistent`, or a competing script).
3. Swap the client `Endpoint` port (`:53` → `:51820` or `:443`) to isolate port-specific filtering from a systemic failure.

---

## Verification Commands

**Server**

```bash
sudo wg show                                       # active tunnels & last handshake
sudo iptables -t nat -L -n -v --line-numbers        # confirm NAT rules are actually loaded
sudo tcpdump -n -i any udp port 53 or udp port 51820   # live capture of tunnel/evasion traffic
```

**Client (PowerShell)**

```powershell
Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric | Format-Table DestinationPrefix, NextHop, RouteMetric, InterfaceAlias
ipconfig /flushdns
```

---

## Lessons Learned

- **Dynamic interface resolution beats hardcoding.** Cloud NICs can be renamed by the platform outside of your control; resolve them at runtime in every script that references an interface name.
- **A working tunnel has failure points outside the tunnel itself.** AWS hypervisor-level source/destination checking and Security Group state are invisible from inside the OS — `sudo wg show` looking healthy doesn't rule them out.
- **Port redirection defeats port-based filters, not DPI.** Disguising a UDP/51820 handshake as UDP/53 works against simple allow/deny port rules; it does not survive a firewall that inspects payload entropy/structure against the expected protocol.
- **Client-side routing state outlives the VPN session.** Manual Windows interface metrics and custom DNS assignments can persist after disconnecting and break normal connectivity — always pair a manual override with an explicit revert path (`AutomaticMetric Enabled`).
- **`PersistentKeepalive` is a NAT-survival tool, not a security feature.** It exists solely to stop intermediate NAT tables (especially CGNAT) from expiring the session during idle periods.

---

*This README covers the operational build and troubleshooting history of the pVPN infrastructure. See the accompanying formatted documentation report for the full phase-by-phase engineering write-up.*