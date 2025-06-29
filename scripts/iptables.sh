#!/bin/bash

set -e

echo "🔄 Applying firewall rules..."

# Blacklist
if ipset list blacklist &>/dev/null; then
  ipset flush blacklist
else
  ipset create blacklist hash:ip
fi

# Allowlist
if ipset list allowlist &>/dev/null; then
  ipset flush allowlist
else
  ipset create allowlist hash:ip
fi

# Example IPs — edit as needed
#ipset add allowlist 203.0.113.10
#ipset add allowlist 198.51.100.55

# Flush iptables
iptables -F

# Reset or create udp_limit chain
if iptables -L udp_limit -n &>/dev/null; then
  iptables -F udp_limit
else
  iptables -N udp_limit
fi

# 1. Drop blacklisted
iptables -A udp_limit -m set --match-set blacklist src -j DROP

# 2. Apply hashlimit to allowlist (to detect impostors)
iptables -A udp_limit -m set --match-set allowlist src -m hashlimit \
  --hashlimit-above 750/sec \
  --hashlimit-burst 200 \
  --hashlimit-mode srcip \
  --hashlimit-name trusted_check \
  -j SET --add-set blacklist src

# 3. Accept if in allowlist
iptables -A udp_limit -m set --match-set allowlist src -j ACCEPT

# 4. Drop all others
iptables -A udp_limit -j DROP

# Apply to UDP ports 7240–7260
iptables -D INPUT -p udp --dport 7240:7260 -j udp_limit 2>/dev/null || true
iptables -A INPUT -p udp --dport 7240:7260 -j udp_limit

# NAT: Redirect TCP 80 → 8080
iptables -t nat -F

# External traffic (e.g., from LAN, WAN)
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

# Localhost traffic
iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport 80 -j DNAT --to-destination 127.0.0.1:8080
iptables -t nat -A OUTPUT -p tcp -d 127.0.0.2 --dport 80 -j DNAT --to-destination 127.0.0.2:8080

echo "✅ Firewall with allowlist + blacklist applied."