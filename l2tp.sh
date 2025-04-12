#!/usr/bin/env bash
set -e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

username="piminer"
password="piminer123"
mypsk="1"

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi
}

check_tun() {
    if [[ ! -e /dev/net/tun ]]; then
        echo "TUN device is not available. Enable it before running this script."
        exit 1
    fi
}

get_ip() {
    IP=$(hostname -I | awk '{print $1}')
    if [[ -z "$IP" ]]; then
        IP=$(wget -qO- ipv4.icanhazip.com)
    fi
    echo "Detected public IP: $IP"
}

install_packages() {
    echo "[INFO] Updating and installing packages..."
    apt update
    apt install -y strongswan xl2tpd ppp iptables iproute2
}

configure_ipsec() {
    echo "[INFO] Configuring IPsec..."
    cat > /etc/ipsec.conf <<EOF
config setup
    uniqueids=never 
    charondebug="ike 1, knl 1, cfg 0"

conn l2tp-psk
    keyexchange=ikev1
    authby=secret
    type=transport
    left=$IP
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
    auto=add
EOF

    cat > /etc/ipsec.secrets <<EOF
%any  %any  : PSK "$mypsk"
EOF
}

configure_xl2tpd() {
    echo "[INFO] Configuring xl2tpd..."
    iprange="172.$((RANDOM % 16 + 16)).$(hostname -I | awk '{print $1}' | awk -F. '{print $NF}')"
    
    cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lns default]
ip range = ${iprange}.10-${iprange}.100
local ip = ${iprange}.1
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

    cat > /etc/ppp/options.xl2tpd <<EOF
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 8.8.4.4
auth
mtu 1410
mru 1410
crtscts
lock
hide-password
modem
debug
proxyarp
lcp-echo-failure 4
lcp-echo-interval 30
EOF

    cat > /etc/ppp/chap-secrets <<EOF
# client    server    secret    IP addresses
${username} l2tpd ${password} *
EOF
}

enable_ip_forwarding() {
    echo "[INFO] Enabling IP forwarding..."
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-l2tp.conf
    sysctl -p /etc/sysctl.d/99-l2tp.conf
}

configure_firewall() {
    echo "[INFO] Configuring iptables..."
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables -A INPUT -p udp --dport 500 -j ACCEPT
    iptables -A INPUT -p udp --dport 4500 -j ACCEPT
    iptables -A INPUT -p udp --dport 1701 -j ACCEPT
    iptables -A INPUT -p esp -j ACCEPT
    iptables -A INPUT -p ah -j ACCEPT

    iptables-save > /etc/iptables.rules

    cat > /etc/network/if-pre-up.d/iptables <<EOF
#!/bin/sh
/sbin/iptables-restore < /etc/iptables.rules
EOF
    chmod +x /etc/network/if-pre-up.d/iptables
}

restart_services() {
    echo "[INFO] Restarting services..."
    systemctl restart strongswan
    systemctl restart xl2tpd
    systemctl enable strongswan
    systemctl enable xl2tpd
}

print_info() {
    echo
    echo "✅ L2TP/IPSec VPN setup completed!"
    echo
    echo "Server IP    : $IP"
    echo "PSK (secret) : $mypsk"
    echo "Username     : $username"
    echo "Password     : $password"
    echo
}

main() {
    check_root
    check_tun
    get_ip
    install_packages
    configure_ipsec
    configure_xl2tpd
    enable_ip_forwarding
    configure_firewall
    restart_services
    print_info
}

main
