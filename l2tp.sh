#!/usr/bin/env bash
set -e

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

cur_dir=$(pwd)

# 用户名和密码自定义
username="piminer"
password="piminer123"
mypsk="1"

rootness(){
    if [[ $EUID -ne 0 ]]; then
        echo "Error: This script must be run as root!" >&2
        exit 1
    fi
}

tunavailable(){
    if [[ ! -e /dev/net/tun ]]; then
        echo "Error: TUN/TAP is not available!" >&2
        exit 1
    fi
}

get_ip(){
    IP=$(hostname -I | awk '{print $1}')
    [ -z "$IP" ] && IP=$(wget -qO- ipv4.icanhazip.com)
}

disable_firewalld(){
    echo "Disabling UFW (if present)..."
    systemctl disable ufw >/dev/null 2>&1 || true
    systemctl stop ufw >/dev/null 2>&1 || true
}

preinstall_l2tp(){
    echo "Checking for OpenVZ..."
    if [ -d "/proc/vz" ]; then
        echo "WARNING: Your system uses OpenVZ. IPSec may not work properly."
        read -p "Continue anyway? [y/N]: " confirm
        [[ "$confirm" != "y" ]] && exit 0
    fi

    ipc=$(hostname -I | awk -F '.' '{print $3}')
    iprange="172.$((RANDOM % 16 + 16)).${ipc:-16}"
}

install_dependencies(){
    echo "Installing required packages..."
    apt update
    DEBIAN_FRONTEND=noninteractive apt install -y strongswan xl2tpd ppp iptables iptables-persistent wget curl net-tools
}

configure_ipsec(){
    echo "Configuring IPsec..."
    cat > /etc/ipsec.conf <<EOF
config setup
    charondebug="all"
    uniqueids=no

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

configure_xl2tpd(){
    echo "Configuring xl2tpd..."
    cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lns default]
ip range = ${iprange}.2-${iprange}.10
local ip = ${iprange}.1
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

    cat > /etc/ppp/options.xl2tpd <<EOF
ipcp-accept-local
ipcp-accept-remote
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 8.8.4.4
noccp
auth
hide-password
idle 1800
debug
proxyarp
connect-delay 5000
EOF

    cat > /etc/ppp/chap-secrets <<EOF
# client    server    secret    IP addresses
$username   l2tpd     $password  *
EOF
}

enable_ip_forwarding(){
    echo "Enabling IP forwarding..."
    sed -i '/^#net.ipv4.ip_forward=1/c\net.ipv4.ip_forward=1' /etc/sysctl.conf
    sysctl -p
}

configure_iptables(){
    echo "Configuring iptables rules..."
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X

    iptables -A INPUT -p udp --dport 500 -j ACCEPT
    iptables -A INPUT -p udp --dport 4500 -j ACCEPT
    iptables -A INPUT -p udp --dport 1701 -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -p icmp -j ACCEPT
    iptables -P INPUT DROP
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT

    iptables -t nat -A POSTROUTING -s ${iprange}.0/24 -o eth0 -j MASQUERADE

    netfilter-persistent save
}

start_services(){
    echo "Starting services..."
    systemctl restart strongswan
    systemctl restart xl2tpd
    systemctl enable strongswan
    systemctl enable xl2tpd
}

print_info(){
    echo
    echo "VPN setup completed."
    echo "=============================="
    echo "Server IP   : $IP"
    echo "Username    : $username"
    echo "Password    : $password"
    echo "PSK         : $mypsk"
    echo "=============================="
}

main(){
    rootness
    tunavailable
    get_ip
    preinstall_l2tp
    disable_firewalld
    install_dependencies
    configure_ipsec
    configure_xl2tpd
    enable_ip_forwarding
    configure_iptables
    start_services
    print_info
}

main
