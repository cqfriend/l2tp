#!/usr/bin/env bash
set -e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

username="pi"
password="pi123"
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
    IP=$(wget -qO- ip.sb)
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
version 2.0

config setup
    protostack=netkey
    nhelpers=0
    uniqueids=no
    interfaces=%defaultroute
    virtual_private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12

conn l2tp-psk
    rightsubnet=vhost:0.0.0.0/0  # 修正子网定义
    also=l2tp-psk-nonat

conn l2tp-psk-nonat
    authby=secret
    pfs=no
    auto=add
    keyingtries=3
    rekey=no
    ikelifetime=8h
    keylife=1h
    type=transport
    left=%defaultroute
    leftid=$IP
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
    dpddelay=40
    dpdtimeout=130
    dpdaction=restart  # 改为重启
    sha2-truncbug=yes
    ike=aes128-sha1-modp1024  # 兼端算法
    esp=aes256-modp1024,aes128-sha1-modp1024
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
ip range = ${iprange}.2-${iprange}.2
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
mtu 1300
mru 1300
hide-password
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
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p 
}

configure_firewall() {
    echo "[INFO] Configuring iptables..."
# 清除 nat 表的所有规则
#iptables -t nat -F
# 清除 filter 表的所有规则
#iptables -F
# 清除 mangle 表的所有规则（如果有使用）
#iptables -t mangle -F
# 清除 raw 表的所有规则（如果有使用）
#iptables -t raw -F
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables -A INPUT -p udp --dport 500 -j ACCEPT
    iptables -A INPUT -p udp --dport 4500 -j ACCEPT
    iptables -A INPUT -p udp --dport 1701 -j ACCEPT
    iptables -A INPUT -p esp -j ACCEPT
    iptables -A INPUT -p ah -j ACCEPT
    # 定义 VPN 客户端 IP
    VPN_CLIENT_IP="${iprange}.2"

    # 批量开放端口 31400-31409 的 TCP 和 UDP 流量
    PORT_START=31400
    PORT_END=31409

    # 使用单个规则处理 TCP 和 UDP 的端口范围
    iptables -A INPUT -p tcp --match multiport --dports ${PORT_START}:${PORT_END} -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT


    # DNAT 规则
    iptables -t nat -A PREROUTING -p tcp --match multiport --dports ${PORT_START}:${PORT_END} -j DNAT --to-destination $VPN_CLIENT_IP:${PORT_START}-${PORT_END}


    iptables-save > /etc/iptables.rules

    cat > /etc/network/if-pre-up.d/iptables <<EOF
#!/bin/sh
/sbin/iptables-restore < /etc/iptables.rules
EOF
    chmod +x /etc/network/if-pre-up.d/iptables
}

restart_services() {
    echo "[INFO] Restarting services..."
    systemctl enable strongswan-starter
    systemctl start strongswan-starter
    systemctl restart xl2tpd
    systemctl enable xl2tpd
    systemctl restart strongswan-starter

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
