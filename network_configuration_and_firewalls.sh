# Network Configuration and Firewalls
# iptables and ip6tables
# Inspect and Activate Default Rules
# Set Default ip6tables Policy for Incoming Packets
# Remediation is applicable only in certain platforms
if ( ! ( dpkg-query --show --showformat='${db:Status-Status}\n' 'nftables' 2>/dev/null | grep -q installed ) && ! ( dpkg-query --show --showformat='${db:Status-Status}\n' 'ufw' 2>/dev/null | grep -q installed ) ); then

sed -i 's/^:INPUT ACCEPT.*/:INPUT DROP [0:0]/g' /etc/sysconfig/ip6tables

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Set configuration for IPv6 loopback traffic
# Remediation is applicable only in certain platforms
if ( ! ( dpkg-query --show --showformat='${db:Status-Status}\n' 'nftables' 2>/dev/null | grep -q installed ) && ! ( dpkg-query --show --showformat='${db:Status-Status}\n' 'ufw' 2>/dev/null | grep -q installed ) ); then

if [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6)" -eq 0 ]; then
  # IPv6 is not disabled, so run the script
  ip6tables -A INPUT -i lo -j ACCEPT
  ip6tables -A OUTPUT -o lo -j ACCEPT
  ip6tables -A INPUT -s ::1 -j DROP
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

