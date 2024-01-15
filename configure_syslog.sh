# Configure Syslog
# systemd-journald
# Install systemd-journal-remote Package
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "systemd-journal-remote"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Enable systemd-journald Service
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" unmask 'systemd-journald.service'
"$SYSTEMCTL_EXEC" start 'systemd-journald.service'
"$SYSTEMCTL_EXEC" enable 'systemd-journald.service'

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure journald is configured to compress large log files
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if [ -e "/etc/systemd/journald.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*Compress\s*=\s*/d" "/etc/systemd/journald.conf"
else
    touch "/etc/systemd/journald.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/systemd/journald.conf"

cp "/etc/systemd/journald.conf" "/etc/systemd/journald.conf.bak"
# Insert before the line matching the regex '^#\s*Compress'.
line_number="$(LC_ALL=C grep -n "^#\s*Compress" "/etc/systemd/journald.conf.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^#\s*Compress', insert at
    # the end of the file.
    printf '%s\n' "Compress='yes'" >> "/etc/systemd/journald.conf"
else
    head -n "$(( line_number - 1 ))" "/etc/systemd/journald.conf.bak" > "/etc/systemd/journald.conf"
    printf '%s\n' "Compress='yes'" >> "/etc/systemd/journald.conf"
    tail -n "+$(( line_number ))" "/etc/systemd/journald.conf.bak" >> "/etc/systemd/journald.conf"
fi
# Clean up after ourselves.
rm "/etc/systemd/journald.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure journald is configured to write log files to persistent disk
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if [ -e "/etc/systemd/journald.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*Storage\s*=\s*/d" "/etc/systemd/journald.conf"
else
    touch "/etc/systemd/journald.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/systemd/journald.conf"

cp "/etc/systemd/journald.conf" "/etc/systemd/journald.conf.bak"
# Insert before the line matching the regex '^#\s*Storage'.
line_number="$(LC_ALL=C grep -n "^#\s*Storage" "/etc/systemd/journald.conf.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^#\s*Storage', insert at
    # the end of the file.
    printf '%s\n' "Storage='persistent'" >> "/etc/systemd/journald.conf"
else
    head -n "$(( line_number - 1 ))" "/etc/systemd/journald.conf.bak" > "/etc/systemd/journald.conf"
    printf '%s\n' "Storage='persistent'" >> "/etc/systemd/journald.conf"
    tail -n "+$(( line_number ))" "/etc/systemd/journald.conf.bak" >> "/etc/systemd/journald.conf"
fi
# Clean up after ourselves.
rm "/etc/systemd/journald.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Disable systemd-journal-remote Socket
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

SOCKET_NAME="systemd-journal-remote.socket"
SYSTEMCTL_EXEC='/usr/bin/systemctl'

if "$SYSTEMCTL_EXEC" -q list-unit-files --type socket | grep -q "$SOCKET_NAME"; then
    "$SYSTEMCTL_EXEC" stop "$SOCKET_NAME"
    "$SYSTEMCTL_EXEC" unmask "$SOCKET_NAME"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Configure rsyslogd to Accept Remote Messages If Acting as a Log Server
# Ensure rsyslog Does Not Accept Remote Messages Unless Acting As Log Server
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

legacy_regex='^\s*\$(((Input(TCP|RELP)|UDP)ServerRun)|ModLoad\s+(imtcp|imudp|imrelp))'
rainer_regex='^\s*(module|input)\((load|type)="(imtcp|imudp)".*$'

readarray -t legacy_targets < <(grep -l -E -r "${legacy_regex[@]}" /etc/rsyslog.conf /etc/rsyslog.d/)
readarray -t rainer_targets < <(grep -l -E -r "${rainer_regex[@]}" /etc/rsyslog.conf /etc/rsyslog.d/)

config_changed=false
if [ ${#legacy_targets[@]} -gt 0 ]; then
    for target in "${legacy_targets[@]}"; do
        sed -E -i "/$legacy_regex/ s/^/# /" "$target"
    done
    config_changed=true
fi

if [ ${#rainer_targets[@]} -gt 0 ]; then
    for target in "${rainer_targets[@]}"; do
        sed -E -i "/$rainer_regex/ s/^/# /" "$target"
    done
    config_changed=true
fi

if $config_changed; then
    systemctl restart rsyslog.service
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Rsyslog Logs Sent To Remote Host
# Ensure Logs Sent To Remote Host
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

rsyslog_remote_loghost_address='logcollector'


# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^\*\.\*")

# shellcheck disable=SC2059
printf -v formatted_output "%s %s" "$stripped_key" "@@$rsyslog_remote_loghost_address"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^\*\.\*\\>" "/etc/rsyslog.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^\*\.\*\\>.*/$escaped_formatted_output/gi" "/etc/rsyslog.conf"
else
    if [[ -s "/etc/rsyslog.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/rsyslog.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/rsyslog.conf"
    fi
    printf '%s\n' "$formatted_output" >> "/etc/rsyslog.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure rsyslog is Installed
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "rsyslog"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Enable rsyslog Service 
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" unmask 'rsyslog.service'
"$SYSTEMCTL_EXEC" start 'rsyslog.service'
"$SYSTEMCTL_EXEC" enable 'rsyslog.service'

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure rsyslog Default File Permissions Configured
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

readarray -t targets < <(grep -H '^\s*$FileCreateMode' /etc/rsyslog.conf /etc/rsyslog.d/*)

# if $FileCreateMode set in multiple places
if [ ${#targets[@]} -gt 1 ]; then
    # delete all and create new entry with expected value
    sed -i '/^\s*$FileCreateMode/d' /etc/rsyslog.conf /etc/rsyslog.d/*
    echo '$FileCreateMode 0640' > /etc/rsyslog.d/99-rsyslog_filecreatemode.conf
# if $FileCreateMode set in only one place
elif [ "${#targets[@]}" -eq 1 ]; then
    filename=$(echo "${targets[0]}" | cut -d':' -f1)
    value=$(echo "${targets[0]}" | cut -d' ' -f2)
    #convert to decimal and bitwise or operation
    result=$((8#$value | 416))
    # if more permissive than expected, then set it to 0640
    if [ $result -ne 416 ]; then
        # if value is wrong remove it
        sed -i '/^\s*$FileCreateMode/d' $filename
        echo '$FileCreateMode 0640' > $filename
    fi
else
    echo '$FileCreateMode 0640' > /etc/rsyslog.d/99-rsyslog_filecreatemode.conf
fi

systemctl restart rsyslog.service

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

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