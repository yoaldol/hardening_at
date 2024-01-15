# GRUB2 bootloader configuration
# Non-UEFI GRUB2 bootloader configuration
# Verify /boot/grub/grub.cfg User Ownership
# Remediation is applicable only in certain platforms
if [ ! -d /sys/firmware/efi ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'grub2-common' 2>/dev/null | grep -q installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

chown 0 /boot/grub/grub.cfg

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Verify /boot/grub/grub.cfg Permissions
# Remediation is applicable only in certain platforms
if [ ! -d /sys/firmware/efi ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'grub2-common' 2>/dev/null | grep -q installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

chmod u-xs,g-xwrs,o-xwrt /boot/grub/grub.cfg

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# UEFI GRUB2 bootloader configuration


