# System Settings
#  Installing and Maintaining Software
#   Account and Access Control
#    System Accounting with auditd


# Install AIDE
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "aide"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Build and Test AIDE Database
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "aide"

AIDE_CONFIG=/etc/aide/aide.conf
DEFAULT_DB_PATH=/var/lib/aide/aide.db

# Fix db path in the config file, if necessary
if ! grep -q '^database=file:' ${AIDE_CONFIG}; then
    # replace_or_append gets confused by 'database=file' as a key, so should not be used.
    #replace_or_append "${AIDE_CONFIG}" '^database=file' "${DEFAULT_DB_PATH}" '@CCENUM@' '%s:%s'
    echo "database=file:${DEFAULT_DB_PATH}" >> ${AIDE_CONFIG}
fi

# Fix db out path in the config file, if necessary
if ! grep -q '^database_out=file:' ${AIDE_CONFIG}; then
    echo "database_out=file:${DEFAULT_DB_PATH}.new" >> ${AIDE_CONFIG}
fi

/usr/sbin/aideinit -y -f

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Configure AIDE to Verify the Audit Tools
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "aide"

if grep -i '^.*/usr/sbin/auditctl.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/auditctl.*#/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi

if grep -i '^.*/usr/sbin/auditd.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/auditd.*#/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi

if grep -i '^.*/usr/sbin/ausearch.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/ausearch.*#/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi

if grep -i '^.*/usr/sbin/aureport.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/aureport.*#/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi

if grep -i '^.*/usr/sbin/autrace.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/autrace.*#/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi

if grep -i '^.*/usr/sbin/augenrules.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/augenrules.*#/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi

if grep -i '^.*/usr/sbin/audispd.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/audispd.*#/usr/sbin/audispd p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/audispd p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Configure Periodic Execution of AIDE
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "aide"
DEBIAN_FRONTEND=noninteractive apt-get install -y "crontabs"

# AiDE usually adds its own cron jobs to /etc/cron.daily. If script is there, this rule is
# compliant. Otherwise, we copy the script to the /etc/cron.weekly
if ! egrep -q '^(\/usr\/bin\/)?aide(\.wrapper)?\s+' /etc/cron.*/*; then
    cp -f /usr/share/aide/config/cron.daily/aide /etc/cron.weekly/
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

#Package "prelink" Must not be Installed
if [[ -f /usr/sbin/prelink ]];
then
prelink -ua
fi

DEBIAN_FRONTEND=noninteractive apt-get remove -y "prelink"

# GNOME Desktop Environment
# Disable the GNOME3 Login User List
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/login-screen\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|gdm.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/gdm.d/00-security-settings"
DBDIR="/etc/dconf/db/gdm.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*disable-user-list\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)disable-user-list(\s*=)/#\1disable-user-list\2/g" "${SETTINGSFILES[@]}"
    fi
fi


[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/login-screen\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/login-screen]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "true")"
if grep -q "^\\s*disable-user-list\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*disable-user-list\\s*=\\s*.*/disable-user-list=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/login-screen\\]|a\\disable-user-list=${escaped_value}" "${DCONFFILE}"
fi

dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/login-screen/disable-user-list$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|gdm.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/gdm.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/login-screen/disable-user-list$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/login-screen/disable-user-list$" /etc/dconf/db/gdm.d/
then
    echo "/org/gnome/login-screen/disable-user-list" >> "/etc/dconf/db/gdm.d/locks/00-security-settings-lock"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Disable XDMCP in GDM
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed; then

# Try find '[xdmcp]' and 'Enable' in '/etc/gdm3/custom.conf', if it exists, set
# to 'false', if it isn't here, add it, if '[xdmcp]' doesn't exist, add it there
if grep -qzosP '[[:space:]]*\[xdmcp]([^\n\[]*\n+)+?[[:space:]]*Enable' '/etc/gdm3/custom.conf'; then
    
    sed -i "s/Enable[^(\n)]*/Enable=false/" '/etc/gdm3/custom.conf'
elif grep -qs '[[:space:]]*\[xdmcp]' '/etc/gdm3/custom.conf'; then
    sed -i "/[[:space:]]*\[xdmcp]/a Enable=false" '/etc/gdm3/custom.conf'
else
    if test -d "/etc/gdm3"; then
        printf '%s\n' '[xdmcp]' "Enable=false" >> '/etc/gdm3/custom.conf'
    else
        echo "Config file directory '/etc/gdm3' doesnt exist, not remediating, assuming non-applicability." >&2
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Disable GNOME3 Automounting
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/media-handling\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*automount\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)automount(\s*=)/#\1automount\2/g" "${SETTINGSFILES[@]}"
    fi
fi


[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/desktop/media-handling\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/desktop/media-handling]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "false")"
if grep -q "^\\s*automount\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*automount\\s*=\\s*.*/automount=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/desktop/media-handling\\]|a\\automount=${escaped_value}" "${DCONFFILE}"
fi

dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/media-handling/automount$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/media-handling/automount$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/media-handling/automount$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/media-handling/automount" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Disable GNOME3 Automount Opening
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/media-handling\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*automount-open\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)automount-open(\s*=)/#\1automount-open\2/g" "${SETTINGSFILES[@]}"
    fi
fi


[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/desktop/media-handling\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/desktop/media-handling]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "false")"
if grep -q "^\\s*automount-open\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*automount-open\\s*=\\s*.*/automount-open=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/desktop/media-handling\\]|a\\automount-open=${escaped_value}" "${DCONFFILE}"
fi

dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/media-handling/automount-open$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/media-handling/automount-open$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/media-handling/automount-open$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/media-handling/automount-open" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Disable GNOME3 Automount running
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/media-handling\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*autorun-never\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)autorun-never(\s*=)/#\1autorun-never\2/g" "${SETTINGSFILES[@]}"
    fi
fi


[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/desktop/media-handling\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/desktop/media-handling]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "true")"
if grep -q "^\\s*autorun-never\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*autorun-never\\s*=\\s*.*/autorun-never=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/desktop/media-handling\\]|a\\autorun-never=${escaped_value}" "${DCONFFILE}"
fi

dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/media-handling/autorun-never$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/media-handling/autorun-never$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/media-handling/autorun-never$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/media-handling/autorun-never" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Set GNOME3 Screensaver Lock Delay After Activation Period
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

var_screensaver_lock_delay='0'


# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/screensaver\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*lock-delay\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)lock-delay(\s*=)/#\1lock-delay\2/g" "${SETTINGSFILES[@]}"
    fi
fi


[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/desktop/screensaver\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/desktop/screensaver]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "uint32 ${var_screensaver_lock_delay}")"
if grep -q "^\\s*lock-delay\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*lock-delay\\s*=\\s*.*/lock-delay=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/desktop/screensaver\\]|a\\lock-delay=${escaped_value}" "${DCONFFILE}"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Enable GNOME3 Screensaver Lock After Idle Period
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/screensaver\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*lock-enabled\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)lock-enabled(\s*=)/#\1lock-enabled\2/g" "${SETTINGSFILES[@]}"
    fi
fi


[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/desktop/screensaver\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/desktop/screensaver]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "true")"
if grep -q "^\\s*lock-enabled\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*lock-enabled\\s*=\\s*.*/lock-enabled=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/desktop/screensaver\\]|a\\lock-enabled=${escaped_value}" "${DCONFFILE}"
fi

dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/screensaver/lock-enabled$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/screensaver/lock-enabled$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/screensaver/lock-enabled$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/screensaver/lock-enabled" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Remove the GDM Package Group
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed; then

# CAUTION: This remediation script will remove gdm
#	   from the system, and may remove any packages
#	   that depend on gdm. Execute this
#	   remediation AFTER testing on a non-production
#	   system!

DEBIAN_FRONTEND=noninteractive apt-get remove -y "gdm"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Sudo
# Install sudo Package
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "sudo"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure Only Users Logged In To Real tty Can Execute Sudo - sudo use_pty
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'sudo' 2>/dev/null | grep -q installed; then

if /usr/sbin/visudo -qcf /etc/sudoers; then
    cp /etc/sudoers /etc/sudoers.bak
    if ! grep -P '^[\s]*Defaults[\s]*\buse_pty\b.*$' /etc/sudoers; then
        # sudoers file doesn't define Option use_pty
        echo "Defaults use_pty" >> /etc/sudoers
    fi
    
    # Check validity of sudoers and cleanup bak
    if /usr/sbin/visudo -qcf /etc/sudoers; then
        rm -f /etc/sudoers.bak
    else
        echo "Fail to validate remediated /etc/sudoers, reverting to original file."
        mv /etc/sudoers.bak /etc/sudoers
        false
    fi
else
    echo "Skipping remediation, /etc/sudoers failed to validate"
    false
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure Sudo Logfile Exists - sudo logfile
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'sudo' 2>/dev/null | grep -q installed; then

var_sudo_logfile='/var/log/sudo.log'


if /usr/sbin/visudo -qcf /etc/sudoers; then
    cp /etc/sudoers /etc/sudoers.bak
    if ! grep -P '^[\s]*Defaults[\s]*\blogfile=("(?:\\"|\\\\|[^"\\\n])*"\B|[^"](?:(?:\\,|\\"|\\ |\\\\|[^", \\\n])*)\b)\b.*$' /etc/sudoers; then
        # sudoers file doesn't define Option logfile
        echo "Defaults logfile=${var_sudo_logfile}" >> /etc/sudoers
    else
        # sudoers file defines Option logfile, remediate if appropriate value is not set
        if ! grep -P "^[\s]*Defaults.*\blogfile=${var_sudo_logfile}\b.*$" /etc/sudoers; then
            
            escaped_variable=${var_sudo_logfile//$'/'/$'\/'}
            sed -Ei "s/(^[\s]*Defaults.*\blogfile=)[-]?.+(\b.*$)/\1$escaped_variable\2/" /etc/sudoers
        fi
    fi
    
    # Check validity of sudoers and cleanup bak
    if /usr/sbin/visudo -qcf /etc/sudoers; then
        rm -f /etc/sudoers.bak
    else
        echo "Fail to validate remediated /etc/sudoers, reverting to original file."
        mv /etc/sudoers.bak /etc/sudoers
        false
    fi
else
    echo "Skipping remediation, /etc/sudoers failed to validate"
    false
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure Users Re-Authenticate for Privilege Escalation - sudo !authenticate
for f in /etc/sudoers /etc/sudoers.d/* ; do
  if [ ! -e "$f" ] ; then
    continue
  fi
  matching_list=$(grep -P '^(?!#).*[\s]+\!authenticate.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      # comment out "!authenticate" matches to preserve user data
      sed -i "s/^${entry}$/# &/g" $f
    done <<< "$matching_list"

    /usr/sbin/visudo -cf $f &> /dev/null || echo "Fail to validate $f with visudo"
  fi
done

# Ensure Users Re-Authenticate for Privilege Escalation - sudo
for f in /etc/sudoers /etc/sudoers.d/* ; do
  if [ ! -e "$f" ] ; then
    continue
  fi
  matching_list=$(grep -P '^(?!#).*[\s]+NOPASSWD[\s]*\:.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      # comment out "NOPASSWD" matches to preserve user data
      sed -i "s/^${entry}$/# &/g" $f
    done <<< "$matching_list"

    /usr/sbin/visudo -cf $f &> /dev/null || echo "Fail to validate $f with visudo"
  fi
done

for f in /etc/sudoers /etc/sudoers.d/* ; do
  if [ ! -e "$f" ] ; then
    continue
  fi
  matching_list=$(grep -P '^(?!#).*[\s]+\!authenticate.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      # comment out "!authenticate" matches to preserve user data
      sed -i "s/^${entry}$/# &/g" $f
    done <<< "$matching_list"

    /usr/sbin/visudo -cf $f &> /dev/null || echo "Fail to validate $f with visudo"
  fi
done

# Require Re-Authentication When Using the sudo Command
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'sudo' 2>/dev/null | grep -q installed; then

var_sudo_timestamp_timeout='15'


if grep -Px '^[\s]*Defaults.*timestamp_timeout[\s]*=.*' /etc/sudoers.d/*; then
    find /etc/sudoers.d/ -type f -exec sed -Ei "/^[[:blank:]]*Defaults.*timestamp_timeout[[:blank:]]*=.*/d" {} \;
fi

if /usr/sbin/visudo -qcf /etc/sudoers; then
    cp /etc/sudoers /etc/sudoers.bak
    if ! grep -P '^[\s]*Defaults.*timestamp_timeout[\s]*=[\s]*[-]?\w+.*$' /etc/sudoers; then
        # sudoers file doesn't define Option timestamp_timeout
        echo "Defaults timestamp_timeout=${var_sudo_timestamp_timeout}" >> /etc/sudoers
    else
        # sudoers file defines Option timestamp_timeout, remediate if appropriate value is not set
        if ! grep -P "^[\s]*Defaults.*timestamp_timeout[\s]*=[\s]*${var_sudo_timestamp_timeout}.*$" /etc/sudoers; then
            
            sed -Ei "s/(^[[:blank:]]*Defaults.*timestamp_timeout[[:blank:]]*=)[[:blank:]]*[-]?\w+(.*$)/\1${var_sudo_timestamp_timeout}\2/" /etc/sudoers
        fi
    fi
    
    # Check validity of sudoers and cleanup bak
    if /usr/sbin/visudo -qcf /etc/sudoers; then
        rm -f /etc/sudoers.bak
    else
        echo "Fail to validate remediated /etc/sudoers, reverting to original file."
        mv /etc/sudoers.bak /etc/sudoers
        false
    fi
else
    echo "Skipping remediation, /etc/sudoers failed to validate"
    false
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

