# AppArmor
# Ensure AppArmor is installed
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "apparmor"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Enforce all AppArmor Profiles
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# make sure apparmor-utils is installed for aa-complain and aa-enforce
DEBIAN_FRONTEND=noninteractive apt-get install -y "apparmor-utils"

# Ensure all AppArmor Profiles are enforcing
apparmor_parser -q -r /etc/apparmor.d/
aa-enforce /etc/apparmor.d/*


UNCONFINED=$(aa-status | grep "processes are unconfined" | awk '{print $1;}')
if [ $UNCONFINED -ne 0 ];

then
  echo -e "***WARNING***: There are some unconfined processes:"
  echo -e "----------------------------"
  echo "The may need to have a profile created or activated for them and then be restarted."
  for PROCESS in "${UNCONFINED[@]}"
  do
      echo "$PROCESS"
  done
  echo -e "----------------------------"
  echo "The may need to have a profile created or activated for them and then be restarted."
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# All AppArmor Profiles are in enforce or complain mode
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

var_apparmor_mode='enforce'


# make sure apparmor-utils is installed for aa-complain and aa-enforce
DEBIAN_FRONTEND=noninteractive apt-get install -y "apparmor-utils"

# Reload all AppArmor profiles
apparmor_parser -q -r /etc/apparmor.d/

# Set the mode
APPARMOR_MODE="$var_apparmor_mode"

if [ "$APPARMOR_MODE" = "enforce" ]
then
  # Set all profiles to enforce mode
  aa-enforce /etc/apparmor.d/*
fi

if [ "$APPARMOR_MODE" = "complain" ]
then
  # Set all profiles to complain mode
  aa-complain /etc/apparmor.d/*
fi


UNCONFINED=$(aa-status | grep "processes are unconfined" | awk '{print $1;}')
if [ $UNCONFINED -ne 0 ];

then
  echo -e "***WARNING***: There are some unconfined processes:"
  echo -e "----------------------------"
  echo "The may need to have a profile created or activated for them and then be restarted."
  for PROCESS in "${UNCONFINED[@]}"
  do
      echo "$PROCESS"
  done
  echo -e "----------------------------"
  echo "The may need to have a profile created or activated for them and then be restarted."
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure AppArmor is enabled in the bootloader configuration 
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Correct the form of default kernel command line in GRUB
if grep -q '^GRUB_CMDLINE_LINUX=.*apparmor=.*"'  '/etc/default/grub' ; then
       # modify the GRUB command-line if an apparmor= arg already exists
       sed -i "s/\(^GRUB_CMDLINE_LINUX=\".*\)apparmor=[^[:space:]]\+\(.*\"\)/\1apparmor=1\2/"  '/etc/default/grub'
else
       # no apparmor=arg is present, append it
       sed -i "s/\(^GRUB_CMDLINE_LINUX=\".*\)\"/\1 apparmor=1\"/"  '/etc/default/grub'
fi
# Correct the form of default kernel command line in GRUB
if grep -q '^GRUB_CMDLINE_LINUX=.*security=.*"'  '/etc/default/grub' ; then
       # modify the GRUB command-line if an security= arg already exists
       sed -i "s/\(^GRUB_CMDLINE_LINUX=\".*\)security=[^[:space:]]\+\(.*\"\)/\1security=apparmor\2/"  '/etc/default/grub'
else
       # no security=arg is present, append it
       sed -i "s/\(^GRUB_CMDLINE_LINUX=\".*\)\"/\1 security=apparmor\"/"  '/etc/default/grub'
fi


update-grub

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

