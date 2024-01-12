# System Accounting with auditd
# Configure auditd Rules for Comprehensive Auditing
# Record Events that Modify the System's Discretionary Access Controls
# Record Events that Modify the System's Discretionary Access Controls - chmod
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="chmod"
	KEY="perm_mod"
	SYSCALL_GROUPING="chmod fchmod fchmodat"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify the System's Discretionary Access Controls - chown
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="chown"
	KEY="perm_mod"
	SYSCALL_GROUPING="chown fchown fchownat lchown"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify the System's Discretionary Access Controls - fchmod
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fchmod"
	KEY="perm_mod"
	SYSCALL_GROUPING="chmod fchmod fchmodat"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify the System's Discretionary Access Controls - fchmodat
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fchmodat"
	KEY="perm_mod"
	SYSCALL_GROUPING="chmod fchmod fchmodat"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify the System's Discretionary Access Controls - fchown
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fchown"
	KEY="perm_mod"
	SYSCALL_GROUPING="chown fchown fchownat lchown"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify the System's Discretionary Access Controls - fchownat
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fchownat"
	KEY="perm_mod"
	SYSCALL_GROUPING="chown fchown fchownat lchown"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify the System's Discretionary Access Controls - fremovexattr
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fremovexattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify the System's Discretionary Access Controls - fsetxattr
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fsetxattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify the System's Discretionary Access Controls - lchown
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="lchown"
	KEY="perm_mod"
	SYSCALL_GROUPING="chown fchown fchownat lchown"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify the System's Discretionary Access Controls - lremovexattr
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="lremovexattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify the System's Discretionary Access Controls - lsetxattr
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="lsetxattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify the System's Discretionary Access Controls - removexattr 
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="removexattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify the System's Discretionary Access Controls - setxattr
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="setxattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Execution Attempts to Run ACL Privileged Commands
# Record Any Attempts to Run chacl 
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/chacl -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Any Attempts to Run setfacl
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/setfacl -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Execution Attempts to Run SELinux Privileged Commands
# Record Any Attempts to Run chcon
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/chcon -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record File Deletion Events by User 
# Ensure auditd Collects File Deletion Events by User - rename
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="rename"
	KEY="delete"
	SYSCALL_GROUPING="unlink unlinkat rename renameat rmdir"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects File Deletion Events by User - renameat
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="renameat"
	KEY="delete"
	SYSCALL_GROUPING="unlink unlinkat rename renameat rmdir"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects File Deletion Events by User - unlink
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="unlink"
	KEY="delete"
	SYSCALL_GROUPING="unlink unlinkat rename renameat rmdir"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects File Deletion Events by User - unlinkat
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="unlinkat"
	KEY="delete"
	SYSCALL_GROUPING="unlink unlinkat rename renameat rmdir"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Unauthorized Access Attempts Events to Files (unsuccessful)
# Record Unsuccessful Access Attempts to Files - creat
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL="creat"
KEY="access"
SYSCALL_GROUPING="creat ftruncate truncate open openat open_by_handle_at"

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EACCES"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EPERM"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Unsuccessful Access Attempts to Files - ftruncate
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL="ftruncate"
KEY="access"
SYSCALL_GROUPING="creat ftruncate truncate open openat open_by_handle_at"

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EACCES"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EPERM"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Unsuccessful Access Attempts to Files - open
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL="open"
KEY="access"
SYSCALL_GROUPING="creat ftruncate truncate open openat open_by_handle_at"

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EACCES"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EPERM"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Unsuccessful Access Attempts to Files - openat
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL="openat"
KEY="access"
SYSCALL_GROUPING="creat ftruncate truncate open openat open_by_handle_at"

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EACCES"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EPERM"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Unsuccessful Access Attempts to Files - truncate
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL="truncate"
KEY="access"
SYSCALL_GROUPING="creat ftruncate truncate open openat open_by_handle_at"

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EACCES"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EPERM"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Information on Kernel Modules Loading and Unloading
# Ensure auditd Collects Information on Kernel Module Unloading - delete_module
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
# Note: 32-bit and 64-bit kernel syscall numbers not always line up =>
#       it's required on a 64-bit system to check also for the presence
#       of 32-bit's equivalent of the corresponding rule.
#       (See `man 7 audit.rules` for details )
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	
	AUID_FILTERS=""
	
	SYSCALL="delete_module"
	KEY="modules"
	SYSCALL_GROUPING="delete_module"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on Kernel Module Loading - init_module
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
# Note: 32-bit and 64-bit kernel syscall numbers not always line up =>
#       it's required on a 64-bit system to check also for the presence
#       of 32-bit's equivalent of the corresponding rule.
#       (See `man 7 audit.rules` for details )
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	
	AUID_FILTERS=""
	
	SYSCALL="init_module"
	KEY="modules"
	SYSCALL_GROUPING="init_module finit_module"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Attempts to Alter Logon and Logout Events
# Record Attempts to Alter Logon and Logout Events - faillog
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/log/faillog" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/log/faillog $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/log/faillog$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/log/faillog -p wa -k logins" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/logins.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/var/log/faillog" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/logins.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/logins.rules"
    # If the logins.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/log/faillog" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/log/faillog $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/log/faillog$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/log/faillog -p wa -k logins" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Attempts to Alter Logon and Logout Events - lastlog
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/log/lastlog" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/log/lastlog $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/log/lastlog$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/log/lastlog -p wa -k logins" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/logins.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/var/log/lastlog" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/logins.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/logins.rules"
    # If the logins.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/log/lastlog" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/log/lastlog $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/log/lastlog$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/log/lastlog -p wa -k logins" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Attempts to Alter Logon and Logout Events - tallylog
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/log/tallylog" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/log/tallylog $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/log/tallylog$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/log/tallylog -p wa -k logins" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/logins.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/var/log/tallylog" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/logins.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/logins.rules"
    # If the logins.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/log/tallylog" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/log/tallylog $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/log/tallylog$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/log/tallylog -p wa -k logins" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Information on the Use of Privileged Commands 
# Ensure auditd Collects Information on the Use of Privileged Commands - at
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/at -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - chage
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/chage -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - chfn
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/chfn -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - chsh
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/chsh -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - crontab
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/crontab -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - gpasswd
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/gpasswd -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - insmod
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/sbin/insmod" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/sbin/insmod $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "x" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/sbin/insmod$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /sbin/insmod -p x -k modules" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/modules.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/sbin/insmod" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/modules.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/modules.rules"
    # If the modules.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/sbin/insmod" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/sbin/insmod $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "x" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/sbin/insmod$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /sbin/insmod -p x -k modules" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - modprobe 
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/sbin/modprobe" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/sbin/modprobe $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "x" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/sbin/modprobe$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /sbin/modprobe -p x -k modules" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/modules.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/sbin/modprobe" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/modules.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/modules.rules"
    # If the modules.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/sbin/modprobe" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/sbin/modprobe $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "x" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/sbin/modprobe$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /sbin/modprobe -p x -k modules" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - mount
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/mount -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - newgidmap
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/newgidmap -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - newgrp 
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/newgrp -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - newuidmap
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/newuidmap -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - postdrop
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/sbin/postdrop -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - postqueue
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/sbin/postqueue -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - rmmod
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/sbin/rmmod" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/sbin/rmmod $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "x" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/sbin/rmmod$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /sbin/rmmod -p x -k modules" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/modules.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/sbin/rmmod" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/modules.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/modules.rules"
    # If the modules.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/sbin/rmmod" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/sbin/rmmod $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "x" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/sbin/rmmod$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /sbin/rmmod -p x -k modules" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Any Attempts to Run ssh-agent 
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/ssh-agent -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - ssh-keysign
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/libexec/openssh/ssh-keysign -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - su
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/su -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - sudo
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/sudo -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - sudoedit
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/sudoedit -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - umount 
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/umount -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - unix_chkpwd
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/sbin/unix_chkpwd -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on the Use of Privileged Commands - usermod
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/sbin/usermod -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Records Events that Modify Date and Time Information 
# Make the auditd Configuration Immutable
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Traverse all of:
#
# /etc/audit/audit.rules,			(for auditctl case)
# /etc/audit/rules.d/*.rules			(for augenrules case)
#
# files to check if '-e .*' setting is present in that '*.rules' file already.
# If found, delete such occurrence since auditctl(8) manual page instructs the
# '-e 2' rule should be placed as the last rule in the configuration
find /etc/audit /etc/audit/rules.d -maxdepth 1 -type f -name '*.rules' -exec sed -i '/-e[[:space:]]\+.*/d' {} ';'

# Append '-e 2' requirement at the end of both:
# * /etc/audit/audit.rules file 		(for auditctl case)
# * /etc/audit/rules.d/immutable.rules		(for augenrules case)

for AUDIT_FILE in "/etc/audit/audit.rules" "/etc/audit/rules.d/immutable.rules"
do
	echo '' >> $AUDIT_FILE
	echo '# Set the audit.rules configuration immutable per security requirements' >> $AUDIT_FILE
	echo '# Reboot is required to change audit rules once this setting is applied' >> $AUDIT_FILE
	echo '-e 2' >> $AUDIT_FILE
	chmod o-rwx $AUDIT_FILE
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify the System's Mandatory Access Controls
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/selinux/" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/selinux/ $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/selinux/$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/selinux/ -p wa -k MAC-policy" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/MAC-policy.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/selinux/" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/MAC-policy.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/MAC-policy.rules"
    # If the MAC-policy.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/selinux/" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/selinux/ $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/selinux/$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/selinux/ -p wa -k MAC-policy" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects Information on Exporting to Media (successful)
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="mount"
	KEY="perm_mod"
	SYSCALL_GROUPING=""

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify the System's Network Environment
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS=""
	SYSCALL="sethostname setdomainname"
	KEY="audit_rules_networkconfig_modification"
	SYSCALL_GROUPING="sethostname setdomainname"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

# Then perform the remediations for the watch rules
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/issue" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/issue $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/issue$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/issue -p wa -k audit_rules_networkconfig_modification" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_networkconfig_modification.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/issue" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/audit_rules_networkconfig_modification.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/audit_rules_networkconfig_modification.rules"
    # If the audit_rules_networkconfig_modification.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/issue" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/issue $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/issue$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/issue -p wa -k audit_rules_networkconfig_modification" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/issue.net" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/issue.net $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/issue.net$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_networkconfig_modification.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/issue.net" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/audit_rules_networkconfig_modification.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/audit_rules_networkconfig_modification.rules"
    # If the audit_rules_networkconfig_modification.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/issue.net" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/issue.net $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/issue.net$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/hosts" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/hosts $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/hosts$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/hosts -p wa -k audit_rules_networkconfig_modification" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_networkconfig_modification.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/hosts" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/audit_rules_networkconfig_modification.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/audit_rules_networkconfig_modification.rules"
    # If the audit_rules_networkconfig_modification.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/hosts" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/hosts $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/hosts$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/hosts -p wa -k audit_rules_networkconfig_modification" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/sysconfig/network" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/sysconfig/network $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/sysconfig/network$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_networkconfig_modification.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/sysconfig/network" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/audit_rules_networkconfig_modification.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/audit_rules_networkconfig_modification.rules"
    # If the audit_rules_networkconfig_modification.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/sysconfig/network" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/sysconfig/network $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/sysconfig/network$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Attempts to Alter Process and Session Initiation Information 
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/run/utmp" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/run/utmp $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/run/utmp$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/run/utmp -p wa -k session" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/session.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/var/run/utmp" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/session.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/session.rules"
    # If the session.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/run/utmp" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/run/utmp $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/run/utmp$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/run/utmp -p wa -k session" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/log/btmp" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/log/btmp $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/log/btmp$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/log/btmp -p wa -k session" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/session.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/var/log/btmp" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/session.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/session.rules"
    # If the session.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/log/btmp" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/log/btmp $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/log/btmp$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/log/btmp -p wa -k session" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/log/wtmp" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/log/wtmp $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/log/wtmp$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/log/wtmp -p wa -k session" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/session.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/var/log/wtmp" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/session.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/session.rules"
    # If the session.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/log/wtmp" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/log/wtmp $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/log/wtmp$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/log/wtmp -p wa -k session" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events When Privileged Executables Are Run
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	
	OTHER_FILTERS="-C uid!=euid -F euid=0"
	
	AUID_FILTERS=""
	SYSCALL="execve"
	KEY="setuid"
	SYSCALL_GROUPING=""
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	
	OTHER_FILTERS="-C gid!=egid -F egid=0"
	
	AUID_FILTERS=""
	SYSCALL="execve"
	KEY="setgid"
	SYSCALL_GROUPING=""
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()



# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Ensure auditd Collects System Administrator Actions 
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/sudoers" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/sudoers $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/sudoers$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/sudoers -p wa -k actions" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/actions.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/sudoers" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/actions.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/actions.rules"
    # If the actions.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/sudoers" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/sudoers $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/sudoers$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/sudoers -p wa -k actions" >> "$audit_rules_file"
    fi
done

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/sudoers.d/" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/sudoers.d/ $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/sudoers.d/$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/sudoers.d/ -p wa -k actions" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/actions.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/sudoers.d/" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/actions.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/actions.rules"
    # If the actions.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/sudoers.d/" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/sudoers.d/ $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/sudoers.d/$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/sudoers.d/ -p wa -k actions" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify User/Group Information - /etc/group
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/group" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/group $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/group$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/group -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/group" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/audit_rules_usergroup_modification.rules"
    # If the audit_rules_usergroup_modification.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/group" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/group $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/group$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/group -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify User/Group Information - /etc/gshadow
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/gshadow" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/gshadow $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/gshadow$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/gshadow -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/gshadow" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/audit_rules_usergroup_modification.rules"
    # If the audit_rules_usergroup_modification.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/gshadow" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/gshadow $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/gshadow$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/gshadow -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify User/Group Information - /etc/security/opasswd
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/security/opasswd" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/security/opasswd $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/security/opasswd$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/security/opasswd" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/audit_rules_usergroup_modification.rules"
    # If the audit_rules_usergroup_modification.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/security/opasswd" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/security/opasswd $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/security/opasswd$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify User/Group Information - /etc/passwd
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/passwd" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/passwd $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/passwd$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/passwd -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/passwd" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/audit_rules_usergroup_modification.rules"
    # If the audit_rules_usergroup_modification.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/passwd" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/passwd $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/passwd$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/passwd -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Events that Modify User/Group Information - /etc/shadow
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/shadow" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/shadow $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/shadow$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/shadow -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/shadow" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/audit_rules_usergroup_modification.rules"
    # If the audit_rules_usergroup_modification.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/shadow" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/shadow $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/shadow$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/shadow -p wa -k audit_rules_usergroup_modification" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Record Attempts to perform maintenance activities
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/log/sudo.log" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/log/sudo.log $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/log/sudo.log$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/log/sudo.log -p wa -k logins" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/logins.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/var/log/sudo.log" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/logins.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/logins.rules"
    # If the logins.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/log/sudo.log" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/log/sudo.log $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/log/sudo.log$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/log/sudo.log -p wa -k logins" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# System Audit Logs Must Have Mode 0750 or Less Permissive
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

if LC_ALL=C grep -iw ^log_file /etc/audit/auditd.conf; then
  DIR=$(awk -F "=" '/^log_file/ {print $2}' /etc/audit/auditd.conf | tr -d ' ' | rev | cut -d"/" -f2- | rev)
else
  DIR="/var/log/audit"
fi


if LC_ALL=C grep -m 1 -q ^log_group /etc/audit/auditd.conf; then
  GROUP=$(awk -F "=" '/log_group/ {print $2}' /etc/audit/auditd.conf | tr -d ' ')
  if ! [ "${GROUP}" == 'root' ] ; then
    chmod 0750 $DIR
  else
    chmod 0700 $DIR
  fi
else
  chmod 0700 $DIR
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# System Audit Logs Must Be Group Owned By Root 
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

if LC_ALL=C grep -iw log_file /etc/audit/auditd.conf; then
  FILE=$(awk -F "=" '/^log_file/ {print $2}' /etc/audit/auditd.conf | tr -d ' ')
else
  FILE="/var/log/audit/audit.log"
fi


if LC_ALL=C grep -m 1 -q ^log_group /etc/audit/auditd.conf; then
  GROUP=$(awk -F "=" '/log_group/ {print $2}' /etc/audit/auditd.conf | tr -d ' ')
    if ! [ "${GROUP}" == 'root' ]; then
      chgrp ${GROUP} $FILE*
    else
      chgrp root $FILE*
    fi
else
  chgrp root $FILE*
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Audit Configuration Files Must Be Owned By Group root 
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

find /etc/audit/ -maxdepth 1 -type f ! -gid 0 -regex '^audit(\.rules|d\.conf)$' -exec chgrp 0 {} \;

find /etc/audit/rules.d/ -maxdepth 1 -type f ! -gid 0 -regex '^.*\.rules$' -exec chgrp 0 {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Audit Configuration Files Must Be Owned By Root
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

find /etc/audit/ -maxdepth 1 -type f ! -uid 0 -regex '^audit(\.rules|d\.conf)$' -exec chown 0 {} \;

find /etc/audit/rules.d/ -maxdepth 1 -type f ! -uid 0 -regex '^.*\.rules$' -exec chown 0 {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# System Audit Logs Must Be Owned By Root
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

if LC_ALL=C grep -iw log_file /etc/audit/auditd.conf; then
    FILE=$(awk -F "=" '/^log_file/ {print $2}' /etc/audit/auditd.conf | tr -d ' ')
    chown root $FILE*
else
    chown root /var/log/audit/audit.log*
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# System Audit Logs Must Have Mode 0640 or Less Permissive
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

if LC_ALL=C grep -iw ^log_file /etc/audit/auditd.conf; then
    FILE=$(awk -F "=" '/^log_file/ {print $2}' /etc/audit/auditd.conf | tr -d ' ')
else
    FILE="/var/log/audit/audit.log"
fi


if LC_ALL=C grep -m 1 -q ^log_group /etc/audit/auditd.conf; then
  GROUP=$(awk -F "=" '/log_group/ {print $2}' /etc/audit/auditd.conf | tr -d ' ')
  if ! [ "${GROUP}" == 'root' ] ; then
    chmod 0640 $FILE
    chmod 0440 $FILE.*
  else
    chmod 0600 $FILE
    chmod 0400 $FILE.*
  fi
else
  chmod 0600 $FILE
  chmod 0400 $FILE.*
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Configure auditd Data Retention
# Ensure the audit Subsystem is Installed
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "auditd"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Enable auditd Service
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && { dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; }; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" unmask 'auditd.service'
"$SYSTEMCTL_EXEC" start 'auditd.service'
"$SYSTEMCTL_EXEC" enable 'auditd.service'

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Enable Auditing for Processes Which Start Prior to the Audit Daemon 
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && { dpkg-query --show --showformat='${db:Status-Status}\n' 'grub2-common' 2>/dev/null | grep -q installed; }; then

# Correct the form of default kernel command line in GRUB
if grep -q '^GRUB_CMDLINE_LINUX=.*audit=.*"'  '/etc/default/grub' ; then
       # modify the GRUB command-line if an audit= arg already exists
       sed -i "s/\(^GRUB_CMDLINE_LINUX=\".*\)audit=[^[:space:]]\+\(.*\"\)/\1audit=1\2/"  '/etc/default/grub'
else
       # no audit=arg is present, append it
       sed -i "s/\(^GRUB_CMDLINE_LINUX=\".*\)\"/\1 audit=1\"/"  '/etc/default/grub'
fi
update-grub

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Extend Audit Backlog Limit for the Audit Daemon
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && { dpkg-query --show --showformat='${db:Status-Status}\n' 'grub2-common' 2>/dev/null | grep -q installed; }; then

# Correct the form of default kernel command line in GRUB
if grep -q '^GRUB_CMDLINE_LINUX=.*audit_backlog_limit=.*"'  '/etc/default/grub' ; then
       # modify the GRUB command-line if an audit_backlog_limit= arg already exists
       sed -i "s/\(^GRUB_CMDLINE_LINUX=\".*\)audit_backlog_limit=[^[:space:]]\+\(.*\"\)/\1audit_backlog_limit=8192\2/"  '/etc/default/grub'
else
       # no audit_backlog_limit=arg is present, append it
       sed -i "s/\(^GRUB_CMDLINE_LINUX=\".*\)\"/\1 audit_backlog_limit=8192\"/"  '/etc/default/grub'
fi
update-grub

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
