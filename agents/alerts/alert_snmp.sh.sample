#!/bin/sh
#
# Copyright 2013 Florian CROUZAT <gentoo@floriancrouzat.net>
# Later changes copyright 2013-2023 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
# Description:  Manages a SNMP trap, provided by NTT OSSC as a
#               script under Pacemaker control
#
##############################################################################
# This sample script assumes that only users who already have
# hacluster-equivalent access to the cluster nodes can edit the CIB. Otherwise,
# a malicious user could run commands as hacluster by inserting shell code into
# the trap_options or timestamp-format parameters.
#
# Sample configuration (cib fragment in xml notation)
# ================================
# <configuration>
#   <alerts>
#     <alert id="snmp_alert" path="/path/to/alert_snmp.sh">
#       <instance_attributes id="config_for_alert_snmp">
#         <nvpair id="trap_node_states" name="trap_node_states" value="all"/>
#       </instance_attributes>
#       <meta_attributes id="config_for_timestamp">
#         <nvpair id="ts_fmt" name="timestamp-format" value="%Y-%m-%d,%H:%M:%S.%01N"/>
#       </meta_attributes>
#       <recipient id="snmp_destination" value="192.168.1.2"/>
#     </alert>
#   </alerts>
# </configuration>
# ================================
#
# This uses the official Pacemaker MIB.
# 1.3.6.1.4.1.32723 has been assigned to the project by IANA:
# http://www.iana.org/assignments/enterprise-numbers

# Defaults for user-configurable values
trap_binary_default="/usr/bin/snmptrap"
trap_version_default="2c"
trap_options_default=""
trap_community_default="public"
trap_node_states_default="all"
trap_fencing_tasks_default="all"
trap_resource_tasks_default="all"
trap_monitor_success_default="false"
trap_add_hires_timestamp_oid_default="true"
trap_snmp_persistent_dir_default="/var/lib/pacemaker/snmp"
trap_ignore_int32_default=2147483647  # maximum Integer32 value
trap_ignore_string_default="n/a"      # doesn't conflict with valid XML IDs

# Ensure all user-provided variables have values.
: ${trap_binary=${trap_binary_default}}
: ${trap_version=${trap_version_default}}
: ${trap_options=${trap_options_default}}
: ${trap_community=${trap_community_default}}
: ${trap_node_states=${trap_node_states_default}}
: ${trap_fencing_tasks=${trap_fencing_tasks_default}}
: ${trap_resource_tasks=${trap_resource_tasks_default}}
: ${trap_monitor_success=${trap_monitor_success_default}}
: ${trap_add_hires_timestamp_oid=${trap_add_hires_timestamp_oid_default}}
: ${trap_snmp_persistent_dir=${trap_snmp_persistent_dir_default}}
: ${trap_ignore_int32=${trap_ignore_int32_default}}
: ${trap_ignore_string=${trap_ignore_string_default}}

# Ensure all cluster-provided variables have values, regardless of alert type.
: ${CRM_alert_node=${trap_ignore_string}}
: ${CRM_alert_rsc=${trap_ignore_string}}
: ${CRM_alert_task=${trap_ignore_string}}
: ${CRM_alert_desc=${trap_ignore_string}}
: ${CRM_alert_status=${trap_ignore_int32}}
: ${CRM_alert_rc=${trap_ignore_int32}}
: ${CRM_alert_target_rc=${trap_ignore_int32}}
: ${CRM_alert_attribute_name=${trap_ignore_string}}
: ${CRM_alert_attribute_value=${trap_ignore_string}}
: ${CRM_alert_version:=""}
: ${CRM_alert_recipient:=""}
: ${CRM_alert_kind:=""}

if [ -z "$CRM_alert_version" ]; then
    echo "$0 must be run by Pacemaker version 1.1.15 or later"
    exit 0
fi

# SNMP v3 and above do not use community, which must be empty
case "$trap_version" in
	1|2c) ;;
	*) trap_community="" ;;
esac

if [ -z "$CRM_alert_recipient" ]; then
    echo "$0 requires a recipient configured with the SNMP server IP address"
    exit 0
fi

# Echo a high-resolution equivalent of the Pacemaker-provided time values
# using NetSNMP's DateAndTime specification ("%Y-%m-%d,%H:%M:%S.%01N").
get_system_date() {
    : ${CRM_alert_timestamp_epoch=$(date +%s)}
    : ${CRM_alert_timestamp_usec=0}

    YMDHMS=$(date --date="@${CRM_alert_timestamp_epoch}" +"%Y-%m-%d,%H:%M:%S")
    USEC=$(echo ${CRM_alert_timestamp_usec} | cut -b 1)
    echo "${YMDHMS}.${USEC}"
}

is_in_list() {
    item_list=`echo "$1" | tr ',' ' '`

    if [ "${item_list}" = "all" ]; then
        return 0
    else
        for act in $item_list
        do
            act=`echo "$act" | tr A-Z a-z`
            [ "$act" != "$2" ] && continue
            return 0
        done
    fi
    return 1
}

send_pacemaker_trap() {
    PREFIX="PACEMAKER-MIB::pacemakerNotification"

    OUTPUT=$("${trap_binary}" -v "${trap_version}" ${trap_options} \
        ${trap_community:+-c "${trap_community}"} \
        "${CRM_alert_recipient}" "" \
        "${PREFIX}Trap" \
        "${PREFIX}Node"             s "${CRM_alert_node}" \
        "${PREFIX}Resource"         s "${CRM_alert_rsc}" \
        "${PREFIX}Operation"        s "${CRM_alert_task}" \
        "${PREFIX}Description"      s "${CRM_alert_desc}" \
        "${PREFIX}Status"           i "${CRM_alert_status}" \
        "${PREFIX}ReturnCode"       i "${CRM_alert_rc}" \
        "${PREFIX}TargetReturnCode" i "${CRM_alert_target_rc}" \
        "${PREFIX}AttributeName"    s "${CRM_alert_attribute_name}" \
        "${PREFIX}AttributeValue"   s "${CRM_alert_attribute_value}" \
        ${hires_timestamp} 2>&1)

    if [ $? -ne 0 ]; then
        echo "${trap_binary} returned error : rc=$? $OUTPUT"
    fi
}

if [ "${trap_add_hires_timestamp_oid}" = "true" ]; then
    hires_timestamp="HOST-RESOURCES-MIB::hrSystemDate s $(get_system_date)"
fi

if [ -z ${SNMP_PERSISTENT_DIR} ]; then
    export SNMP_PERSISTENT_DIR="${trap_snmp_persistent_dir}"
    # mkdir for snmp trap tools.
    if [ ! -d ${SNMP_PERSISTENT_DIR} ]; then
        mkdir -p ${SNMP_PERSISTENT_DIR}
    fi
fi

case "$CRM_alert_kind" in
    node)
        if is_in_list "${trap_node_states}" "${CRM_alert_desc}"; then
            send_pacemaker_trap
        fi
        ;;

    fencing)
        if is_in_list "${trap_fencing_tasks}" "${CRM_alert_task}"; then
            send_pacemaker_trap
        fi
        ;;

    resource)
        if is_in_list "${trap_resource_tasks}" "${CRM_alert_task}" && \
           [ "${CRM_alert_desc}" != "Cancelled" ] ; then

            if [ "${trap_monitor_success}" = "false" ] && \
               [ "${CRM_alert_rc}" = "${CRM_alert_target_rc}" ] && \
               [ "${CRM_alert_task}" = "monitor" ]; then
                exit 0
            fi
            send_pacemaker_trap
        fi
        ;;

    attribute)
        send_pacemaker_trap
        ;;

    *)
        ;;
esac
