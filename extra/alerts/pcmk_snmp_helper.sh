#!/bin/sh
#
# Description:  Manages a SNMP trap, provided by NTT OSSC as an
#               script under Heartbeat/LinuxHA control
#
# Copyright (c) 2016 NIPPON TELEGRAPH AND TELEPHONE CORPORATION
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
#
##############################################################################
# This sample script assumes that only users who already have root access can edit the CIB.
# Otherwise, a malicious user could run commands as root by inserting shell code into the
# the trap_options variable. If that is not the case in your environment, you should edit this
# script to remove or validate trap_options.
#
# Sample configuration (cib fragment in xml notation)
# ================================
# <configuration>
#   <alerts>
#     <alert id="snmp_alert" path="/path/to/pcmk_snmp_helper.sh">
#       <instance_attributes id="insta_9">
#         <nvpair id="trap_nodes" name="trap_node" value="no"/>
#         <nvpair id="trap_fencing" name="trap_fencing" value="no"/>
#       </instance_attributes>
#       <recipient id="snmp_destination" value="192.168.1.2"/>
#     </alert>
#   </alerts>
# </configuration>
# ================================
# ================================
# <configuration>
#   <alerts>
#     <alert id="snmp_alert" path="/path/to/pcmk_snmp_helper.sh">
#       <recipient id="snmp_destination" value="192.168.1.2">
#        <instance_attributes id="insta_9">
#         <nvpair id="trap_nodes" name="trap_node" value="no"/>
#         <nvpair id="trap_fencing" name="trap_fencing" value="no"/>
#        </instance_attributes>
#       </recipient>
#     </alert>
#   </alerts>
# </configuration>
# ================================

if [ -z $CRM_alert_version ]; then
    echo "Pacemaker version 1.1.15 or later is required"
    exit 0
fi

#
trap_binary_default="/usr/bin/snmptrap"
trap_version_default="2c"
trap_options_default=""
trap_community_default="public"
trap_node_default="true"
trap_fencing_default="true"
trap_resource_default="true"
trap_only_monitor_failed_default="true"

: ${trap_binary=${trap_binary_default}}
: ${trap_version=${trap_version_default}}
: ${trap_options=${trap_options_default}}
: ${trap_community=${trap_community_default}}
: ${trap_node=${trap_node_default}}
: ${trap_fencing=${trap_fencing_default}}
: ${trap_resource=${trap_resource_default}}
: ${trap_only_monitor_failed=${trap_only_monitor_failed_default}}

#
case $CRM_alert_kind in
    node)
        if [ ${trap_node} = "true" ]; then
    	    ${trap_binary} -v ${trap_version} ${trap_options} -c ${trap_community} ${CRM_alert_recipient} "" PACEMAKER-MIB::pacemakerNotificationTrap \
		PACEMAKER-MIB::pacemakerNotificationNode s "${CRM_alert_node}" \
		PACEMAKER-MIB::pacemakerNotificationDescription s "${CRM_alert_desc}"
        fi
	;;
    fencing)
        if [ ${trap_fencing} = "true" ]; then
    	    ${trap_binary} -v ${trap_version} ${trap_options} -c ${trap_community} ${CRM_alert_recipient} "" PACEMAKER-MIB::pacemakerNotificationTrap \
		PACEMAKER-MIB::pacemakerNotificationNode s "${CRM_alert_node}" \
		PACEMAKER-MIB::pacemakerNotificationOperation s "${CRM_alert_task}" \
		PACEMAKER-MIB::pacemakerNotificationDescription s "${CRM_alert_desc}" \
		PACEMAKER-MIB::pacemakerNotificationReturnCode i ${CRM_alert_rc}
        fi
	;;
    resource)
        if [ ${trap_resource} = "true" ]; then
	    case ${CRM_alert_desc} in
	        Cancelled) ;;
	        *)
                    if [ ${trap_only_monitor_failed} = "true" ]; then
                        if [[ ${CRM_alert_rc} == 0 && ${CRM_alert_task} == "monitor" ]]; then
                            exit;
                        fi
                    fi

    		    ${trap_binary} -v ${trap_version} ${trap_options} -c ${trap_community} ${CRM_alert_recipient} "" PACEMAKER-MIB::pacemakerNotificationTrap \
			PACEMAKER-MIB::pacemakerNotificationNode s "${CRM_alert_node}" \
			PACEMAKER-MIB::pacemakerNotificationResource s "${CRM_alert_rsc}" \
			PACEMAKER-MIB::pacemakerNotificationOperation s "${CRM_alert_task}" \
			PACEMAKER-MIB::pacemakerNotificationDescription s "${CRM_alert_desc}" \
			PACEMAKER-MIB::pacemakerNotificationStatus i ${CRM_alert_status} \
			PACEMAKER-MIB::pacemakerNotificationReturnCode i ${CRM_alert_rc} PACEMAKER-MIB::pacemakerNotificationTargetReturnCode i ${CRM_alert_target_rc}
		    ;;
	    esac
        fi
	;;
    *)
        ;;

esac
