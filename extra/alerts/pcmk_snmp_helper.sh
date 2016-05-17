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
#
# Sample configuration (cib fragment in xml notation)
# ================================
# <configuration>
#   <alerts>
#     <instance_attributes id="insta_9">
#       <nvpair id="trap_nodes" name="trap_node" value="no"/>
#       <nvpair id="trap_fencing" name="trap_fencing" value="no"/>
#     </instance_attributes>
#     <alert id="snmp_alert" path="/path/to/pcmk_snmp_notify.sh">
#       <recipient id="snmp_destination" value="192.168.1.2"/>
#     </alert>
#   </alerts>
# </configuration>
# ================================

if [ -z $CRM_alert_version ]; then
    echo "Pacemaker version 1.1.15 is required"
    exit 0
fi

#
trap_binary_default="/usr/bin/snmptrap"
trap_community_default="public"
trap_node_default="yes"
trap_fencing_default="yes"
trap_resource_default="yes"

: ${trap_binary=${trap_binary_default}}
: ${trap_community=${trap_community_default}}
: ${trap_node=${trap_node_default}}
: ${trap_fencing=${trap_fencing_default}}
: ${trap_resource=${trap_resource_default}}

#
case $CRM_alert_kind in
    node)
        if [ ${trap_node} = "yes" ]; then
    	    ${trap_binary} -v 2c -c ${trap_community} ${CRM_alert_recipient} "" PACEMAKER-MIB::pacemakerNotificationTrap \
		PACEMAKER-MIB::pacemakerNotificationNode s "${CRM_alert_node}" \
		PACEMAKER-MIB::pacemakerNotificationDescription s "${CRM_alert_desc}"
        fi
	;;
    fencing)
        if [ ${trap_fencing} = "yes" ]; then
    	    ${trap_binary} -v 2c -c ${trap_community} ${CRM_alert_recipient} "" PACEMAKER-MIB::pacemakerNotificationTrap \
		PACEMAKER-MIB::pacemakerNotificationNode s "${CRM_alert_node}" \
		PACEMAKER-MIB::pacemakerNotificationOperation s "${CRM_alert_task}" \
		PACEMAKER-MIB::pacemakerNotificationDescription s "${CRM_alert_desc}" \
		PACEMAKER-MIB::pacemakerNotificationReturnCode i ${CRM_alert_rc}
        fi
	;;
    resource)
        if [ ${trap_resource} = "yes" ]; then
	    case ${CRM_alert_desc} in
	        Cancelled) ;;
	        *)
    		    ${trap_binary} -v 2c -c ${trap_community} ${CRM_alert_recipient} "" PACEMAKER-MIB::pacemakerNotificationTrap \
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
