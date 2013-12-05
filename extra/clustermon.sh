#!/bin/bash
#
# Cluster Monitoring Script, for use with crm_mon and Pacemaker,
# to emulate the oft-missing --snmp-traps and --mail options.
#
# Copyright 2013 Rob Thomas <xrobau@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# Uncomment these lines to run a test of the script.
#CRM_notify_desc=OK
#CRM_notify_node=freepbx-a
#CRM_notify_rc=0
#CRM_notify_recipient=emailalert@hipbx.org
#CRM_notify_rsc=spare_fs
#CRM_notify_status=0
#CRM_notify_target_rc=0
#CRM_notify_task=start

# Set some defaults
FROMADDR=cluster@`hostname`

# Check to see if we should do anything with this alert.
# You could put some smarts in this, a database lookup, etc
# This is just a simple setup that tries to guess what you
# want to do based on the notify_recipient option to crm_mon

# Basic examples:
# pcs resource create ClusterMon-Email --clone ClusterMon user=root extra_options="-E /usr/local/bin/clustermon-new.sh -e emailalert@hipbx.org"
# pcs resource create ClusterMon-SNMP --clone ClusterMon user=root extra_options="-E /usr/local/bin/clustermon-new.sh -e 192.168.254.254"

function getDest {
	# This looks for an '@' in the notify_recipient. If it finds it, it'll send an email.
	# Otherwise, it'll send a SNMP trap.
	if [ ! -z "${CRM_notify_recipient}" ]
	then
		if [[ "${CRM_notify_recipient}" == *@* ]]
		then
			SMTPDEST=${CRM_notify_recipient}
			DEST='smtp'
		else
			SNMPDEST=${CRM_notify_recipient}
			DEST='snmp'
		fi
	else
		# Hard coded defaults. Please change these.
		SMTPDEST='ididntchangethedefaults@hipbx.org'
		SNMPDEST='192.168.254.254'
		SNMPCOMMUNITY='public'
		# If 'DEST' is blank, nothing happens.
		DEST='both'
	fi
}

# Other Predefined functions

function sendsmtp {
	# Re-implemtation of code in crm_mon.c
	[ -z "${SMTPDEST}" ] && return

	[ -z "${CRM_notify_node}" ] && CRM_notify_node="-"
	node=${CRM_notify_node}
	[ -z "${CRM_notify_rsc}" ] && CRM_notify_rsc="-"
	rsc=${CRM_notify_rsc}
	[ -z "${CRM_notify_desc}" ] && CRM_notify_desc="-"
	desc=${CRM_notify_desc}

	crm_mail_prefix="Cluster notification"

	subject="${crm_mail_prefix} - ${CRM_notify_task} event for ${rsc} on ${node}"
	body="\n${crm_mail_pref}\n====\n\n"
	if [ ${CRM_notify_target_rc} -eq ${CRM_notify_rc} ]
	then
		body="${body}Completed operation ${CRM_notify_task} for resource ${rsc} on ${node}\n"
	else
		body="${body}Operation ${CRM_notify_task} for resource ${rsc} on ${node} failed: ${desc}\n"
	fi
	statusstr=$(ocf_status ${CRM_notify_status})
	body="${body}\nDetails:\n\toperation status: (${CRM_notify_status}) ${statusstr}\n"
	if [ "${CRM_notify_status}" -eq 0 ]
	then
		result=$(ocf_exitcode ${CRM_notify_rc})
		target=$(ocf_exitcode ${CRM_notify_target_rc})
		body="${body}\tscript returned: (${CRM_notify_rc}) ${result}\n"
		body="${body}\texpected return value: (${CRM_notify_target_rc}) ${target}\n"
	fi

	echo -e $body | mail -r "$FROMADDR" -s "$subject" "$SMTPDEST"
}

function ocf_status {
	case $1 in
		-1) echo "pending" ;;
		 0) echo "complete" ;;
		 1) echo "Cancelled" ;;
		 2) echo "Timed Out" ;;
		 3) echo "NOT SUPPORTED" ;;
		 4) echo "Error" ;;
		 5) echo "Not installed" ;;
		 *) echo "Exceptionally unusual" ;;
	 esac
}

function ocf_exitcode {
	case $1 in
		0) echo "OK" ;;
		1) echo "Unknown Error" ;;
		2) echo "Invalid Parameter" ;;
		3) echo "Unimplemented Feature" ;;
		4) echo "Insufficient Privileges" ;;
		5) echo "not installed" ;;
		6) echo "not configured" ;;
		7) echo "not running" ;;
		8) echo "master" ;;
		9) echo "master (failed)" ;;
		192) echo "OCF_EXEC_ERROR" ;;
		193) echo "OCF_UNKNOWN" ;;
		194) echo "OCF_SIGNAL" ;;
		195) echo "OCF_NOT_SUPPORTED" ;;
		196) echo "OCF_PENDING" ;;
		197) echo "OCF_CANCELLED" ;;
		198) echo "OCF_TIMEOUT" ;;
		199) echo "OCF_OTHER_ERROR" ;;
		*) echo "Exceptionally unknown error" ;;
	esac
}


function sendsnmp() {
  [ -f /usr/bin/snmptrap ] && /usr/bin/snmptrap -v 2c -c "$SNMPCOMMUNITY" "$SNMPDEST" "" PACEMAKER-MIB::pacemakerNotification \
        PACEMAKER-MIB::pacemakerNotificationNode s "${node}" \
        PACEMAKER-MIB::pacemakerNotificationResource s "${rsc}" \
        PACEMAKER-MIB::pacemakerNotificationOperation s "${CRM_notify_task}" \
        PACEMAKER-MIB::pacemakerNotificationDescription s "${desc}" \
        PACEMAKER-MIB::pacemakerNotificationStatus i "${CRM_notify_status}" \
        PACEMAKER-MIB::pacemakerNotificationReturnCode i ${CRM_notify_rc} \
        PACEMAKER-MIB::pacemakerNotificationTargetReturnCode i ${CRM_notify_target_rc}
}

# Lets see who wants to do what with this.
getDest

# Do we want to do anything with this alert?
if [ -z "$DEST" ]
then
	exit 0;
fi

if [ "$DEST" == "both" -o "$DEST" == "smtp" ]
then
	sendsmtp;
fi

if [ "$DEST" == "both" -o "$DEST" == "snmp" ]
then
	sendsnmp;
fi
