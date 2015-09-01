#!/bin/bash
#
# Copyright (C) 2015 Andrew Beekhof <andrew@beekhof.net>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

if [ -z $CRM_notify_version ]; then
    echo "Pacemaker version 1.1.14 is required" >> ${CRM_notify_recipient}
    exit 0
fi

case $CRM_notify_kind in
    node)
	echo "Node '${CRM_notify_node}' is now '${CRM_notify_desc}'" >> ${CRM_notify_recipient}
	;;
    fencing)
	# Other keys:
	# 
	# CRM_notify_node
	# CRM_notify_task
	# CRM_notify_rc
	#
	echo "Fencing ${CRM_notify_desc}" >> ${CRM_notify_recipient}
	;;
    resource)
	# Other keys:
	# 
	# CRM_notify_target_rc
	# CRM_notify_status
	# CRM_notify_rc
	#
	if [ ${CRM_notify_interval} = "0" ]; then
	    CRM_notify_interval=""
	else
	    CRM_notify_interval=" (${CRM_notify_interval})"
	fi

	if [ ${CRM_notify_target_rc} = "0" ]; then
	    CRM_notify_target_rc=""
	else
	    CRM_notify_target_rc=" (target: ${CRM_notify_target_rc})"
	fi
	
	case ${CRM_notify_desc} in
	    Cancelled) ;;
	    *)
		echo "Resource operation '${CRM_notify_task}${CRM_notify_interval}' for '${CRM_notify_rsc}' on '${CRM_notify_node}': ${CRM_notify_desc}${CRM_notify_target_rc}" >> ${CRM_notify_recipient}
		;;
	esac
	;;
    *)
        echo "Unhandled $CRM_notify_kind notification" >> ${CRM_notify_recipient}
	env | grep CRM_notify >> ${CRM_notify_recipient}
        ;;

esac
