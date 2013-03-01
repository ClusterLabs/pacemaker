#!/bin/bash

#
# Copyright (C) 2013 Florian CROUZAT <gentoo@floriancrouzat.net>
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

# Resources:
#  crm ra meta ocf:pacemaker:ClusterMon
#  man 8 crm_mon

# Sample configuration
# ================================
# primitive ClusterMon ocf:pacemaker:ClusterMon \
#        params user="root" update="30" extra_options="-E /path/to/pcmk_snmp_helper.sh -e 192.168.1.2" \
#        op monitor on-fail="restart" interval="10"
#
# clone ClusterMon-clone ClusterMon \
#        meta target-role="Started"
# ================================

# The external agent is fed with environment variables allowing us to know
# what transition happened and to react accordingly:
#  http://clusterlabs.org/doc/en-US/Pacemaker/1.1-crmsh/html/Pacemaker_Explained/s-notification-external.html

# Generates SNMP alerts for any failing monitor operation
#  OR
# for any operations (even successful) that are not a monitor
if [[ ${CRM_notify_rc} != 0 && ${CRM_notify_task} == "monitor" ]] || [[ ${CRM_notify_task} != "monitor" ]] ; then
    # This trap is compliant with PACEMAKER MIB
    #  https://github.com/ClusterLabs/pacemaker/blob/master/extra/PCMK-MIB.txt
    /usr/bin/snmptrap -v 2c -c public ${CRM_notify_recipient} "" PACEMAKER-MIB::pacemakerNotification \
	PACEMAKER-MIB::pacemakerNotificationNode s "${CRM_notify_node}" \
	PACEMAKER-MIB::pacemakerNotificationResource s "${CRM_notify_rsc}" \
	PACEMAKER-MIB::pacemakerNotificationOperation s "${CRM_notify_task}" \
	PACEMAKER-MIB::pacemakerNotificationDescription s "${CRM_notify_desc}" \
	PACEMAKER-MIB::pacemakerNotificationStatus i "${CRM_notify_status}" \
	PACEMAKER-MIB::pacemakerNotificationReturnCode i ${CRM_notify_rc} \
	PACEMAKER-MIB::pacemakerNotificationTargetReturnCode i ${CRM_notify_target_rc} && exit 0 || exit 1
fi

exit 0
