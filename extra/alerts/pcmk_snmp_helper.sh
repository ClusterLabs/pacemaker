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
#  Pacemaker Explained - to come
#  man 8 pcs - to come
#  pcs alert help - to come
#  https://github.com/ClusterLabs/pacemaker/pull/950 - to go away

# Sample configuration (cib fragment in xml notation)
# ================================
# <configuration>
#   <alerts>
#     <alert id="snmp_alert" path="/path/to/pcmk_snmp_helper.sh">
#       <recipient id="snmp_destination" value="192.168.1.2"/>
#     </alert>
#   </alerts>
# </configuration>
# ================================

# The external agent is fed with environment variables allowing us to know
# what transition happened and to react accordingly.

# Generates SNMP alerts for any failing monitor operation
#  OR
# for any operations (even successful) that are not a monitor
if [[ ${CRM_alert_rc} != 0 && ${CRM_alert_task} == "monitor" ]] || [[ ${CRM_alert_task} != "monitor" ]] ; then
    # This trap is compliant with PACEMAKER MIB
    #  https://github.com/ClusterLabs/pacemaker/blob/master/extra/PCMK-MIB.txt
    /usr/bin/snmptrap -v 2c -c public ${CRM_alert_recipient} "" PACEMAKER-MIB::pacemakerNotificationTrap \
	PACEMAKER-MIB::pacemakerNotificationNode s "${CRM_alert_node}" \
	PACEMAKER-MIB::pacemakerNotificationResource s "${CRM_alert_rsc}" \
	PACEMAKER-MIB::pacemakerNotificationOperation s "${CRM_alert_task}" \
	PACEMAKER-MIB::pacemakerNotificationDescription s "${CRM_alert_desc}" \
	PACEMAKER-MIB::pacemakerNotificationStatus i "${CRM_alert_status}" \
	PACEMAKER-MIB::pacemakerNotificationReturnCode i ${CRM_alert_rc} \
	PACEMAKER-MIB::pacemakerNotificationTargetReturnCode i ${CRM_alert_target_rc} && exit 0 || exit 1
fi

exit 0
