/*
 * Copyright (C) 2012-2017 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */
#ifndef CRM_COMPATIBILITY__H
#  define CRM_COMPATIBILITY__H

/* Heartbeat-specific definitions. Support for heartbeat has been removed
 * entirely, so any code branches relying on these should be deleted.
 */
#define ACTIVESTATUS "active"
#define DEADSTATUS "dead"
#define PINGSTATUS "ping"
#define JOINSTATUS "join"
#define LEAVESTATUS "leave"
#define NORMALNODE "normal"
#define CRM_NODE_EVICTED "evicted"
#define CRM_LEGACY_CONFIG_DIR "/var/lib/heartbeat/crm"
#define HA_VARLIBHBDIR "/var/lib/heartbeat"

#endif
