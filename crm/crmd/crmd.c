/* $Id: crmd.c,v 1.15 2004/03/05 14:01:17 andrew Exp $ */
/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <crm/common/crm.h>

#include <portability.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <hb_api.h>
#include <apphb.h>

#include <clplumbing/ipc.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/GSource.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/uids.h>
#include <clplumbing/realtime.h>
#include <clplumbing/GSource.h>
#include <clplumbing/cl_poll.h>

#include <ocf/oc_event.h>
#include <crm/common/xmlvalues.h>
#include <crm/common/msgutils.h>
#include <crm/common/xmlutils.h>

#include <crmd_fsa.h>



ll_cluster_t *hb_cluster = NULL;
GHashTable   *ipc_clients = NULL;

#include <crm/common/crmutils.h>
#include <crm/common/ipcutils.h>
#include <crm/common/msgutils.h>
#include <crm/common/xmltags.h>
#include <crm/common/xmlutils.h>
#include <glib.h>
#include <crmd.h>

#include <crm/dmalloc_wrapper.h>



