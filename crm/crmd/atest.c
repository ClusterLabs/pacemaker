/* $Id: atest.c,v 1.2 2005/02/07 11:18:13 andrew Exp $ */
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
#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <apphb.h>

#include <clplumbing/ipc.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/uids.h>
#include <clplumbing/realtime.h>
#include <clplumbing/GSource.h>
#include <clplumbing/cl_poll.h>
#include <clplumbing/coredumps.h>

#include <crm/crm.h>
#include <crm/common/ctrl.h>
#include <crm/common/ipc.h>
#include <crm/common/xml.h>

#include <crmd.h>
#include <crmd_fsa.h>
#include <crmd_messages.h>
#include <crm/cib.h>

#include <crm/dmalloc_wrapper.h>

const char* crm_system_name = "core";

gboolean process_atest_message(
	HA_Message *msg, crm_data_t *xml_data, IPC_Channel *sender);


GMainLoop*  mainloop = NULL;

int
main(int argc, char ** argv)
{
	IPC_Channel* channels[2];
	crm_data_t *a_cib = NULL;
	HA_Message *cmd = NULL;
	
	crm_log_init(crm_system_name);
	set_crm_log_level(LOG_INSANE-1);
	
	a_cib = createEmptyCib();
	cl_log_message(LOG_DEBUG, (HA_Message*)a_cib);

	if (ipc_channel_pair(channels) != IPC_OK) {
		cl_perror("Can't create ipc channel pair");
		exit(1);
	}
	G_main_add_IPC_Channel(G_PRIORITY_LOW,
			       channels[1], FALSE,
			       subsystem_msg_dispatch,
			       (void*)process_atest_message, 
			       default_ipc_connection_destroy);

	/* send transition graph over IPC instead */
	cmd = create_request(CRM_OP_TRANSITION, a_cib, NULL,
			     CRM_SYSTEM_TENGINE, CRM_SYSTEM_TENGINE, NULL);
	
	send_ipc_message(channels[0], cmd);

	mainloop = g_main_new(FALSE);
	crm_debug("Starting mainloop");
	g_main_run(mainloop);
	
#if 0
    /* read local config file */
    crm_debug("Enabling coredumps");
    if(cl_set_corerootdir(HA_COREDIR) < 0){
	    cl_perror("cannot set corerootdir");
    }
    if(cl_enable_coredumps(1) != 0) {
	    crm_err("Cannot enable coredumps");
    }
    if(cl_cdtocoredir() != 0) {
	    crm_err("Cannot cd to coredump dir");
    }

    crm_warn("Calling abort()");
    abort();
    crm_err("We just dumped core");
#endif
    return 0;
}

gboolean
process_atest_message(HA_Message *msg, crm_data_t *xml_data, IPC_Channel *sender)
{
	crm_debug("made it");
	cl_log_message(LOG_DEBUG, msg);
	return TRUE;
}
