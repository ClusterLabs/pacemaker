/* $Id: atest.c,v 1.1 2005/02/02 21:52:20 andrew Exp $ */
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

int
main(int argc, char ** argv)
{
    /* Redirect messages from glib functions to our handler */
    g_log_set_handler(NULL,
		      G_LOG_LEVEL_ERROR      | G_LOG_LEVEL_CRITICAL
		      | G_LOG_LEVEL_WARNING  | G_LOG_LEVEL_MESSAGE
		      | G_LOG_LEVEL_INFO     | G_LOG_LEVEL_DEBUG
		      | G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL,
		      cl_glib_msg_handler, NULL);

    /* and for good measure... */
    g_log_set_always_fatal((GLogLevelFlags)0);    
    cl_log_set_entity(crm_system_name);
    cl_log_set_facility(LOG_LOCAL7);
    cl_log_send_to_logging_daemon(TRUE);
    CL_SIGNAL(DEBUG_INC, alter_debug);
    CL_SIGNAL(DEBUG_DEC, alter_debug);

    set_crm_log_level(LOG_DEV);

    crm_debug("some log");
    cl_log(LOG_DEBUG, "same log");
    crm_debug("some log");
    cl_log(LOG_DEBUG, "same log");
    
#if 0
    /* read local config file */
    crm_debug("Enabling coredumps");
    if(cl_set_corerootdir(DEVEL_DIR) < 0){
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
