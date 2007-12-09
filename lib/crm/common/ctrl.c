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

#include <hb_config.h>

#include <sys/param.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/ctrl.h>

#include <apphb.h>

#include <clplumbing/cl_log.h>
#include <clplumbing/Gmain_timeout.h>


#if 0

static int  wdt_interval_ms = 10000;

void
register_with_apphb(const char *client_name,
		    gboolean(*tickle_fn)(gpointer data))
{
	char	app_instance[APPNAME_LEN];
	int     hb_intvl_ms = wdt_interval_ms * 2;
	int     rc = 0;

	/* Register with apphb */
	crm_info("Signing in with AppHb");
	sprintf(app_instance, "%s_%ld", client_name, (long)getpid());
  
	crm_info("Client %s registering with apphb", app_instance);

	rc = apphb_register(client_name, app_instance);
    
	if (rc < 0) {
		cl_perror("%s registration failure", app_instance);
		exit(1);
	}
  
	crm_debug_3("Client %s registered with apphb", app_instance);
  
	crm_info("Client %s setting %d ms apphb heartbeat interval",
		 app_instance, hb_intvl_ms);
	rc = apphb_setinterval(hb_intvl_ms);
	if (rc < 0) {
		cl_perror("%s setinterval failure", app_instance);
		exit(2);
	}
  
	/* regularly tell apphb that we are alive */
	crm_info("Setting up AppHb Heartbeat");
	Gmain_timeout_add(wdt_interval_ms, tickle_fn, NULL);
}


gboolean
tickle_apphb_template(gpointer data)
{
	char	app_instance[APPNAME_LEN];
	int     rc = 0;
	sprintf(app_instance, "%s_%ld", "our_system_name", (long)getpid());

	rc = apphb_hb();
	if (rc < 0) {
		cl_perror("%s apphb_hb failure", app_instance);

		exit(3);
	}
	return TRUE;
}

#endif
