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
#include <crm.h>

#include <portability.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

//#include <hb_api.h>
#include <apphb.h>

#include <clplumbing/cl_log.h>

#include <time.h> // for getNow()

#include <crmutils.h>

extern void*         ha_malloc(size_t size);
extern void          ha_free(void *ptr);

char *
getNow(void)
{
    char *since_epoch = (char*)ha_malloc(128*(sizeof(char)));
    sprintf(since_epoch, "%ld", (unsigned long)time(NULL));
    return since_epoch;
}

gboolean
tickle_apphb(gpointer data)
{
    char	app_instance[APPNAME_LEN];
    int     rc = 0;
    sprintf(app_instance, "%s_%ld", daemon_name, (long)getpid());

    rc = apphb_hb();
    if (rc < 0) {
	cl_perror("%s apphb_hb failure", app_instance);
	exit(3);
    }
    return TRUE;
  
}

