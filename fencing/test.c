/* 
 * Copyright (C) 2009 Andrew Beekhof <andrew@beekhof.net>
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

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/utsname.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/cluster.h>

#include <crm/stonith-ng.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

static struct crm_option long_options[] = {
    {"verbose",     0, 0, 'V'},
    {"version",     0, 0, '$'},
    {"help",        0, 0, '?'},
    
    {0, 0, 0, 0}
};

int
main(int argc, char ** argv)
{
    int flag;
    int rc = 0;
    int argerr = 0;
    int option_index = 0;
    stonith_t *st = NULL;
    GHashTable *hash = g_hash_table_new(g_str_hash, g_str_equal);
    
    crm_log_init("stonith-test", LOG_INFO, TRUE, TRUE, argc, argv);
    crm_set_options("V?$", "mode [options]", long_options,
		    "Provides a summary of cluster's current state."
		    "\n\nOutputs varying levels of detail in a number of different formats.\n");

    while (1) {
	flag = crm_get_option(argc, argv, &option_index);
	if (flag == -1)
	    break;
		
	switch(flag) {
	    case 'V':
		alter_debug(DEBUG_INC);
		cl_log_enable_stderr(1);
		break;
	    case '$':
	    case '?':
		crm_help(flag, LSB_EXIT_OK);
		break;
	    default:
		++argerr;
		break;
	}
    }

    if (optind > argc) {
	++argerr;
    }
    
    if (argerr) {
	crm_help('?', LSB_EXIT_GENERIC);
    }

    crm_debug("Create");
    st = stonith_api_new();
    crm_debug("Connect");
    st->cmds->connect(st, crm_system_name, NULL, NULL);

    crm_debug("Register");
    g_hash_table_insert(hash, crm_strdup("ipaddr"), crm_strdup("localhost"));
    g_hash_table_insert(hash, crm_strdup("portmap"), crm_strdup("pcmk-1=1 pcmk-2=2 pcmk-3=3,4"));
    g_hash_table_insert(hash, crm_strdup("login"), crm_strdup("user"));
    g_hash_table_insert(hash, crm_strdup("passwd"), crm_strdup("pass"));
    st->cmds->register_device(st, 0, "test-id", "stonith-ng", "fence_virsh", hash);
    
    crm_debug("Test");
    st->cmds->call(st, 0, "test-id", "status", 10);

    crm_debug("Invoke");
    st->cmds->fence(st, 0, "some-host", 10);

    crm_debug("Remove");
    st->cmds->remove_device(st, 0, "test-id");
    
    sleep(5);
    crm_debug("Disconnect");
    st->cmds->disconnect(st);
    crm_debug("Destroy");
    stonith_api_delete(st);
    
    return rc;
}
