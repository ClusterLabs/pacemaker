/* 
 * Copyright (C) 2009 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
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
#include <crm/cib.h>
#include <crm/pengine/status.h>

#include <crm/common/xml.h>
#include <crm/common/msg.h>

static struct crm_option long_options[] = {
    {"help",        0, 0, '?', "\tThis text"},
    {"version",     0, 0, '$', "\tVersion information"  },
    {"verbose",     0, 0, 'V', "\tIncrease debug output"},

    {"list",        1, 0, 'l', "List devices that can terminate the specified host"},
    {"list-all",    0, 0, 'L', "List all registered devices"},

    {"metadata",    0, 0, 'M', "Check the device's metadata"},
    {"query",       1, 0, 'Q', "Check the device's status"},
    {"fence",       1, 0, 'F', "Fence the named host"},
    {"unfence",     1, 0, 'U', "Unfence the named host"},
    {"confirm",     1, 0, 'C', "Confirm the named host is now safely down"},

    {"register",    1, 0, 'R', "Register a stonith device"},
    {"deregister",  1, 0, 'D', "De-register a stonith device"},

    {"env-option",  1, 0, 'e'},
    {"option",      1, 0, 'o'},
    {"agent",       1, 0, 'a'},
    
    {0, 0, 0, 0}
};

int st_opts = st_opt_sync_call;

static void st_callback(stonith_t *st, const char *event, xmlNode *msg)
{
    crm_log_xml_notice(msg, event);
}

static void
hash_copy(gpointer key, gpointer value, gpointer user_data) 
{
    const char *name    = key;
    const char *s_value = value;
    GHashTable *hash    = user_data;

    if(g_hash_table_lookup(hash, name) == NULL) {
	crm_trace("Copying in %s=%s", name, s_value);
	g_hash_table_insert(hash, strdup(name), strdup(value));
    }
}

extern void cleanup_calculations(pe_working_set_t *data_set);
extern gboolean unpack_nodes(xmlNode * xml_nodes, pe_working_set_t *data_set);

static void st_get_node_attributes(const char *target, GHashTable *attrs) 
{
    int rc = 0;
    node_t *node = NULL;
    cib_t *global_cib = NULL;
    pe_working_set_t data_set;

    set_working_set_defaults(&data_set);

    global_cib = cib_new();
    global_cib->cmds->signon(global_cib, crm_system_name, cib_command);

    rc = global_cib->cmds->query(global_cib, NULL, &(data_set.input), cib_sync_call|cib_scope_local);
    if(rc == cib_ok) {
	crm_trace("Looking up current node attributes for %s", target);
	unpack_nodes(get_object_root(XML_CIB_TAG_NODES, data_set.input), &data_set);
    }

    /* Assume uname and fall back to uuid if there is no match */
    node = pe_find_node(data_set.nodes, target);
    if(node) {
	node = pe_find_node_id(data_set.nodes, target);
    }
    
    if(node) {
	/* Copy in any parameters not explicitly set from the command line */
	g_hash_table_foreach(node->details->attrs, hash_copy, attrs);	
    }
    
    cleanup_calculations(&data_set);
    global_cib->cmds->signoff(global_cib);
    cib_delete(global_cib);
}

int
main(int argc, char ** argv)
{
    int flag;
    int rc = 0;
    int argerr = 0;
    int option_index = 0;

    char name[512];
    char value[512];
    const char *agent = NULL;
    const char *device = NULL;
    const char *target = NULL;
    
    char action = 0;
    stonith_t *st = NULL;
    GHashTable *hash = g_hash_table_new(g_str_hash, g_str_equal);
    
    crm_log_init(NULL, LOG_INFO, TRUE, TRUE, argc, argv);
    crm_set_options("V?$LQ:R:D:o:a:l:e:F:U:M", "mode [options]", long_options,
		    "Provides access to the stonith-ng API.\n");

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
	    case 'L':
		action = flag;
		break;
	    case 'Q':
	    case 'R':
	    case 'D':
		action = flag;
		device = optarg;
		break;
	    case 'a':
		agent = optarg;
		break;
	    case 'l':
		target = optarg;
		action = 'L';
		break;
	    case 'M':
		action = flag;
		break;
	    case 'F':
	    case 'U':
	    case 'C':
		target = optarg;
		action = flag;
		break;
	    case 'o':
		crm_info("Scanning: -o %s", optarg);
		rc = sscanf(optarg, "%[^=]=%[^=]", name, value);
		if(rc != 2) {
		    crm_err("Invalid option: -o %s", optarg);
		    ++argerr;
		} else {
		    crm_info("Got: '%s'='%s'", name, value);
		    g_hash_table_insert(hash, crm_strdup(name), crm_strdup(value));
		}
		break;
	    case 'e':
		{
		    char *key = crm_concat("OCF_RESKEY", optarg, '_');
		    const char *env = getenv(key);
		    
		    if(env == NULL) {
			crm_err("Invalid option: -e %s", optarg);
			++argerr;
		    } else {
			crm_info("Got: '%s'='%s'", optarg, env);
			g_hash_table_insert(hash, crm_strdup(optarg), crm_strdup(env));
		    }
		}
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

#if 0
    g_hash_table_insert(hash, crm_strdup("ipaddr"), crm_strdup("localhost"));
    g_hash_table_insert(hash, crm_strdup("pcmk-portmap"), crm_strdup("some-host=pcmk-1 pcmk-3=3,4"));
    g_hash_table_insert(hash, crm_strdup("login"), crm_strdup("root"));
    g_hash_table_insert(hash, crm_strdup("identity_file"), crm_strdup("/root/.ssh/id_dsa"));
#endif

    crm_debug("Create");
    st = stonith_api_new();

    if(action != 'M') {
	rc = st->cmds->connect(st, crm_system_name, NULL, NULL);
	crm_debug("Connect: %d", rc);
	
	rc = st->cmds->register_notification(st, T_STONITH_NOTIFY_DISCONNECT, st_callback);
    }
    
    switch(action)
    {
	case 'L':
	    {
		GListPtr devices = NULL;
		rc = st->cmds->query(st, st_opts, target, &devices, 10);
		if(rc == 0) {
		    fprintf(stderr, "No devices found\n");

		} else if(rc > 0) {
		    GListPtr lpc = NULL;
		    fprintf(stderr, "%d devices found\n", rc);
		    for(lpc = devices; lpc != NULL; lpc = lpc->next) {
			char *device = (char*)lpc->data;
			fprintf(stdout, " %s\n", device);
		    }
		    rc = 0;
		}
	    }
	    break;
	case 'Q':
	    rc = st->cmds->call(st, st_opts, device, "monitor", NULL, 10);
	    if(rc < 0) {
		rc = st->cmds->call(st, st_opts, device, "list", NULL, 10);
	    }
	    break;
	case 'R':
	    rc = st->cmds->register_device(st, st_opts, device, "stonith-ng", agent, hash);
	    break;
	case 'D':
	    rc = st->cmds->remove_device(st, st_opts, device);
	    break;
	case 'M':
	    {
	        char *buffer = NULL;
		st->cmds->metadata(st, st_opt_sync_call, agent, NULL, &buffer, 0);
		printf("%s\n", buffer);
		crm_free(buffer);
	    }
	    break;
	    
	case 'C':
	    st_get_node_attributes(target, hash);
	    rc = st->cmds->confirm(st, st_opts, target);
	    break;
	case 'F':
	    st_get_node_attributes(target, hash);
	    rc = st->cmds->fence(st, st_opts, target, hash, "off", 120);
	    break;
	case 'U':
	    st_get_node_attributes(target, hash);
	    rc = st->cmds->fence(st, st_opts, target, hash, "on", 120);
	    break;
    }    
    
    st->cmds->disconnect(st);
    crm_debug("Disconnect: %d", rc);

    crm_debug("Destroy");
    stonith_api_delete(st);
    
    return rc;
}
