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
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/utsname.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/cluster.h>

#include <crm/stonith-ng.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>
#include <internal.h>

#define FE_AGENT_FORK		-2
#define FE_AGENT_ERROR		-3

GHashTable *device_list = NULL;
int invoke_device(stonith_device_t *device, const char *action, const char *port, char **output);

static void append_arg(
    gpointer key, gpointer value, gpointer user_data) 
{
    int len = 3; /* =, \n, \0 */ 
    int last = 0;
    char **args = user_data;


    if(strstr(key, "pcmk-")) {
	return;
    }
    
    len += strlen(key);
    len += strlen(value);
    if(*args != NULL) {
	last = strlen(*args);
    }
    
    crm_realloc(*args, last+len);
    
    sprintf((*args)+last, "%s=%s\n", (char *)key, (char *)value);
}

static char *make_args(GHashTable *args)
{
    char *arg_list = NULL;
    g_hash_table_foreach(args, append_arg, &arg_list);
    crm_debug_3("Calculated: %s", arg_list);
    return arg_list;
}

/* Borrowed from libfence */
static int run_agent(char *agent, GHashTable *arg_hash, int *agent_result, char **output)
{
    char *args = make_args(arg_hash);
    int pid, status, len, rc = -1;
    int pr_fd, pw_fd;  /* parent read/write file descriptors */
    int cr_fd, cw_fd;  /* child read/write file descriptors */
    int fd1[2];
    int fd2[2];

    cr_fd = cw_fd = pr_fd = pw_fd = -1;

    if (args == NULL || agent == NULL)
	goto fail;
    len = strlen(args);

    if (pipe(fd1))
	goto fail;
    pr_fd = fd1[0];
    cw_fd = fd1[1];

    if (pipe(fd2))
	goto fail;
    cr_fd = fd2[0];
    pw_fd = fd2[1];

    pid = fork();
    if (pid < 0) {
	*agent_result = FE_AGENT_FORK;
	goto fail;
    }

    if (pid) {
	/* parent */
	int ret;

	fcntl(pr_fd, F_SETFL, fcntl(pr_fd, F_GETFL, 0) | O_NONBLOCK);

	do {
	    ret = write(pw_fd, args, len);
	} while (ret < 0 && errno == EINTR);

	if (ret != len)
	    goto fail;

	close(pw_fd);
	waitpid(pid, &status, 0);

	if(output != NULL) {
	    len = 0;
	    do {
		char buf[500];
		ret = read(pr_fd, buf, 500);
		if(ret > 0) {
		    buf[ret] = 0;
		    crm_realloc(*output, len + ret + 1);
		    sprintf((*output)+len, "%s", buf);
		    len += ret;
		}
	    } while (ret < 0 && errno == EINTR);
	}

	crm_info("%d %d", WIFEXITED(status), WEXITSTATUS(status));
	
	*agent_result = FE_AGENT_ERROR;
	if (WIFEXITED(status)) {
	    *agent_result = -WEXITSTATUS(status);
	    rc = 0;
	}

    } else {
	/* child */

	close(1);
	if (dup(cw_fd) < 0)
	    goto fail;
	close(2);
	if (dup(cw_fd) < 0)
	    goto fail;
	close(0);
	if (dup(cr_fd) < 0)
	    goto fail;
	/* keep cw_fd open so parent can report all errors. */
	close(pr_fd);
	close(cr_fd);
	close(pw_fd);

	execlp(agent, agent, NULL);
	exit(EXIT_FAILURE);
    }

  fail:
    crm_free(args);
    close(pr_fd);
    close(cw_fd);
    close(cr_fd);
    close(pw_fd);
    return rc;
}

static void free_device(gpointer data)
{
    stonith_device_t *device = data;

    g_hash_table_destroy(device->params);
    crm_free(device->namespace);
    crm_free(device->agent);
    crm_free(device->id);
    crm_free(device);
}

static void build_port_aliases(stonith_device_t *device) 
{
    char *name = NULL;
    char *value = NULL;
    int last = 0, lpc = 0, max = 0;
    
    const char *portmap = g_hash_table_lookup(device->params, "pcmk-portmap");
    if(portmap == NULL) {
	return;
    }
    
    max = strlen(portmap);
    for(; lpc < max; lpc++) {
	if(portmap[lpc] == 0) {
	    break;
	    
	} else if(isalpha(portmap[lpc])) {
	    /* keep going */
	    
	} else if(portmap[lpc] == '=') {
	    crm_malloc0(name, 1 + lpc - last);
	    strncpy(name, portmap + last, lpc - last);
	    last = lpc + 1;
	    
	} else if(name && isspace(portmap[lpc])) {
	    crm_malloc0(value, 1 + lpc - last);
	    strncpy(value, portmap + last, lpc - last);
	    last = lpc + 1;

	    crm_info("Adding alias '%s'='%s' for %s", name, value, device->id);
	    g_hash_table_replace(device->aliases, name, value);
	    value=NULL;
	    name=NULL;
	    
	} else if(isspace(portmap[lpc])) {
	    last = lpc;
	}   
    }
}

static int stonith_device_register(xmlNode *msg) 
{
    xmlNode *dev = get_xpath_object("//"F_STONITH_DEVICE, msg, LOG_ERR);
    stonith_device_t *device = NULL;

    crm_malloc0(device, sizeof(stonith_device_t));
    device->id = crm_element_value_copy(dev, XML_ATTR_ID);
    device->agent = crm_element_value_copy(dev, "agent");
    device->namespace = crm_element_value_copy(dev, "namespace");
    device->params = xml2list(dev);
    device->aliases = g_hash_table_new_full(g_str_hash, g_str_equal, g_hash_destroy_str, g_hash_destroy_str);
    build_port_aliases(device);
    
    g_hash_table_insert(device_list, device->id, device);

    crm_info("Added '%s' to the device list (%d active devices)", device->id, g_hash_table_size(device_list));
    return stonith_ok;
}

static int stonith_device_remove(xmlNode *msg) 
{
    xmlNode *dev = get_xpath_object("//"F_STONITH_DEVICE, msg, LOG_ERR);
    const char *id = crm_element_value(dev, XML_ATTR_ID);
    if(g_hash_table_remove(device_list, id)) {
	crm_info("Removed '%s' from the device list (%d active devices)",
		 id, g_hash_table_size(device_list));
    } else {
	crm_info("Device '%s' not found (%d active devices)",
		 id, g_hash_table_size(device_list));
    }
    
    return stonith_ok;
}

static const char *get_device_port(stonith_device_t *dev, const char *host) 
{
    time_t now;
    char *alias = NULL;

    if(host == NULL) {
	return NULL;
    }
    
    now = time(NULL);
    alias = g_hash_table_lookup(dev->aliases, host);
    
    if(dev->targets == NULL || dev->targets_age + 300 < now) {
	int rc = stonith_ok;
	char *output = NULL;
	crm_free(dev->targets);
	dev->targets = NULL;

	rc = invoke_device(dev, "list", NULL, &output);
	crm_info("Port list for %s: %d", dev->id, rc);
	if(rc == 0) {
	    crm_info("Refreshing port list for %s", dev->id);
	    dev->targets = output;
	    dev->targets_age = now;
	} else {
	    crm_info("Disabling port list queries for %s", dev->id);	    
	    dev->targets_age = -1;
	}
    }

    /* See if portmap is defined and look up the translated name */
    if(alias) {
	if(dev->targets && strstr(dev->targets, alias)) {
	    return alias;
	} else if(dev->targets == NULL) {
	    return alias;
	}
    }

    if(dev->targets && strstr(dev->targets, host)) {
	return host;
    }

    return NULL;
}

int invoke_device(stonith_device_t *device, const char *action, const char *port, char **output) 
{
    int rc = 0;
    const char *device_port = get_device_port(device, port);
    if(port && device_port) {
	g_hash_table_replace(device->params, crm_strdup("port"), crm_strdup(device_port));

    } else if(port) {
	crm_err("Unknown or unhandled port '%s' for device '%s'", port, device->id);
	return -1;
    }

    crm_info("Calling '%s' with action '%s'%s%s", device->id,  action, port?" on port ":"", port?port:"");
    g_hash_table_replace(device->params, crm_strdup("option"), crm_strdup(action));
    if(run_agent(device->agent, device->params, &rc, output) < 0) {
	crm_err("Operation %s on %s failed (%d): %s", action, device->id, rc, *output);

    } else {
	crm_info("Operation %s on %s passed: %s", action, device->id, *output);
    }
    g_hash_table_remove(device->params, "port");
    return rc;
}

static int stonith_device_action(xmlNode *msg, char **output) 
{
    int rc = stonith_ok;
    xmlNode *dev = get_xpath_object("//@"F_STONITH_DEVICE, msg, LOG_ERR);
    const char *id = crm_element_value(dev, F_STONITH_DEVICE);
    const char *action = crm_element_value(dev, F_STONITH_ACTION);
    const char *port = crm_element_value(dev, F_STONITH_PORT);
    stonith_device_t *device = NULL;
    if(id) {
	crm_info("Looking for '%s'", id);
	device = g_hash_table_lookup(device_list, id);
    }

    if(device) {
	rc = invoke_device(device, action, port, output);
	
    } else {
	crm_err("Device %s not found", id);
    }
    
    return rc;
}

struct device_search_s 
{
	const char *host;
	GListPtr capable;
};

static void search_devices(
    gpointer key, gpointer value, gpointer user_data) 
{
    stonith_device_t *dev = value;
    struct device_search_s *search = user_data;
    if(get_device_port(value, search->host)) {
	crm_debug_4("Device '%s' can fence '%s'", dev->id, search->host);
	search->capable = g_list_append(search->capable, value);

    } else {
	crm_debug_3("Device '%s' cannot fence '%s'", dev->id, search->host);
    }
}

static int stonith_query(xmlNode *msg, xmlNode **list) 
{
    struct device_search_s search;
    xmlNode *dev = get_xpath_object("//@target", msg, LOG_ERR);
	
    search.capable = NULL;
    search.host = crm_element_value(dev, "target");
	
    g_hash_table_foreach(device_list, search_devices, &search);
    crm_info("Found %d matching devices for '%s'", g_list_length(search.capable), search.host);

    /* Pack the results into data */
    if(list) {
	*list = create_xml_node(NULL, __FUNCTION__);
	crm_xml_add_int(*list, "st-available-devices", g_list_length(search.capable));
	slist_iter(device, stonith_device_t, search.capable, lpc,
		   dev = create_xml_node(*list, F_STONITH_DEVICE);
		   crm_xml_add(dev, XML_ATTR_ID, device->id);
		   crm_xml_add(dev, "namespace", device->namespace);
		   crm_xml_add(dev, "agent", device->agent);
	    );
    }
    
    return g_list_length(search.capable);
}

static int stonith_fence(xmlNode *msg, const char *action) 
{
    struct device_search_s search;
    xmlNode *dev = get_xpath_object("//@target", msg, LOG_ERR);

    search.capable = NULL;
    search.host = crm_element_value(dev, "target");

    g_hash_table_foreach(device_list, search_devices, &search);
    crm_info("Found %d matching devices for '%s'", g_list_length(search.capable), search.host);

    slist_iter(dev, stonith_device_t, search.capable, lpc,
	       int rc = 0;
	       char *output = NULL;
	       const char *port = get_device_port(dev, search.host);
	       CRM_CHECK(port != NULL, continue);
	       
	       g_hash_table_replace(dev->params, crm_strdup("option"), crm_strdup(action));
	       g_hash_table_replace(dev->params, crm_strdup("port"), crm_strdup(port));

	       if(run_agent(dev->agent, dev->params, &rc, &output) == 0) {
		   crm_info("Terminated host '%s' with device '%s'", search.host, dev->id);
		   crm_free(output);
		   return stonith_ok;

	       } else {
		   crm_err("Termination of host '%s' with device '%s' failed: %s", search.host, dev->id, output);
	       }
	       crm_free(output);
	);
    
    return -1;
}

static xmlNode *
stonith_construct_reply(xmlNode *request, char *output, xmlNode *data, int rc) 
{
    int lpc = 0;
    xmlNode *reply = NULL;
	
    const char *name = NULL;
    const char *value = NULL;
    const char *names[] = {
	F_STONITH_OPERATION,
	F_STONITH_CALLID,
	F_STONITH_CLIENTID,
	F_STONITH_CALLOPTS
    };

    crm_debug_4("Creating a basic reply");
    reply = create_xml_node(NULL, "stonith-reply");
    crm_xml_add(reply, F_TYPE, T_STONITH);

    for(lpc = 0; lpc < DIMOF(names); lpc++) {
	name = names[lpc];
	value = crm_element_value(request, name);
	crm_xml_add(reply, name, value);
    }

    crm_xml_add_int(reply, F_STONITH_RC, rc);
    crm_xml_add(reply, "st_output", output);

    if(data != NULL) {
	crm_debug_4("Attaching reply output");
	add_message_xml(reply, F_STONITH_CALLDATA, data);
    }
    return reply;
}

void
stonith_command(stonith_client_t *client, xmlNode *request, gboolean remote)
{
    int rc = stonith_ok;
    int call_options = 0;

    gboolean done = TRUE;

    xmlNode *reply = NULL;
    xmlNode *data = NULL;

    char *output = NULL;
    const char *op = crm_element_value(request, F_STONITH_OPERATION);
    const char *client_id = crm_element_value(request, F_STONITH_CLIENTID);

    crm_element_value_int(request, F_STONITH_CALLOPTS, &call_options);
    
    if(device_list == NULL) {
	device_list = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_device);
    }

    crm_info("Processing %s from %s", op, client->name);
    
    if(crm_str_eq(op, CRM_OP_REGISTER, TRUE)) {
	return;
	    
    } else if(crm_str_eq(op, T_STONITH_NOTIFY, TRUE)) {
	const char *flag_name = NULL;

	flag_name = crm_element_value(request, F_STONITH_NOTIFY_ACTIVATE);
	if(flag_name) {
	    crm_debug("Setting %s callbacks for %s (%s): ON",
		      flag_name, client->name, client->id);
	    client->flags |= get_stonith_flag(flag_name);
	}
	
	flag_name = crm_element_value(request, F_STONITH_NOTIFY_DEACTIVATE);
	if(flag_name) {
	    crm_debug("Setting %s callbacks for %s (%s): off",
		      flag_name, client->name, client->id);
	    client->flags |= get_stonith_flag(flag_name);
	}
	return;

    } else if(crm_str_eq(op, STONITH_OP_DEVICE_ADD, TRUE)) {
	rc = stonith_device_register(request);
	do_stonith_notify(call_options, op, rc, request, T_STONITH_NOTIFY_DEVICE_ADD);
	
    } else if(crm_str_eq(op, STONITH_OP_DEVICE_DEL, TRUE)) {
	rc = stonith_device_remove(request);
	do_stonith_notify(call_options, op, rc, request, T_STONITH_NOTIFY_DEVICE_DEL);
	

    } else if(crm_str_eq(op, STONITH_OP_EXEC, TRUE)) {
	rc = stonith_device_action(request, &output);

    } else if(crm_str_eq(op, STONITH_OP_FENCE, TRUE)) {
	rc = stonith_fence(request, "off");
	do_stonith_notify(call_options, op, rc, request, T_STONITH_NOTIFY_FENCE);

	if(rc < 0) {
	    stonith_query(request, &data);
	}

    } else if(crm_str_eq(op, STONITH_OP_UNFENCE, TRUE)) {
	rc = stonith_fence(request, "on");
	do_stonith_notify(call_options, op, rc, request, T_STONITH_NOTIFY_UNFENCE);

    } else if(crm_str_eq(op, STONITH_OP_QUERY, TRUE)) {
	rc = stonith_query(request, &data);
    }

    if(done) {
	reply = stonith_construct_reply(request, output, data, rc);
	do_local_reply(reply, client_id, call_options & stonith_sync_call, remote);
	free_xml(reply);
    }

    crm_free(output);
    free_xml(data);
}
