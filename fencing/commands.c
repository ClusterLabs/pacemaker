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
#include <internal.h>

#define FE_AGENT_FORK		-1
#define FE_AGENT_ERROR		-2
#define FE_AGENT_SUCCESS	-3

GHashTable *device_list = NULL;

static void append_arg(
    gpointer key, gpointer value, gpointer user_data) 
{
    int len = 3; /* =, \n, \0 */ 
    int last = 0;
    char **args = user_data;

    len += strlen(key);
    len += strlen(value);
    if(*args != NULL) {
	last = strlen(*args);
    }
    
    crm_realloc(*args, last+len);
    
    if(*args == NULL) {
	sprintf((*args)+last, "%s=%s\n", (char *)key, (char *)value);
    }
}

static char *make_args(GHashTable *args)
{
    char *arg_list = NULL;
    g_hash_table_foreach(args, append_arg, &arg_list);
    return arg_list;
}

/* Borrowed from libfence */
static int run_agent(char *agent, GHashTable *arg_hash, int *agent_result)
{
    char *args = make_args(arg_hash);
    int pid, status, len;
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

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
	    *agent_result = FE_AGENT_ERROR;
	    goto fail;
	} else {
	    *agent_result = FE_AGENT_SUCCESS;
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

    crm_free(args);
    close(pr_fd);
    close(cw_fd);
    close(cr_fd);
    close(pw_fd);
    return 0;

  fail:
    crm_free(args);
    close(pr_fd);
    close(cw_fd);
    close(cr_fd);
    close(pw_fd);
    return -1;
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


static int stonith_device_register(xmlNode *msg) 
{
    xmlNode *dev = get_xpath_object("//"F_STONITH_DEVICE, msg, LOG_ERR);
    stonith_device_t *device = NULL;

    crm_malloc0(device, sizeof(stonith_device_t));
    device->id = crm_element_value_copy(dev, XML_ATTR_ID);
    device->agent = crm_element_value_copy(dev, "agent");
    device->namespace = crm_element_value_copy(dev, "namespace");
    device->params = xml2list(dev);

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

static int stonith_device_action(xmlNode *msg) 
{
    xmlNode *dev = get_xpath_object("//@"F_STONITH_DEVICE, msg, LOG_ERR);
    const char *id = crm_element_value(dev, F_STONITH_DEVICE);
    const char *action = crm_element_value(dev, F_STONITH_ACTION);
    stonith_device_t *device = NULL;
    if(id) {
	crm_info("Looking for '%s'", id);
	device = g_hash_table_lookup(device_list, id);
    }

    if(device) {
	int rc = 0;
	g_hash_table_replace(device->params, crm_strdup("option"), crm_strdup(action));
	crm_info("Calling '%s' with action '%s'", id, action);
	if(run_agent(device->agent, device->params, &rc) < 0) {
	    crm_err("Operation %s on %s failed: %d", action, id, rc);
	} else {
	    crm_err("Operation %s on %s passed", action, id);
	}
	
	
    } else {
	crm_err("Device %s not found", id);
    }
    
    return stonith_ok;
}

void
stonith_command(stonith_client_t *client, xmlNode *op_request)
{
    int rc = stonith_ok;
    const char *op = crm_element_value(op_request, F_STONITH_OPERATION);

    if(device_list == NULL) {
	device_list = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_device);
    }

    crm_info("Processing %s from %s", op, client->name);
    
    if(crm_str_eq(op, CRM_OP_REGISTER, TRUE)) {
	return;
	    
    } else if(crm_str_eq(op, T_STONITH_NOTIFY, TRUE)) {
	/* Update the notify filters for this client */
	int on_off = 0;
	crm_element_value_int(op_request, F_STONITH_NOTIFY_ACTIVATE, &on_off);
	    
	crm_debug("Setting callbacks for %s (%s): %s",
		  client->name, client->id, on_off?"on":"off");
	client->flags = on_off;
	return;

    } else if(crm_str_eq(op, STONITH_OP_DEVICE_ADD, TRUE)) {
	rc = stonith_device_register(op_request);
	
    } else if(crm_str_eq(op, STONITH_OP_DEVICE_DEL, TRUE)) {
	rc = stonith_device_remove(op_request);

    } else if(crm_str_eq(op, STONITH_OP_EXEC, TRUE)) {
	rc = stonith_device_action(op_request);

    } else if(crm_str_eq(op, STONITH_OP_FENCE, TRUE)) {
    }
}
