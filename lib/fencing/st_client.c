/*
 * Copyright (c) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */
#include <crm_internal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <glib.h>
#include <dirent.h>
#include <libgen.h>             /* Add it for compiling on OSX */

#include <crm/crm.h>
#include <crm/stonith-ng.h>
#include <crm/stonith-ng-internal.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <stonith/stonith.h>

#include <crm/common/mainloop.h>


CRM_TRACE_INIT_DATA(stonith);

typedef struct stonith_private_s {
    char *token;
    crm_ipc_t *ipc;
    mainloop_io_t *source;
    GHashTable *stonith_op_callback_table;
    GList *notify_list;

    void (*op_callback) (stonith_t * st, const xmlNode * msg, int call, int rc, xmlNode * output,
                         void *userdata);

} stonith_private_t;

typedef struct stonith_notify_client_s {
    const char *event;
    const char *obj_id;         /* implement one day */
    const char *obj_type;       /* implement one day */
    void (*notify) (stonith_t * st, const char *event, xmlNode * msg);

} stonith_notify_client_t;

typedef struct stonith_callback_client_s {
    void (*callback) (stonith_t * st, const xmlNode * msg, int call, int rc, xmlNode * output,
                      void *userdata);
    const char *id;
    void *user_data;
    gboolean only_success;
    struct timer_rec_s *timer;

} stonith_callback_client_t;

struct notify_blob_s {
    stonith_t *stonith;
    xmlNode *xml;
};

struct timer_rec_s {
    int call_id;
    int timeout;
    guint ref;
    stonith_t *stonith;
};

typedef enum stonith_errors (*stonith_op_t) (const char *, int, const char *, xmlNode *,
                                             xmlNode *, xmlNode *, xmlNode **, xmlNode **);

static const char META_TEMPLATE[] =
    "<?xml version=\"1.0\"?>\n"
    "<!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n"
    "<resource-agent name=\"%s\">\n"
    "  <version>1.0</version>\n"
    "  <longdesc lang=\"en\">\n"
    "%s\n"
    "  </longdesc>\n"
    "  <shortdesc lang=\"en\">%s</shortdesc>\n"
    "%s\n"
    "  <actions>\n"
    "    <action name=\"start\"   timeout=\"20\" />\n"
    "    <action name=\"stop\"    timeout=\"15\" />\n"
    "    <action name=\"status\"  timeout=\"20\" />\n"
    "    <action name=\"monitor\" timeout=\"20\" interval=\"3600\"/>\n"
    "    <action name=\"meta-data\"  timeout=\"15\" />\n"
    "  </actions>\n"
    "  <special tag=\"heartbeat\">\n"
    "    <version>2.0</version>\n" "  </special>\n" "</resource-agent>\n";

bool stonith_dispatch(stonith_t * st);
int stonith_dispatch_internal(const char *buffer, ssize_t length, gpointer userdata);
void stonith_perform_callback(stonith_t * stonith, xmlNode * msg, int call_id, int rc);
xmlNode *stonith_create_op(int call_id, const char *token, const char *op, xmlNode * data,
                           int call_options);
int stonith_send_command(stonith_t * stonith, const char *op, xmlNode * data,
                         xmlNode ** output_data, int call_options, int timeout);

static void stonith_connection_destroy(gpointer user_data);
static void stonith_send_notification(gpointer data, gpointer user_data);

static void
stonith_connection_destroy(gpointer user_data)
{
    stonith_t *stonith = user_data;
    stonith_private_t *native = NULL;
    struct notify_blob_s blob;

    crm_trace("Sending destroyed notification");
    blob.stonith = stonith;
    blob.xml = create_xml_node(NULL, "notify");

    native = stonith->private;
    native->ipc = NULL;
    native->source = NULL;

    stonith->state = stonith_disconnected;
    crm_xml_add(blob.xml, F_TYPE, T_STONITH_NOTIFY);
    crm_xml_add(blob.xml, F_SUBTYPE, T_STONITH_NOTIFY_DISCONNECT);

    g_list_foreach(native->notify_list, stonith_send_notification, &blob);
    free_xml(blob.xml);
}

xmlNode *
create_device_registration_xml(const char *id, const char *namespace, const char *agent,
                               stonith_key_value_t * params)
{
    xmlNode *data = create_xml_node(NULL, F_STONITH_DEVICE);
    xmlNode *args = create_xml_node(data, XML_TAG_ATTRS);

    crm_xml_add(data, XML_ATTR_ID, id);
    crm_xml_add(data, "origin", __FUNCTION__);
    crm_xml_add(data, "agent", agent);
    crm_xml_add(data, "namespace", namespace);

    for (; params; params = params->next) {
        hash2field((gpointer) params->key, (gpointer) params->value, args);
    }

    return data;
}

static int
stonith_api_register_device(stonith_t * st, int call_options,
                            const char *id, const char *namespace, const char *agent,
                            stonith_key_value_t * params)
{
    int rc = 0;
    xmlNode *data = create_device_registration_xml(id, namespace, agent, params);

    rc = stonith_send_command(st, STONITH_OP_DEVICE_ADD, data, NULL, call_options, 0);
    free_xml(data);

    return rc;
}

static int
stonith_api_remove_device(stonith_t * st, int call_options, const char *name)
{
    int rc = 0;
    xmlNode *data = NULL;

    data = create_xml_node(NULL, F_STONITH_DEVICE);
    crm_xml_add(data, "origin", __FUNCTION__);
    crm_xml_add(data, XML_ATTR_ID, name);
    rc = stonith_send_command(st, STONITH_OP_DEVICE_DEL, data, NULL, call_options, 0);
    free_xml(data);

    return rc;
}

static int
stonith_api_remove_level(stonith_t * st, int options, const char *node, int level)
{
    int rc = 0;
    xmlNode *data = NULL;

    data = create_xml_node(NULL, F_STONITH_LEVEL);
    crm_xml_add(data, "origin", __FUNCTION__);
    crm_xml_add(data, F_STONITH_TARGET, node);
    crm_xml_add_int(data, XML_ATTR_ID, level);
    rc = stonith_send_command(st, STONITH_OP_LEVEL_DEL, data, NULL, options, 0);
    free_xml(data);

    return rc;
}

xmlNode *
create_level_registration_xml(const char *node, int level, stonith_key_value_t * device_list)
{
    xmlNode *data = create_xml_node(NULL, F_STONITH_LEVEL);

    crm_xml_add_int(data, XML_ATTR_ID, level);
    crm_xml_add(data, F_STONITH_TARGET, node);
    crm_xml_add(data, "origin", __FUNCTION__);

    for (; device_list; device_list = device_list->next) {
        xmlNode *dev = create_xml_node(data, F_STONITH_DEVICE);

        crm_xml_add(dev, XML_ATTR_ID, device_list->value);
    }

    return data;
}

static int
stonith_api_register_level(stonith_t * st, int options, const char *node, int level,
                           stonith_key_value_t * device_list)
{
    int rc = 0;
    xmlNode *data = create_level_registration_xml(node, level, device_list);

    rc = stonith_send_command(st, STONITH_OP_LEVEL_ADD, data, NULL, options, 0);
    free_xml(data);

    return rc;
}

static void
append_arg(gpointer key, gpointer value, gpointer user_data)
{
    int len = 3;                /* =, \n, \0 */
    int last = 0;
    char **args = user_data;

    CRM_CHECK(key != NULL, return);
    CRM_CHECK(value != NULL, return);

    if (strstr(key, "pcmk_")) {
        return;
    } else if (strstr(key, CRM_META)) {
        return;
    } else if (safe_str_eq(key, "crm_feature_set")) {
        return;
    }

    len += strlen(key);
    len += strlen(value);
    if (*args != NULL) {
        last = strlen(*args);
    }

    crm_realloc(*args, last + len);
    crm_trace("Appending: %s=%s", (char *)key, (char *)value);
    sprintf((*args) + last, "%s=%s\n", (char *)key, (char *)value);
}

static void
append_const_arg(const char *key, const char *value, char **arg_list)
{
    char *glib_sucks_key = crm_strdup(key);
    char *glib_sucks_value = crm_strdup(value);

    append_arg(glib_sucks_key, glib_sucks_value, arg_list);

    free(glib_sucks_value);
    free(glib_sucks_key);
}

static void
append_host_specific_args(const char *victim, const char *map, GHashTable * params, char **arg_list)
{
    char *name = NULL;
    int last = 0, lpc = 0, max = 0;

    if (map == NULL) {
        /* The best default there is for now... */
        crm_debug("Using default arg map: port=uname");
        append_const_arg("port", victim, arg_list);
        return;
    }

    max = strlen(map);
    crm_debug("Processing arg map: %s", map);
    for (; lpc < max + 1; lpc++) {
        if (isalpha(map[lpc])) {
            /* keep going */

        } else if (map[lpc] == '=' || map[lpc] == ':') {
            free(name);
            name = calloc(1, 1 + lpc - last);
            memcpy(name, map + last, lpc - last);
            crm_debug("Got name: %s", name);
            last = lpc + 1;

        } else if (map[lpc] == 0 || map[lpc] == ',' || isspace(map[lpc])) {
            char *param = NULL;
            const char *value = NULL;

            param = calloc(1, 1 + lpc - last);
            memcpy(param, map + last, lpc - last);
            last = lpc + 1;

            crm_debug("Got key: %s", param);
            if (name == NULL) {
                crm_err("Misparsed '%s', found '%s' without a name", map, param);
                free(param);
                continue;
            }

            if (safe_str_eq(param, "uname")) {
                value = victim;
            } else {
                char *key = crm_meta_name(param);

                value = g_hash_table_lookup(params, key);
                free(key);
            }

            if (value) {
                crm_debug("Setting '%s'='%s' (%s) for %s", name, value, param, victim);
                append_const_arg(name, value, arg_list);

            } else {
                crm_err("No node attribute '%s' for '%s'", name, victim);
            }

            free(name);
            name = NULL;
            free(param);
            if (map[lpc] == 0) {
                break;
            }

        } else if (isspace(map[lpc])) {
            last = lpc;
        }
    }
    free(name);
}

static char *
make_args(const char *action, const char *victim, GHashTable * device_args, GHashTable * port_map)
{
    char buffer[512];
    char *arg_list = NULL;
    const char *value = NULL;

    CRM_CHECK(action != NULL, return NULL);

    if (device_args) {
        g_hash_table_foreach(device_args, append_arg, &arg_list);
    }

    buffer[511] = 0;
    snprintf(buffer, 511, "pcmk_%s_action", action);
    if (device_args) {
        value = g_hash_table_lookup(device_args, buffer);
    }

    if (value == NULL && device_args) {
        /* Legacy support for early 1.1 releases - Remove for 1.2 */
        snprintf(buffer, 511, "pcmk_%s_cmd", action);
        value = g_hash_table_lookup(device_args, buffer);
    }

    if (value) {
        crm_info("Substituting action '%s' for requested operation '%s'", value, action);
        action = value;
    }

    append_const_arg(STONITH_ATTR_ACTION_OP, action, &arg_list);
    if (victim && device_args) {
        const char *alias = victim;
        const char *param = g_hash_table_lookup(device_args, STONITH_ATTR_HOSTARG);

        if (port_map && g_hash_table_lookup(port_map, victim)) {
            alias = g_hash_table_lookup(port_map, victim);
        }

        /* Always supply the node's name too:
         *    https://fedorahosted.org/cluster/wiki/FenceAgentAPI
         */
        append_const_arg("nodename", victim, &arg_list);

        /* Check if we need to supply the victim in any other form */
        if (param == NULL) {
            const char *map = g_hash_table_lookup(device_args, STONITH_ATTR_ARGMAP);

            if (map == NULL) {
                param = "port";
                value = g_hash_table_lookup(device_args, param);

            } else {
                /* Legacy handling */
                append_host_specific_args(alias, map, device_args, &arg_list);
                value = map;    /* Nothing more to do */
            }

        } else if (safe_str_eq(param, "none")) {
            value = param;      /* Nothing more to do */

        } else {
            value = g_hash_table_lookup(device_args, param);
        }

        /* Don't overwrite explictly set values for $param */
        if (value == NULL || safe_str_eq(value, "dynamic")) {
            crm_debug("Performing %s action for node '%s' as '%s=%s'", action, victim, param,
                      alias);
            append_const_arg(param, alias, &arg_list);
        }
    }

    crm_trace("Calculated: %s", arg_list);
    return arg_list;
}

static gboolean
st_child_term(gpointer data)
{
    int rc = 0;
    async_command_t * track = data;
    crm_info("Child %d timed out, sending SIGTERM", track->pid);
    track->timer_sigterm = 0;
    rc = kill(track->pid, SIGTERM);
    if(rc < 0) {
        crm_perror(LOG_ERR, "Couldn't send SIGTERM to %d", track->pid);
    }
    return FALSE;
}

static gboolean
st_child_kill(gpointer data)
{
    int rc = 0;
    async_command_t * track = data;
    crm_info("Child %d timed out, sending SIGKILL", track->pid);
    track->timer_sigkill = 0;
    rc = kill(track->pid, SIGKILL);
    if(rc < 0) {
        crm_perror(LOG_ERR, "Couldn't send SIGKILL to %d", track->pid);
    }
    return FALSE;
}

/* Borrowed from libfence and extended */
int
run_stonith_agent(const char *agent, const char *action, const char *victim,
                  GHashTable * device_args, GHashTable * port_map, int *agent_result, char **output,
                  async_command_t * track)
{
    char *args = make_args(action, victim, device_args, port_map);
    int pid, status, len, rc = st_err_internal;
    int p_read_fd, p_write_fd;  /* parent read/write file descriptors */
    int c_read_fd, c_write_fd;  /* child read/write file descriptors */
    int fd1[2];
    int fd2[2];

    c_read_fd = c_write_fd = p_read_fd = p_write_fd = -1;

    if (args == NULL || agent == NULL)
        goto fail;
    len = strlen(args);

    if (pipe(fd1))
        goto fail;
    p_read_fd = fd1[0];
    c_write_fd = fd1[1];

    if (pipe(fd2))
        goto fail;
    c_read_fd = fd2[0];
    p_write_fd = fd2[1];

    crm_debug("forking");
    pid = fork();
    if (pid < 0) {
        rc = st_err_agent_fork;
        goto fail;
    }

    if (pid) {
        /* parent */
        int ret;
        int total = 0;

        fcntl(p_read_fd, F_SETFL, fcntl(p_read_fd, F_GETFL, 0) | O_NONBLOCK);

        do {
            crm_debug("sending args");
            ret = write(p_write_fd, args + total, len - total);
            if (ret > 0) {
                total += ret;
            }

        } while (errno == EINTR && total < len);

        if (total != len) {
            crm_perror(LOG_ERR, "Sent %d not %d bytes", total, len);
            if (ret >= 0) {
                rc = st_err_agent_args;
            }
            goto fail;
        }

        close(p_write_fd);

        if (track && track->done) {
            track->stdout = p_read_fd;
            g_child_watch_add(pid, track->done, track);
            crm_trace("Op: %s on %s, pid: %d, timeout: %ds", action, agent, pid, track->timeout);

            if (track->timeout) {
                track->pid = pid;
                track->timer_sigterm = g_timeout_add(1000*track->timeout, st_child_term, track);
                track->timer_sigkill = g_timeout_add(1000*(track->timeout+5), st_child_kill, track);

            } else {
                crm_err("No timeout set for stonith operation %s with device %s", action, agent);
            }

            close(c_write_fd);
            close(c_read_fd);
            free(args);
            return pid;

        } else {
            pid_t p;

            do {
                p = waitpid(pid, &status, 0);
            } while (p < 0 && errno == EINTR);

            if (p < 0) {
                crm_perror(LOG_ERR, "waitpid(%d)", pid);

            } else if (p != pid) {
                crm_err("Waited for %d, got %d", pid, p);
            }

            if (output != NULL) {
                len = 0;
                do {
                    char buf[500];

                    ret = read(p_read_fd, buf, 500);
                    if (ret > 0) {
                        buf[ret] = 0;
                        crm_realloc(*output, len + ret + 1);
                        sprintf((*output) + len, "%s", buf);
                        crm_debug("%d: %s", ret, (*output) + len);
                        len += ret;
                    }

                } while (ret == 500 || (ret < 0 && errno == EINTR));
            }

            rc = st_err_agent;
            *agent_result = st_err_agent;
            if (WIFEXITED(status)) {
                crm_debug("result = %d", WEXITSTATUS(status));
                *agent_result = -WEXITSTATUS(status);
                rc = 0;

            } else if (WIFSIGNALED(status)) {
                crm_err("call %s for %s exited due to signal %d", action, agent, WTERMSIG(status));

            } else {
                crm_err("call %s for %s exited abnormally. stopped=%d, continued=%d",
                        action, agent, WIFSTOPPED(status), WIFCONTINUED(status));
            }
        }

    } else {
        /* child */

        close(1);
        /* coverity[leaked_handle] False positive */
        if (dup(c_write_fd) < 0)
            goto fail;
        close(2);
        /* coverity[leaked_handle] False positive */
        if (dup(c_write_fd) < 0)
            goto fail;
        close(0);
        /* coverity[leaked_handle] False positive */
        if (dup(c_read_fd) < 0)
            goto fail;

        /* keep c_write_fd open so parent can report all errors. */
        close(c_read_fd);
        close(p_read_fd);
        close(p_write_fd);

        execlp(agent, agent, NULL);
        exit(EXIT_FAILURE);
    }

  fail:
    free(args);

    if (p_read_fd >= 0) {
        close(p_read_fd);
    }
    if (p_write_fd >= 0) {
        close(p_write_fd);
    }

    if (c_read_fd >= 0) {
        close(c_read_fd);
    }
    if (c_write_fd >= 0) {
        close(c_write_fd);
    }

    return rc;
}

static int
stonith_api_device_list(stonith_t * stonith, int call_options, const char *namespace,
                        stonith_key_value_t ** devices, int timeout)
{
    int count = 0;

    if (devices == NULL) {
        crm_err("Parameter error: stonith_api_device_list");
        return -2;
    }

    /* Include Heartbeat agents */
    if (namespace == NULL || safe_str_eq("heartbeat", namespace)) {
        char **entry = NULL;
        char **type_list = stonith_types();

        for (entry = type_list; entry != NULL && *entry; ++entry) {
            crm_trace("Added: %s", *entry);
            *devices = stonith_key_value_add(*devices, NULL, *entry);
            count++;
        }
        if (type_list) {
            stonith_free_hostlist(type_list);
        }
    }

    /* Include Red Hat agents, basically: ls -1 @sbin_dir@/fence_* */
    if (namespace == NULL || safe_str_eq("redhat", namespace)) {
        struct dirent **namelist;
        int file_num = scandir(RH_STONITH_DIR, &namelist, 0, alphasort);

        if (file_num > 0) {
            struct stat prop;
            char buffer[FILENAME_MAX + 1];

            while (file_num--) {
                if ('.' == namelist[file_num]->d_name[0]) {
                    free(namelist[file_num]);
                    continue;

                } else if (0 != strncmp(RH_STONITH_PREFIX,
                                        namelist[file_num]->d_name, strlen(RH_STONITH_PREFIX))) {
                    free(namelist[file_num]);
                    continue;
                }

                snprintf(buffer, FILENAME_MAX, "%s/%s", RH_STONITH_DIR, namelist[file_num]->d_name);
                if (stat(buffer, &prop) == 0 && S_ISREG(prop.st_mode)) {
                    *devices = stonith_key_value_add(*devices, NULL, namelist[file_num]->d_name);
                    count++;
                }

                free(namelist[file_num]);
            }
            free(namelist);
        }
    }

    return count;
}

static int
stonith_api_device_metadata(stonith_t * stonith, int call_options, const char *agent,
                            const char *namespace, char **output, int timeout)
{
    int rc = 0;
    int bufferlen = 0;

    char *buffer = NULL;
    char *xml_meta_longdesc = NULL;
    char *xml_meta_shortdesc = NULL;

    char *meta_param = NULL;
    char *meta_longdesc = NULL;
    char *meta_shortdesc = NULL;
    const char *provider = get_stonith_provider(agent, namespace);

    Stonith *stonith_obj = NULL;
    static const char *no_parameter_info = "<!-- no value -->";

    crm_trace("looking up %s/%s metadata", agent, provider);

    /* By having this in a library, we can access it from stonith_admin
     *  when neither lrmd or stonith-ng are running
     * Important for the crm shell's validations...
     */

    if (safe_str_eq(provider, "redhat")) {

        int exec_rc = run_stonith_agent(agent, "metadata", NULL, NULL, NULL, &rc, &buffer, NULL);

        if (exec_rc < 0 || rc != 0 || buffer == NULL) {
            /* failed */
            crm_debug("Query failed: %d %d: %s", exec_rc, rc, crm_str(buffer));

            /* provide a fake metadata entry */
            meta_longdesc = crm_strdup(no_parameter_info);
            meta_shortdesc = crm_strdup(no_parameter_info);
            meta_param = crm_strdup("  <parameters>\n"
                                    "    <parameter name=\"action\">\n"
                                    "      <getopt mixed=\"-o\" />\n"
                                    "      <content type=\"string\" default=\"reboot\" />\n"
                                    "      <shortdesc lang=\"en\">Fencing action (null, off, on, [reboot], status, hostlist, devstatus)</shortdesc>\n"
                                    "    </parameter>\n" "  </parameters>");

            goto build;

        } else {

            xmlNode *xml = string2xml(buffer);
            xmlNode *actions = NULL;
            xmlXPathObject *xpathObj = NULL;

            xpathObj = xpath_search(xml, "//actions");
            if (xpathObj && xpathObj->nodesetval->nodeNr > 0) {
                actions = getXpathResult(xpathObj, 0);
            }

            /* Now fudge the metadata so that the start/stop actions appear */
            xpathObj = xpath_search(xml, "//action[@name='stop']");
            if (xpathObj == NULL || xpathObj->nodesetval->nodeNr <= 0) {
                xmlNode *tmp = NULL;

                tmp = create_xml_node(actions, "action");
                crm_xml_add(tmp, "name", "stop");
                crm_xml_add(tmp, "timeout", "20s");

                tmp = create_xml_node(actions, "action");
                crm_xml_add(tmp, "name", "start");
                crm_xml_add(tmp, "timeout", "20s");
            }

            /* Now fudge the metadata so that the port isn't required in the configuration */
            xpathObj = xpath_search(xml, "//parameter[@name='port']");
            if (xpathObj && xpathObj->nodesetval->nodeNr > 0) {
                /* We'll fill this in */
                xmlNode *tmp = getXpathResult(xpathObj, 0);

                crm_xml_add(tmp, "required", "0");
            }

            free(buffer);
            buffer = dump_xml_formatted(xml);
            free_xml(xml);
        }

    } else {
        stonith_obj = stonith_new(agent);

        meta_longdesc = crm_strdup(stonith_get_info(stonith_obj, ST_DEVICEDESCR));
        if (meta_longdesc == NULL) {
            crm_warn("no long description in %s's metadata.", agent);
            meta_longdesc = crm_strdup(no_parameter_info);
        }

        meta_shortdesc = crm_strdup(stonith_get_info(stonith_obj, ST_DEVICEID));
        if (meta_shortdesc == NULL) {
            crm_warn("no short description in %s's metadata.", agent);
            meta_shortdesc = crm_strdup(no_parameter_info);
        }

        meta_param = crm_strdup(stonith_get_info(stonith_obj, ST_CONF_XML));
        if (meta_param == NULL) {
            crm_warn("no list of parameters in %s's metadata.", agent);
            meta_param = crm_strdup(no_parameter_info);
        }

  build:
        xml_meta_longdesc =
            (char *)xmlEncodeEntitiesReentrant(NULL, (const unsigned char *)meta_longdesc);
        xml_meta_shortdesc =
            (char *)xmlEncodeEntitiesReentrant(NULL, (const unsigned char *)meta_shortdesc);

        bufferlen = strlen(META_TEMPLATE) + strlen(agent)
            + strlen(xml_meta_longdesc) + strlen(xml_meta_shortdesc)
            + strlen(meta_param) + 1;

        buffer = calloc(1, bufferlen);
        snprintf(buffer, bufferlen - 1, META_TEMPLATE,
                 agent, xml_meta_longdesc, xml_meta_shortdesc, meta_param);

        xmlFree(xml_meta_longdesc);
        xmlFree(xml_meta_shortdesc);

        if (stonith_obj) {
            stonith_delete(stonith_obj);
        }

        free(meta_shortdesc);
        free(meta_longdesc);
        free(meta_param);
    }

    if (output) {
        *output = buffer;

    } else {
        free(buffer);
    }

    return rc;
}

static int
stonith_api_query(stonith_t * stonith, int call_options, const char *target,
                  stonith_key_value_t ** devices, int timeout)
{
    int rc = 0, lpc = 0, max = 0;

    xmlNode *data = NULL;
    xmlNode *output = NULL;
    xmlXPathObjectPtr xpathObj = NULL;

    CRM_CHECK(devices != NULL, return st_err_missing);

    data = create_xml_node(NULL, F_STONITH_DEVICE);
    crm_xml_add(data, "origin", __FUNCTION__);
    crm_xml_add(data, F_STONITH_TARGET, target);
    rc = stonith_send_command(stonith, STONITH_OP_QUERY, data, &output, call_options, timeout);

    if (rc < 0) {
        return rc;
    }

    xpathObj = xpath_search(output, "//@agent");
    if (xpathObj) {
        max = xpathObj->nodesetval->nodeNr;

        for (lpc = 0; lpc < max; lpc++) {
            xmlNode *match = getXpathResult(xpathObj, lpc);

            CRM_CHECK(match != NULL, continue);

            crm_info("%s[%d] = %s", "//@agent", lpc, xmlGetNodePath(match));
            *devices = stonith_key_value_add(*devices, NULL, crm_element_value(match, XML_ATTR_ID));
        }
    }

    free_xml(output);
    free_xml(data);
    return max;
}

static int
stonith_api_call(stonith_t * stonith, int call_options, const char *id, const char *action,
                 const char *victim, int timeout)
{
    int rc = 0;
    xmlNode *data = NULL;

    data = create_xml_node(NULL, F_STONITH_DEVICE);
    crm_xml_add(data, "origin", __FUNCTION__);
    crm_xml_add(data, F_STONITH_DEVICE, id);
    crm_xml_add(data, F_STONITH_ACTION, action);
    crm_xml_add(data, F_STONITH_TARGET, victim);

    rc = stonith_send_command(stonith, STONITH_OP_EXEC, data, NULL, call_options, timeout);
    free_xml(data);

    return rc;
}

static int
stonith_api_fence(stonith_t * stonith, int call_options, const char *node, const char *action,
                  int timeout)
{
    int rc = 0;
    xmlNode *data = NULL;

    data = create_xml_node(NULL, __FUNCTION__);
    crm_xml_add(data, F_STONITH_TARGET, node);
    crm_xml_add(data, F_STONITH_ACTION, action);
    crm_xml_add_int(data, F_STONITH_TIMEOUT, timeout);

    rc = stonith_send_command(stonith, STONITH_OP_FENCE, data, NULL, call_options, timeout);
    free_xml(data);

    return rc;
}

static int
stonith_api_confirm(stonith_t * stonith, int call_options, const char *target)
{
    return stonith_api_fence(stonith, call_options | st_opt_manual_ack, target, "off", 0);
}

static int
stonith_api_history(stonith_t * stonith, int call_options, const char *node,
                    stonith_history_t ** history, int timeout)
{
    int rc = 0;
    xmlNode *data = NULL;
    xmlNode *output = NULL;
    stonith_history_t *last = NULL;

    *history = NULL;

    if (node) {
        data = create_xml_node(NULL, __FUNCTION__);
        crm_xml_add(data, F_STONITH_TARGET, node);
    }

    rc = stonith_send_command(stonith, STONITH_OP_FENCE_HISTORY, data, &output,
                              call_options | st_opt_sync_call, timeout);
    free_xml(data);

    if (rc == 0) {
        xmlNode *op = NULL;
        xmlNode *reply = get_xpath_object("//" F_STONITH_HISTORY_LIST, output, LOG_ERR);

        for (op = __xml_first_child(reply); op != NULL; op = __xml_next(op)) {
            stonith_history_t *kvp;

            kvp = calloc(1, sizeof(stonith_history_t));
            kvp->target = crm_element_value_copy(op, F_STONITH_TARGET);
            kvp->action = crm_element_value_copy(op, F_STONITH_ACTION);
            kvp->origin = crm_element_value_copy(op, F_STONITH_ORIGIN);
            kvp->delegate = crm_element_value_copy(op, F_STONITH_DELEGATE);
            crm_element_value_int(op, F_STONITH_DATE, &kvp->completed);
            crm_element_value_int(op, F_STONITH_STATE, &kvp->state);

            if (last) {
                last->next = kvp;
            } else {
                *history = kvp;
            }
            last = kvp;
        }
    }
    return rc;
}

const char *
stonith_error2string(enum stonith_errors return_code)
{
    const char *error_msg = NULL;

    switch (return_code) {
        case stonith_ok:
            error_msg = "OK";
            break;
        case st_err_not_supported:
            error_msg = "Not supported";
            break;
        case st_err_authentication:
            error_msg = "Not authenticated";
            break;
        case st_err_generic:
            error_msg = "Generic error";
            break;
        case st_err_internal:
            error_msg = "Internal error";
            break;
        case st_err_unknown_device:
            error_msg = "Unknown device";
            break;
        case st_err_unknown_operation:
            error_msg = "Unknown operation";
            break;
        case st_err_unknown_port:
            error_msg = "Unknown victim";
            break;
        case st_err_none_available:
            error_msg = "No available fencing devices";
            break;
        case st_err_connection:
            error_msg = "Not connected";
            break;
        case st_err_missing:
            error_msg = "Missing input";
            break;
        case st_err_exists:
            error_msg = "Device exists";
            break;
        case st_err_timeout:
            error_msg = "Operation timed out";
            break;
        case st_err_signal:
            error_msg = "Killed by signal";
            break;
        case st_err_ipc:
            error_msg = "IPC connection failed";
            break;
        case st_err_peer:
            error_msg = "Error from peer";
            break;
        case stonith_pending:
            error_msg = "Stonith operation is in progress";
            break;
        case st_err_agent_fork:
            error_msg = "Call to fork() failed";
            break;
        case st_err_agent_args:
            error_msg = "Could not send arguments to the stonith device";
            break;
        case st_err_agent:
            error_msg = "Execution of the stonith agent failed";
            break;
        case st_err_invalid_target:
            error_msg = "Invalid target";
            break;
        case st_err_invalid_level:
            error_msg = "Invalid fencing level specified";
            break;
    }

    if (error_msg == NULL) {
        crm_err("Unknown Stonith error code: %d", return_code);
        error_msg = "<unknown error>";
    }

    return error_msg;
}

gboolean
is_redhat_agent(const char *agent)
{
    int rc = 0;
    struct stat prop;
    char buffer[FILENAME_MAX + 1];

    snprintf(buffer, FILENAME_MAX, "%s/%s", RH_STONITH_DIR, agent);
    rc = stat(buffer, &prop);
    if (rc >= 0 && S_ISREG(prop.st_mode)) {
        return TRUE;
    }
    return FALSE;
}

const char *
get_stonith_provider(const char *agent, const char *provider)
{
    /* This function sucks */
    if (is_redhat_agent(agent)) {
        return "redhat";

    } else {
        Stonith *stonith_obj = stonith_new(agent);

        if (stonith_obj) {
            stonith_delete(stonith_obj);
            return "heartbeat";
        }
    }

    crm_err("No such device: %s", agent);
    return NULL;
}

static gint
stonithlib_GCompareFunc(gconstpointer a, gconstpointer b)
{
    int rc = 0;
    const stonith_notify_client_t *a_client = a;
    const stonith_notify_client_t *b_client = b;

    CRM_CHECK(a_client->event != NULL && b_client->event != NULL, return 0);
    rc = strcmp(a_client->event, b_client->event);
    if (rc == 0) {
        if (a_client->notify == NULL || b_client->notify == NULL) {
            return 0;

        } else if (a_client->notify == b_client->notify) {
            return 0;

        } else if (((long)a_client->notify) < ((long)b_client->notify)) {
            crm_err("callbacks for %s are not equal: %p vs. %p",
                    a_client->event, a_client->notify, b_client->notify);
            return -1;
        }
        crm_err("callbacks for %s are not equal: %p vs. %p",
                a_client->event, a_client->notify, b_client->notify);
        return 1;
    }
    return rc;
}

xmlNode *
stonith_create_op(int call_id, const char *token, const char *op, xmlNode * data, int call_options)
{
    int rc = HA_OK;
    xmlNode *op_msg = create_xml_node(NULL, "stonith_command");

    CRM_CHECK(op_msg != NULL, return NULL);
    CRM_CHECK(token != NULL, return NULL);

    crm_xml_add(op_msg, F_XML_TAGNAME, "stonith_command");

    crm_xml_add(op_msg, F_TYPE, T_STONITH_NG);
    crm_xml_add(op_msg, F_STONITH_CALLBACK_TOKEN, token);
    crm_xml_add(op_msg, F_STONITH_OPERATION, op);
    crm_xml_add_int(op_msg, F_STONITH_CALLID, call_id);
    crm_trace("Sending call options: %.8lx, %d", (long)call_options, call_options);
    crm_xml_add_int(op_msg, F_STONITH_CALLOPTS, call_options);

    if (data != NULL) {
        add_message_xml(op_msg, F_STONITH_CALLDATA, data);
    }

    if (rc != HA_OK) {
        crm_err("Failed to create STONITH operation message");
        crm_log_xml_err(op_msg, "BadOp");
        free_xml(op_msg);
        return NULL;
    }

    return op_msg;
}

static void
stonith_destroy_op_callback(gpointer data)
{
    stonith_callback_client_t *blob = data;

    if (blob->timer && blob->timer->ref > 0) {
        g_source_remove(blob->timer->ref);
    }
    free(blob->timer);
    free(blob);
}

static int
stonith_api_signoff(stonith_t * stonith)
{
    stonith_private_t *native = stonith->private;

    crm_debug("Signing out of the STONITH Service");

    if (native->ipc != NULL) {
        /* If attached to mainloop and it is active, _close() will result in:
         *  - the source being removed from mainloop
         *  - the dnotify callback being invoked
         * Otherwise, we are at least correctly disconnecting IPC
         */
        crm_ipc_close(native->ipc);
        crm_ipc_destroy(native->ipc);
        native->source = NULL;
        native->ipc = NULL;
    }

    stonith->state = stonith_disconnected;
    return stonith_ok;
}

static int
stonith_api_signon(stonith_t * stonith, const char *name, int *stonith_fd)
{
    int rc = stonith_ok;
    stonith_private_t *native = stonith->private;
    static struct ipc_client_callbacks st_callbacks = 
        {
            .dispatch = stonith_dispatch_internal,
            .destroy = stonith_connection_destroy
        };

    crm_trace("Connecting command channel");

    stonith->state = stonith_connected_command;
    if(stonith_fd) {
        /* No mainloop */
        native->ipc = crm_ipc_new("stonith-ng", 0);
        
        if(native->ipc && crm_ipc_connect(native->ipc)) {
            *stonith_fd = crm_ipc_get_fd(native->ipc);

        } else if(native->ipc) {
            rc = st_err_connection;
        }

    } else {
        /* With mainloop */
        native->source = mainloop_add_ipc_client("stonith-ng", 0, stonith, &st_callbacks);
        native->ipc = mainloop_get_ipc_client(native->source);
    }
    
    if (native->ipc == NULL) {
        crm_debug("Could not connect to the Stonith API");
        rc = st_err_connection;
    }

    if (rc == stonith_ok) {
        xmlNode *reply = NULL;
        xmlNode *hello = create_xml_node(NULL, "stonith_command");

        crm_xml_add(hello, F_TYPE, T_STONITH_NG);
        crm_xml_add(hello, F_STONITH_OPERATION, CRM_OP_REGISTER);
        crm_xml_add(hello, F_STONITH_CLIENTNAME, name);
        rc = crm_ipc_send(native->ipc, hello, &reply, -1);

        if(rc < 0) {
            crm_perror(LOG_DEBUG, "Couldn't complete registration with the fencing API: %d", rc);
            rc = st_err_ipc;

        } else if(reply == NULL) {
            crm_err("Did not receive registration reply");
            rc = st_err_internal;

        } else {
            const char *msg_type = crm_element_value(reply, F_STONITH_OPERATION);
            const char *tmp_ticket = crm_element_value(reply, F_STONITH_CLIENTID);
            
            if (safe_str_neq(msg_type, CRM_OP_REGISTER)) {
                crm_err("Invalid registration message: %s", msg_type);
                crm_log_xml_err(reply, "Bad reply");
                rc = st_err_internal;
                
            } else if (tmp_ticket == NULL) {
                crm_err("No registration token provided");
                crm_log_xml_err(reply, "Bad reply");
                rc = st_err_internal;
                
            } else {
                crm_trace("Obtained registration token: %s", tmp_ticket);
                native->token = crm_strdup(tmp_ticket);
                rc = stonith_ok;
            }
        }
        
        free_xml(reply);
        free_xml(hello);
    }

    if (rc == stonith_ok) {
#if HAVE_MSGFROMIPC_TIMEOUT
        stonith->call_timeout = MAX_IPC_DELAY;
#endif
        crm_debug("Connection to STONITH successful");
        return stonith_ok;
    }

    crm_debug("Connection to STONITH failed: %s", stonith_error2string(rc));
    stonith->cmds->disconnect(stonith);
    return rc;
}

static int
stonith_set_notification(stonith_t * stonith, const char *callback, int enabled)
{
    xmlNode *notify_msg = create_xml_node(NULL, __FUNCTION__);
    stonith_private_t *native = stonith->private;

    if (stonith->state != stonith_disconnected) {
        int rc;

        crm_xml_add(notify_msg, F_STONITH_OPERATION, T_STONITH_NOTIFY);
        if (enabled) {
            crm_xml_add(notify_msg, F_STONITH_NOTIFY_ACTIVATE, callback);
        } else {
            crm_xml_add(notify_msg, F_STONITH_NOTIFY_DEACTIVATE, callback);
        }
        rc = crm_ipc_send(native->ipc, notify_msg, NULL, -1);
        if(rc < 0) {
            crm_perror(LOG_DEBUG, "Couldn't register for fencing notifications: %d", rc);
            rc = st_err_ipc;
        }
    }

    free_xml(notify_msg);
    return stonith_ok;
}

static int
stonith_api_add_notification(stonith_t * stonith, const char *event,
                             void (*callback) (stonith_t * stonith, const char *event,
                                               xmlNode * msg))
{
    GList *list_item = NULL;
    stonith_notify_client_t *new_client = NULL;
    stonith_private_t *private = NULL;

    private = stonith->private;
    crm_trace("Adding callback for %s events (%d)", event, g_list_length(private->notify_list));

    new_client = calloc(1, sizeof(stonith_notify_client_t));
    new_client->event = event;
    new_client->notify = callback;

    list_item = g_list_find_custom(private->notify_list, new_client, stonithlib_GCompareFunc);

    if (list_item != NULL) {
        crm_warn("Callback already present");
        free(new_client);
        return st_err_exists;

    } else {
        private->notify_list = g_list_append(private->notify_list, new_client);

        stonith_set_notification(stonith, event, 1);

        crm_trace("Callback added (%d)", g_list_length(private->notify_list));
    }
    return stonith_ok;
}

static int
stonith_api_del_notification(stonith_t * stonith, const char *event)
{
    GList *list_item = NULL;
    stonith_notify_client_t *new_client = NULL;
    stonith_private_t *private = NULL;

    crm_debug("Removing callback for %s events", event);

    private = stonith->private;
    new_client = calloc(1, sizeof(stonith_notify_client_t));
    new_client->event = event;
    new_client->notify = NULL;

    list_item = g_list_find_custom(private->notify_list, new_client, stonithlib_GCompareFunc);

    stonith_set_notification(stonith, event, 0);

    if (list_item != NULL) {
        stonith_notify_client_t *list_client = list_item->data;

        private->notify_list = g_list_remove(private->notify_list, list_client);
        free(list_client);

        crm_trace("Removed callback");

    } else {
        crm_trace("Callback not present");
    }
    free(new_client);
    return stonith_ok;
}

static gboolean
stonith_async_timeout_handler(gpointer data)
{
    struct timer_rec_s *timer = data;

    crm_err("Async call %d timed out after %dms", timer->call_id, timer->timeout);
    stonith_perform_callback(timer->stonith, NULL, timer->call_id, st_err_timeout);

    /* Always return TRUE, never remove the handler
     * We do that in stonith_del_callback()
     */
    return TRUE;
}

static int
stonith_api_add_callback(stonith_t * stonith, int call_id, int timeout, bool only_success,
                         void *user_data, const char *callback_name,
                         void (*callback) (stonith_t * st, const xmlNode * msg, int call, int rc,
                                           xmlNode * output, void *userdata))
{
    stonith_callback_client_t *blob = NULL;
    stonith_private_t *private = NULL;

    CRM_CHECK(stonith != NULL, return st_err_missing);
    CRM_CHECK(stonith->private != NULL, return st_err_missing);
    private = stonith->private;

    if (call_id == 0) {
        private->op_callback = callback;

    } else if (call_id < 0) {
        if (only_success == FALSE) {
            crm_trace("Call failed, calling %s: %s",
                      callback_name, stonith_error2string(call_id));
            callback(stonith, NULL, call_id, call_id, NULL, user_data);
        } else {
            crm_warn("STONITH call failed: %s", stonith_error2string(call_id));
        }
        return FALSE;
    }

    blob = calloc(1, sizeof(stonith_callback_client_t));
    blob->id = callback_name;
    blob->only_success = only_success;
    blob->user_data = user_data;
    blob->callback = callback;

    if (timeout > 0) {
        struct timer_rec_s *async_timer = NULL;

        async_timer = calloc(1, sizeof(struct timer_rec_s));
        blob->timer = async_timer;

        async_timer->stonith = stonith;
        async_timer->call_id = call_id;
        /* Allow a fair bit of grace to allow the server to tell us of a timeout
         * This is only a fallback
         */
        async_timer->timeout = (timeout + 60) * 1000;
        async_timer->ref =
            g_timeout_add(async_timer->timeout, stonith_async_timeout_handler, async_timer);
    }

    g_hash_table_insert(private->stonith_op_callback_table, GINT_TO_POINTER(call_id), blob);
    crm_trace("Added callback to %s for call %d", callback_name, call_id);

    return TRUE;
}

static int
stonith_api_del_callback(stonith_t * stonith, int call_id, bool all_callbacks)
{
    stonith_private_t *private = stonith->private;

    if (all_callbacks) {
        private->op_callback = NULL;
        g_hash_table_destroy(private->stonith_op_callback_table);
        private->stonith_op_callback_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                                                   NULL,
                                                                   stonith_destroy_op_callback);

    } else if (call_id == 0) {
        private->op_callback = NULL;

    } else {
        g_hash_table_remove(private->stonith_op_callback_table, GINT_TO_POINTER(call_id));
    }
    return stonith_ok;
}

static void
stonith_dump_pending_op(gpointer key, gpointer value, gpointer user_data)
{
    int call = GPOINTER_TO_INT(key);
    stonith_callback_client_t *blob = value;

    crm_debug("Call %d (%s): pending", call, crm_str(blob->id));
}

void
stonith_dump_pending_callbacks(stonith_t * stonith)
{
    stonith_private_t *private = stonith->private;

    if (private->stonith_op_callback_table == NULL) {
        return;
    }
    return g_hash_table_foreach(private->stonith_op_callback_table, stonith_dump_pending_op, NULL);
}

void
stonith_perform_callback(stonith_t * stonith, xmlNode * msg, int call_id, int rc)
{
    xmlNode *output = NULL;
    stonith_private_t *private = NULL;
    stonith_callback_client_t *blob = NULL;
    stonith_callback_client_t local_blob;

    CRM_CHECK(stonith != NULL, return);
    CRM_CHECK(stonith->private != NULL, return);

    private = stonith->private;

    local_blob.id = NULL;
    local_blob.callback = NULL;
    local_blob.user_data = NULL;
    local_blob.only_success = FALSE;

    if (msg != NULL) {
        crm_element_value_int(msg, F_STONITH_RC, &rc);
        crm_element_value_int(msg, F_STONITH_CALLID, &call_id);
        output = get_message_xml(msg, F_STONITH_CALLDATA);
    }

    CRM_CHECK(call_id > 0, crm_log_xml_err(msg, "Bad result"));

    blob = g_hash_table_lookup(private->stonith_op_callback_table, GINT_TO_POINTER(call_id));

    if (blob != NULL) {
        local_blob = *blob;
        blob = NULL;

        stonith_api_del_callback(stonith, call_id, FALSE);

    } else {
        crm_trace("No callback found for call %d", call_id);
        local_blob.callback = NULL;
    }

    if (stonith == NULL) {
        crm_debug("No stonith object supplied");
    }

    if (local_blob.callback != NULL && (rc == stonith_ok || local_blob.only_success == FALSE)) {
        crm_trace("Invoking callback %s for call %d", crm_str(local_blob.id), call_id);
        local_blob.callback(stonith, msg, call_id, rc, output, local_blob.user_data);

    } else if (private->op_callback == NULL && rc != stonith_ok) {
        crm_warn("STONITH command failed: %s", stonith_error2string(rc));
        crm_log_xml_debug(msg, "Failed STONITH Update");
    }

    if (private->op_callback != NULL) {
        crm_trace("Invoking global callback for call %d", call_id);
        private->op_callback(stonith, msg, call_id, rc, output, NULL);
    }
    crm_trace("OP callback activated.");
}

static void
stonith_send_notification(gpointer data, gpointer user_data)
{
    struct notify_blob_s *blob = user_data;
    stonith_notify_client_t *entry = data;
    const char *event = NULL;

    if (blob->xml == NULL) {
        crm_warn("Skipping callback - NULL message");
        return;
    }

    event = crm_element_value(blob->xml, F_SUBTYPE);

    if (entry == NULL) {
        crm_warn("Skipping callback - NULL callback client");
        return;

    } else if (entry->notify == NULL) {
        crm_warn("Skipping callback - NULL callback");
        return;

    } else if (safe_str_neq(entry->event, event)) {
        crm_trace("Skipping callback - event mismatch %p/%s vs. %s", entry, entry->event, event);
        return;
    }

    crm_trace("Invoking callback for %p/%s event...", entry, event);
    entry->notify(blob->stonith, event, blob->xml);
    crm_trace("Callback invoked...");
}

int
stonith_send_command(stonith_t * stonith, const char *op, xmlNode * data, xmlNode ** output_data,
                     int call_options, int timeout)
{
    int rc = 0;
    int reply_id = -1;

    xmlNode *op_msg = NULL;
    xmlNode *op_reply = NULL;

    stonith_private_t *native = stonith->private;

    if (stonith->state == stonith_disconnected) {
        return st_err_connection;
    }

    if (output_data != NULL) {
        *output_data = NULL;
    }

    if (op == NULL) {
        crm_err("No operation specified");
        return st_err_missing;
    }

    stonith->call_id++;
    /* prevent call_id from being negative (or zero) and conflicting
     *    with the stonith_errors enum
     * use 2 because we use it as (stonith->call_id - 1) below
     */
    if (stonith->call_id < 1) {
        stonith->call_id = 1;
    }

    CRM_CHECK(native->token != NULL,;);
    op_msg = stonith_create_op(stonith->call_id, native->token, op, data, call_options);
    if (op_msg == NULL) {
        return st_err_missing;
    }

    crm_xml_add_int(op_msg, F_STONITH_TIMEOUT, timeout);
    crm_trace("Sending %s message to STONITH service, Timeout: %ds", op, timeout);

    rc = crm_ipc_send(native->ipc, op_msg, &op_reply, 1000*(timeout + 60));
    free_xml(op_msg);

    if(rc < 0) {
        crm_perror(LOG_ERR, "Couldn't perform %s operation (timeout=%ds): %d", op, timeout, rc);
        rc = st_err_ipc;
        goto done;
    }

    crm_log_xml_trace(op_reply, "Reply");
    
    if (!(call_options & st_opt_sync_call)) {
        crm_trace("Async call %d, returning", stonith->call_id);
        CRM_CHECK(stonith->call_id != 0, return st_err_internal);
        free_xml(op_reply);

        return stonith->call_id;
    }

    rc = stonith_ok;
    crm_element_value_int(op_reply, F_STONITH_CALLID, &reply_id);

    if (reply_id == stonith->call_id) {
        crm_trace("Syncronous reply %d received", reply_id);

        if (crm_element_value_int(op_reply, F_STONITH_RC, &rc) != 0) {
            rc = st_err_peer;
        }

        if ((call_options & st_opt_discard_reply) || output_data == NULL) {
            crm_trace("Discarding reply");

        } else {
            *output_data = op_reply;
            op_reply = NULL; /* Prevent subsequent free */
        }
        
    } else if (reply_id <= 0) {
        crm_err("Recieved bad reply: No id set");
        crm_log_xml_err(op_reply, "Bad reply");
        free_xml(op_reply);
        rc = st_err_peer;
        
    } else {
        crm_err("Recieved bad reply: %d (wanted %d)", reply_id, stonith->call_id);
        crm_log_xml_err(op_reply, "Old reply");
        free_xml(op_reply);
        rc = st_err_peer;
    }

  done:
    if (crm_ipc_connected(native->ipc) == FALSE) {
        crm_err("STONITH disconnected");
        stonith->state = stonith_disconnected;
    }

    free_xml(op_reply);
    return rc;
}

/* Not used with mainloop */
bool
stonith_dispatch(stonith_t * st)
{
    gboolean stay_connected = TRUE;
    stonith_private_t *private = NULL;

    CRM_ASSERT(st != NULL);
    private = st->private;
    
    while(crm_ipc_ready(private->ipc)) {

        if(crm_ipc_read(private->ipc) > 0) {
            const char *msg = crm_ipc_buffer(private->ipc);
            stonith_dispatch_internal(msg, strlen(msg), st);
        }

        if(crm_ipc_connected(private->ipc) == FALSE) {
            crm_err("Connection closed");
            stay_connected = FALSE;
        }
    }

    return stay_connected;
}

int
stonith_dispatch_internal(const char *buffer, ssize_t length, gpointer userdata)
{
    const char *type = NULL;
    struct notify_blob_s blob;

    stonith_t * st = userdata;
    stonith_private_t *private = NULL;

    CRM_ASSERT(st != NULL);
    private = st->private;

    blob.xml = string2xml(buffer);
    if (blob.xml == NULL) {
        crm_warn("Received a NULL msg from STONITH service: %s.", buffer);
        return 0;
    }

    /* do callbacks */
    type = crm_element_value(blob.xml, F_TYPE);
    crm_trace("Activating %s callbacks...", type);

    if (safe_str_eq(type, T_STONITH_NG)) {
        stonith_perform_callback(st, blob.xml, 0, 0);

    } else if (safe_str_eq(type, T_STONITH_NOTIFY)) {
        g_list_foreach(private->notify_list, stonith_send_notification, &blob);

    } else {
        crm_err("Unknown message type: %s", type);
        crm_log_xml_warn(blob.xml, "BadReply");
    }

    free_xml(blob.xml);
    return 1;
}

static int
stonith_api_free(stonith_t * stonith)
{
    int rc = stonith_ok;

    if (stonith->state != stonith_disconnected) {
        rc = stonith->cmds->disconnect(stonith);
    }

    if (stonith->state == stonith_disconnected) {
        stonith_private_t *private = stonith->private;

        g_hash_table_destroy(private->stonith_op_callback_table);
        free(private->token);
        free(stonith->private);
        free(stonith->cmds);
        free(stonith);
    }

    return rc;
}

void
stonith_api_delete(stonith_t * stonith)
{
    stonith_private_t *private = stonith->private;
    GList *list = private->notify_list;

    while (list != NULL) {
        stonith_notify_client_t *client = g_list_nth_data(list, 0);

        list = g_list_remove(list, client);
        free(client);
    }

    stonith->cmds->free(stonith);
    stonith = NULL;
}

stonith_t *
stonith_api_new(void)
{
    stonith_t *new_stonith = NULL;
    stonith_private_t *private = NULL;

    new_stonith = calloc(1, sizeof(stonith_t));
    private = calloc(1, sizeof(stonith_private_t));
    new_stonith->private = private;

    private->stonith_op_callback_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                                               NULL, stonith_destroy_op_callback);
    private->notify_list = NULL;

    new_stonith->call_id = 1;
    new_stonith->state = stonith_disconnected;

    new_stonith->cmds = calloc(1, sizeof(stonith_api_operations_t));

/* *INDENT-OFF* */
    new_stonith->cmds->free       = stonith_api_free;
    new_stonith->cmds->connect    = stonith_api_signon;
    new_stonith->cmds->disconnect = stonith_api_signoff;
    
    new_stonith->cmds->call       = stonith_api_call;
    new_stonith->cmds->fence      = stonith_api_fence;
    new_stonith->cmds->confirm    = stonith_api_confirm;
    new_stonith->cmds->history    = stonith_api_history;

    new_stonith->cmds->list       = stonith_api_device_list;
    new_stonith->cmds->metadata   = stonith_api_device_metadata;

    new_stonith->cmds->query           = stonith_api_query;
    new_stonith->cmds->remove_device   = stonith_api_remove_device;
    new_stonith->cmds->register_device = stonith_api_register_device;

    new_stonith->cmds->remove_level    = stonith_api_remove_level;
    new_stonith->cmds->register_level  = stonith_api_register_level;
    
    new_stonith->cmds->remove_callback       = stonith_api_del_callback;	
    new_stonith->cmds->register_callback     = stonith_api_add_callback;	
    new_stonith->cmds->remove_notification   = stonith_api_del_notification;
    new_stonith->cmds->register_notification = stonith_api_add_notification;
/* *INDENT-ON* */

    return new_stonith;
}

stonith_key_value_t *
stonith_key_value_add(stonith_key_value_t * head, const char *key, const char *value)
{
    stonith_key_value_t *p, *end;

    p = calloc(1, sizeof(stonith_key_value_t));
    if (key) {
        p->key = crm_strdup(key);
    }
    if (value) {
        p->value = crm_strdup(value);
    }

    end = head;
    while (end && end->next) {
        end = end->next;
    }

    if (end) {
        end->next = p;
    } else {
        head = p;
    }

    return head;
}

void
stonith_key_value_freeall(stonith_key_value_t * head, int keys, int values)
{
    stonith_key_value_t *p;

    while (head) {
        p = head->next;
        if (keys) {
            free(head->key);
        }
        if (values) {
            free(head->value);
        }
        free(head);
        head = p;
    }
}

int
stonith_api_kick(int nodeid, const char *uname, int timeout, bool off)
{
    char *name = NULL;
    const char *action = "reboot";

    int rc = st_err_internal;
    stonith_t *st = NULL;
    enum stonith_call_options opts = st_opt_sync_call | st_opt_allow_suicide;

    st = stonith_api_new();
    if (st) {
        rc = st->cmds->connect(st, "stonith-api", NULL);
    }

    if (uname != NULL) {
        name = strdup(uname);

    } else if (nodeid > 0) {
        opts |= st_opt_cs_nodeid;
        name = crm_itoa(nodeid);
    }

    if (off) {
        action = "off";
    }

    if (rc == stonith_ok) {
        rc = st->cmds->fence(st, opts, name, action, timeout);
    }

    if (st) {
        st->cmds->disconnect(st);
        stonith_api_delete(st);
    }

    free(name);
    return rc;
}

time_t
stonith_api_time(int nodeid, const char *uname, bool in_progress)
{
    int rc = 0;
    char *name = NULL;

    time_t when = 0;
    time_t progress = 0;
    stonith_t *st = NULL;
    stonith_history_t *history, *hp = NULL;
    enum stonith_call_options opts = st_opt_sync_call;

    st = stonith_api_new();
    if (st) {
        rc = st->cmds->connect(st, "stonith-api", NULL);
    }

    if (uname != NULL) {
        name = strdup(uname);

    } else if (nodeid > 0) {
        opts |= st_opt_cs_nodeid;
        name = crm_itoa(nodeid);
    }

    if (st && rc == stonith_ok) {
        st->cmds->history(st, st_opt_sync_call | st_opt_cs_nodeid, name, &history, 120);

        for (hp = history; hp; hp = hp->next) {
            if (in_progress) {
                if (hp->state != st_done && hp->state != st_failed) {
                    progress = time(NULL);
                }

            } else if (hp->state == st_done) {
                when = hp->completed;
            }
        }
    }

    if (progress) {
        when = progress;
    }

    if (st) {
        st->cmds->disconnect(st);
        stonith_api_delete(st);
    }

    free(name);
    return when;
}
