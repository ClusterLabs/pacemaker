/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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
#ifndef STONITH_NG__H
#  define STONITH_NG__H

#  include <dlfcn.h>
#  include <stdbool.h>

/* TO-DO: Work out how to drop this requirement */
#  include <libxml/tree.h>

#define T_STONITH_NOTIFY_DISCONNECT     "st_notify_disconnect"
#define T_STONITH_NOTIFY_FENCE          "st_notify_fence"

/* *INDENT-OFF* */
enum stonith_state {
    stonith_connected_command,
    stonith_connected_query,
    stonith_disconnected,
};

enum stonith_call_options {
    st_opt_none            = 0x00000000,
    st_opt_verbose         = 0x00000001,
    st_opt_allow_suicide   = 0x00000002,

    st_opt_manual_ack      = 0x00000008,
    st_opt_discard_reply   = 0x00000010,
    st_opt_all_replies     = 0x00000020,
    st_opt_topology        = 0x00000040,
    st_opt_scope_local     = 0x00000100,
    st_opt_cs_nodeid       = 0x00000200,
    st_opt_sync_call       = 0x00001000,
};

#define stonith_default_options = stonith_none

enum op_state
{
    st_query,
    st_exec,
    st_done,
    st_failed,
};

typedef struct stonith_key_value_s {
    char *key;
    char *value;
        struct stonith_key_value_s *next;
} stonith_key_value_t;

typedef struct stonith_history_s {
    char *target;
    char *action;
    char *origin;
    char *delegate;
    int completed;
    int state;

    struct stonith_history_s *next;
} stonith_history_t;

typedef struct stonith_s stonith_t;

typedef struct stonith_event_s
{
    char *id;
    char *type;
    char *message;
    char *operation;

    int result;
    char *origin;
    char *target;
    char *executioner;

    char *device;

    /*! The name of the client that initiated the action. */
    char *client_origin;

} stonith_event_t;

typedef struct stonith_api_operations_s
{
    /*!
     * \brief Destroy the stonith api structure.
     */
    int (*free) (stonith_t *st);

    /*!
     * \brief Connect to the local stonith daemon.
     *
     * \retval 0, success
     * \retval negative error code on failure
     */
    int (*connect) (stonith_t *st, const char *name, int *stonith_fd);

    /*!
     * \brief Disconnect from the local stonith daemon.
     *
     * \retval 0, success
     * \retval negative error code on failure
     */
    int (*disconnect)(stonith_t *st);

    /*!
     * \brief Remove a registered stonith device with the local stonith daemon.
     *
     * \note Synchronous, guaranteed to occur in daemon before function returns.
     *
     * \retval 0, success
     * \retval negative error code on failure
     */
    int (*remove_device)(
        stonith_t *st, int options, const char *name);

    /*!
     * \brief Register a stonith device with the local stonith daemon.
     *
     * \note Synchronous, guaranteed to occur in daemon before function returns.
     *
     * \retval 0, success
     * \retval negative error code on failure
     */
    int (*register_device)(
        stonith_t *st, int options, const char *id,
        const char *namespace, const char *agent, stonith_key_value_t *params);

    /*!
     * \brief Remove a fencing level for a specific node.
     *
     * \note This feature is not available when stonith is in standalone mode.
     *
     * \retval 0, success
     * \retval negative error code on failure
     */
    int (*remove_level)(
        stonith_t *st, int options, const char *node, int level);

    /*!
     * \brief Register a fencing level containing the fencing devices to be used
     *        at that level for a specific node.
     *
     * \note This feature is not available when stonith is in standalone mode.
     *
     * \retval 0, success
     * \retval negative error code on failure
     */
    int (*register_level)(
        stonith_t *st, int options, const char *node, int level, stonith_key_value_t *device_list);

    /*!
     * \brief Get the metadata documentation for a resource.
     *
     * \note Value is returned in output.  Output must be freed when set.
     *
     * \retval 0 success
     * \retval negative error code on failure
     */
    int (*metadata)(stonith_t *st, int options,
            const char *device, const char *namespace, char **output, int timeout);

    /*!
     * \brief Retrieve a list of installed stonith agents
     *
     * \note if namespace is not provided, all known agents will be returned
     * \note list must be freed using stonith_key_value_freeall()
     * \note call_options parameter is not used, it is reserved for future use.
     *
     * \retval num items in list on success
     * \retval negative error code on failure
     */
    int (*list_agents)(stonith_t *stonith, int call_options, const char *namespace,
            stonith_key_value_t **devices, int timeout);

    /*!
     * \brief Retrieve string listing hosts and port assignments from a local stonith device.
     *
     * \retval 0 on success
     * \retval negative error code on failure
     */
    int (*list)(stonith_t *st, int options, const char *id, char **list_output, int timeout);

    /*!
     * \brief Check to see if a local stonith device is reachable
     *
     * \retval 0 on success
     * \retval negative error code on failure
     */
    int (*monitor)(stonith_t *st, int options, const char *id, int timeout);

    /*!
     * \brief Check to see if a local stonith device's port is reachable
     *
     * \retval 0 on success
     * \retval negative error code on failure
     */
    int (*status)(stonith_t *st, int options, const char *id, const char *port, int timeout);

    /*!
     * \brief Retrieve a list of registered stonith devices.
     *
     * \note If node is provided, only devices that can fence the node id
     *       will be returned.
     *
     * \retval num items in list on success
     * \retval negative error code on failure
     */
    int (*query)(stonith_t *st, int options, const char *node,
            stonith_key_value_t **devices, int timeout);

    /*!
     * \brief Issue a fencing action against a node.
     *
     * \note Possible actions are, 'on', 'off', and 'reboot'.
     *
     * \retval 0 success
     * \retval negative error code on failure.
     */
    int (*fence)(stonith_t *st, int options, const char *node, const char *action,
            int timeout);

    /*!
     * \brief Manually confirm that a node is down.
     *
     * \retval 0 success
     * \retval negative error code on failure.
     */
    int (*confirm)(stonith_t *st, int options, const char *node);

    /*!
     * \brief Retrieve a list of fencing operations that have occurred for a specific node.
     *
     * \note History is not available in standalone mode.
     *
     * \retval 0 success
     * \retval negative error code on failure.
     */
    int (*history)(stonith_t *st, int options, const char *node, stonith_history_t **output, int timeout);

    int (*register_notification)(
        stonith_t *st, const char *event,
        void (*notify)(stonith_t *st, stonith_event_t *e));
    int (*remove_notification)(stonith_t *st, const char *event);

    int (*register_callback)(
        stonith_t *st, int call_id, int timeout, bool only_success,
        void *userdata, const char *callback_name,
        void (*callback)(stonith_t *st, const xmlNode *msg, int call, int rc, xmlNode *output, void *userdata));
    int (*remove_callback)(stonith_t *st, int call_id, bool all_callbacks);

} stonith_api_operations_t;

struct stonith_s
{
    enum stonith_state state;

    int call_id;
    int call_timeout;
    void *private;

    stonith_api_operations_t *cmds;
};
/* *INDENT-ON* */

/* Core functions */
stonith_t *stonith_api_new(void);
void stonith_api_delete(stonith_t * st);

void stonith_dump_pending_callbacks(stonith_t * st);

const char *get_stonith_provider(const char *agent, const char *provider);

bool stonith_dispatch(stonith_t * st);

stonith_key_value_t *stonith_key_value_add(stonith_key_value_t * kvp, const char *key,
                                                  const char *value);
void stonith_key_value_freeall(stonith_key_value_t * kvp, int keys, int values);

/* Basic helpers that allows nodes to be fenced and the history to be
 * queried without mainloop or the caller understanding the full API
 *
 * At least one of nodeid and uname are required
 */
int stonith_api_kick(int nodeid, const char *uname, int timeout, bool off);
time_t stonith_api_time(int nodeid, const char *uname, bool in_progress);

/*
 * Helpers for using the above functions without install-time dependancies
 *
 * Usage:
 *  #include <crm/stonith-ng.h>
 *
 * To turn a node off by corosync nodeid:
 *  stonith_api_kick_helper(nodeid, 120, 1);
 *
 * To check the last fence date/time (also by nodeid):
 *  last = stonith_api_time_helper(nodeid, 0);
 *
 * To check if fencing is in progress:
 *  if(stonith_api_time_helper(nodeid, 1) > 0) { ... }
 *
 * eg.

 #include <stdio.h>
 #include <time.h>
 #include <crm/stonith-ng.h>
 int
 main(int argc, char ** argv)
 {
     int rc = 0;
     int nodeid = 102;

     rc = stonith_api_time_helper(nodeid, 0);
     printf("%d last fenced at %s\n", nodeid, ctime(rc));

     rc = stonith_api_kick_helper(nodeid, 120, 1);
     printf("%d fence result: %d\n", nodeid, rc);

     rc = stonith_api_time_helper(nodeid, 0);
     printf("%d last fenced at %s\n", nodeid, ctime(rc));

     return 0;
 }

 */

#  define STONITH_LIBRARY "libstonithd.so.2"

static inline int
stonith_api_kick_helper(int nodeid, int timeout, bool off)
{
    static void *st_library = NULL;
    static int (*st_kick_fn) (int nodeid, const char *uname, int timeout, bool off) = NULL;

    if (st_library == NULL) {
        st_library = dlopen(STONITH_LIBRARY, RTLD_LAZY);
    }
    if (st_library && st_kick_fn == NULL) {
        st_kick_fn = dlsym(st_library, "stonith_api_kick");
    }
    if (st_kick_fn == NULL) {
        return -ELIBACC;
    }

    return (*st_kick_fn) (nodeid, NULL, timeout, off);
}

static inline time_t
stonith_api_time_helper(int nodeid, bool in_progress)
{
    static void *st_library = NULL;
    static time_t(*st_time_fn) (int nodeid, const char *uname, bool in_progress) = NULL;

    if (st_library == NULL) {
        st_library = dlopen(STONITH_LIBRARY, RTLD_LAZY);
    }
    if (st_library && st_time_fn == NULL) {
        st_time_fn = dlsym(st_library, "stonith_api_time");
    }
    if (st_time_fn == NULL) {
        return 0;
    }

    return (*st_time_fn) (nodeid, NULL, in_progress);
}

#endif
