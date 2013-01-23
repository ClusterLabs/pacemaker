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

#include <crm_internal.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <crm/crm.h>
#include <crm/services.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crmd.h>
#include <crmd_fsa.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>
#include <crmd_lrm.h>

#define START_DELAY_THRESHOLD 5 * 60 * 1000

typedef struct resource_history_s {
    char *id;
    lrmd_rsc_info_t rsc;
    lrmd_event_data_t *last;
    lrmd_event_data_t *failed;
    GList *recurring_op_list;

    /* Resources must be stopped using the same
     * parameters they were started with.  This hashtable
     * holds the parameters that should be used for the next stop
     * cmd on this resource. */
    GHashTable *stop_params;
} rsc_history_t;

struct recurring_op_s {
    char *rsc_id;
    char *op_type;
    char *op_key;
    int call_id;
    int interval;
    gboolean remove;
    gboolean cancelled;
};

struct pending_deletion_op_s {
    char *rsc;
    ha_msg_input_t *input;
};

struct delete_event_s {
    int rc;
    const char *rsc;
};

GHashTable *resource_history = NULL;
GHashTable *pending_ops = NULL;
GHashTable *deletion_ops = NULL;

int num_lrm_register_fails = 0;
int max_lrm_register_fails = 30;

gboolean process_lrm_event(lrmd_event_data_t * op);
gboolean is_rsc_active(const char *rsc_id);
gboolean build_active_RAs(xmlNode * rsc_list);
static gboolean stop_recurring_actions(gpointer key, gpointer value, gpointer user_data);
static int delete_rsc_status(const char *rsc_id, int call_options, const char *user_name);

static lrmd_event_data_t *construct_op(xmlNode * rsc_op, const char *rsc_id, const char *operation);
void do_lrm_rsc_op(lrmd_rsc_info_t * rsc, const char *operation, xmlNode * msg, xmlNode * request);

void send_direct_ack(const char *to_host, const char *to_sys,
                     lrmd_rsc_info_t * rsc, lrmd_event_data_t * op, const char *rsc_id);

static void
lrm_connection_destroy(void)
{
    if (is_set(fsa_input_register, R_LRM_CONNECTED)) {
        crm_crit("LRM Connection failed");
        register_fsa_input(C_FSA_INTERNAL, I_ERROR, NULL);
        clear_bit(fsa_input_register, R_LRM_CONNECTED);

    } else {
        crm_info("LRM Connection disconnected");
    }

}

static void
free_deletion_op(gpointer value)
{
    struct pending_deletion_op_s *op = value;

    free(op->rsc);
    delete_ha_msg_input(op->input);
    free(op);
}

static void
free_recurring_op(gpointer value)
{
    struct recurring_op_s *op = (struct recurring_op_s *)value;

    free(op->rsc_id);
    free(op->op_type);
    free(op->op_key);
    free(op);
}

static char *
make_stop_id(const char *rsc, int call_id)
{
    char *op_id = NULL;

    op_id = calloc(1, strlen(rsc) + 34);
    if (op_id != NULL) {
        snprintf(op_id, strlen(rsc) + 34, "%s:%d", rsc, call_id);
    }
    return op_id;
}

static void
copy_instance_keys(gpointer key, gpointer value, gpointer user_data)
{
    if (strstr(key, CRM_META "_") == NULL) {
        g_hash_table_replace(user_data, strdup((const char *)key), strdup((const char *)value));
    }
}

static void
copy_meta_keys(gpointer key, gpointer value, gpointer user_data)
{
    if (strstr(key, CRM_META "_") != NULL) {
        g_hash_table_replace(user_data, strdup((const char *)key), strdup((const char *)value));
    }
}

static void
history_cache_destroy(gpointer data)
{
    rsc_history_t *entry = data;

    if (entry->stop_params) {
        g_hash_table_destroy(entry->stop_params);
    }

    free(entry->rsc.type);
    free(entry->rsc.class);
    free(entry->rsc.provider);

    lrmd_free_event(entry->failed);
    lrmd_free_event(entry->last);
    free(entry->id);
    free(entry);
}

static void
update_history_cache(lrmd_rsc_info_t * rsc, lrmd_event_data_t * op)
{
    int target_rc = 0;
    rsc_history_t *entry = NULL;

    if (op->rsc_deleted) {
        crm_debug("Purged history for '%s' after %s", op->rsc_id, op->op_type);
        delete_rsc_status(op->rsc_id, cib_quorum_override, NULL);
        return;
    }

    if (safe_str_eq(op->op_type, RSC_NOTIFY)) {
        return;
    }

    crm_debug("Updating history for '%s' with %s op", op->rsc_id, op->op_type);

    entry = g_hash_table_lookup(resource_history, op->rsc_id);
    if (entry == NULL && rsc) {
        entry = calloc(1, sizeof(rsc_history_t));
        entry->id = strdup(op->rsc_id);
        g_hash_table_insert(resource_history, entry->id, entry);

        entry->rsc.id = entry->id;
        entry->rsc.type = strdup(rsc->type);
        entry->rsc.class = strdup(rsc->class);
        if (rsc->provider) {
            entry->rsc.provider = strdup(rsc->provider);
        } else {
            entry->rsc.provider = NULL;
        }

    } else if (entry == NULL) {
        crm_info("Resource %s no longer exists, not updating cache", op->rsc_id);
        return;
    }

    target_rc = rsc_op_expected_rc(op);
    if (op->op_status == PCMK_LRM_OP_CANCELLED) {
        if (op->interval > 0) {
            GList *gIter, *gIterNext;

            crm_trace("Removing cancelled recurring op: %s_%s_%d", op->rsc_id, op->op_type, op->interval);

            for (gIter = entry->recurring_op_list; gIter != NULL; gIter = gIterNext) {
                lrmd_event_data_t *existing = gIter->data;
                gIterNext = gIter->next;

                if (safe_str_eq(op->rsc_id, existing->rsc_id)
                    && safe_str_eq(op->op_type, existing->op_type)
                    && op->interval == existing->interval) {
                    lrmd_free_event(existing);
                    entry->recurring_op_list = g_list_delete_link(entry->recurring_op_list, gIter);
                }
            }
            return;

        } else {
            crm_trace("Skipping %s_%s_%d rc=%d, status=%d", op->rsc_id, op->op_type, op->interval,
                      op->rc, op->op_status);
        }

    } else if (did_rsc_op_fail(op, target_rc)) {
        /* We must store failed monitors here
         * - otherwise the block below will cause them to be forgetten them when a stop happens
         */
        if (entry->failed) {
            lrmd_free_event(entry->failed);
        }
        entry->failed = lrmd_copy_event(op);

    } else if (op->interval == 0) {
        if (entry->last) {
            lrmd_free_event(entry->last);
        }
        entry->last = lrmd_copy_event(op);

        if (op->params &&
            (safe_str_eq(CRMD_ACTION_START, op->op_type) ||
            safe_str_eq(CRMD_ACTION_STATUS, op->op_type))) {

            if (entry->stop_params) {
                g_hash_table_destroy(entry->stop_params);
            }
            entry->stop_params = g_hash_table_new_full(crm_str_hash,
                g_str_equal, g_hash_destroy_str, g_hash_destroy_str);

            g_hash_table_foreach(op->params, copy_instance_keys, entry->stop_params);
        }
    }

    if (op->interval > 0) {
        crm_trace("Adding recurring op: %s_%s_%d", op->rsc_id, op->op_type, op->interval);
        entry->recurring_op_list = g_list_prepend(entry->recurring_op_list, lrmd_copy_event(op));

    } else if (entry->recurring_op_list && safe_str_eq(op->op_type, RSC_STATUS) == FALSE) {
        GList *gIter = entry->recurring_op_list;

        crm_trace("Dropping %d recurring ops because of: %s_%s_%d",
                  g_list_length(gIter), op->rsc_id, op->op_type, op->interval);
        for (; gIter != NULL; gIter = gIter->next) {
            lrmd_free_event(gIter->data);
        }
        g_list_free(entry->recurring_op_list);
        entry->recurring_op_list = NULL;
    }
}

/*	 A_LRM_CONNECT	*/
void
do_lrm_control(long long action,
               enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state,
               enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    if (fsa_lrm_conn == NULL) {
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
        return;
    }

    if (action & A_LRM_DISCONNECT) {
        if (verify_stopped(cur_state, LOG_INFO) == FALSE) {
            if(action == A_LRM_DISCONNECT) {
                crmd_fsa_stall(FALSE);
                return;
            }
        }

        if (fsa_lrm_conn) {
            clear_bit(fsa_input_register, R_LRM_CONNECTED);
            fsa_lrm_conn->cmds->disconnect(fsa_lrm_conn);
        }

        crm_notice("Disconnected from the LRM");
        if(resource_history) {
            g_hash_table_destroy(resource_history);
            resource_history = NULL;
        }
        if(deletion_ops) {
            g_hash_table_destroy(deletion_ops);
            deletion_ops = NULL;
        }
        if(pending_ops) {
            g_hash_table_destroy(pending_ops);
            pending_ops = NULL;
        }
    }

    if (action & A_LRM_CONNECT) {
        int ret = pcmk_ok;

        deletion_ops = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                             g_hash_destroy_str, free_deletion_op);

        pending_ops = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                            g_hash_destroy_str, free_recurring_op);

        resource_history = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                                 NULL, history_cache_destroy);

        crm_debug("Connecting to the LRM");
        ret = fsa_lrm_conn->cmds->connect(fsa_lrm_conn, CRM_SYSTEM_CRMD, NULL);

        if (ret != pcmk_ok) {
            if (++num_lrm_register_fails < max_lrm_register_fails) {
                crm_warn("Failed to sign on to the LRM %d"
                         " (%d max) times", num_lrm_register_fails, max_lrm_register_fails);

                crm_timer_start(wait_timer);
                crmd_fsa_stall(FALSE);
                return;
            }
        }

        if (ret == pcmk_ok) {
            crm_trace("LRM: set_lrm_callback...");
            fsa_lrm_conn->cmds->set_callback(fsa_lrm_conn, lrm_op_callback);
        }

        if (ret != pcmk_ok) {
            crm_err("Failed to sign on to the LRM %d" " (max) times", num_lrm_register_fails);
            register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
            return;
        }

        set_bit(fsa_input_register, R_LRM_CONNECTED);
        crm_debug("LRM connection established");
    }

    if (action & ~(A_LRM_CONNECT | A_LRM_DISCONNECT)) {
        crm_err("Unexpected action %s in %s", fsa_action2string(action), __FUNCTION__);
    }
}

static void
ghash_print_pending(gpointer key, gpointer value, gpointer user_data)
{
    const char *stop_id = key;
    int *log_level = user_data;
    struct recurring_op_s *pending = value;

    do_crm_log(*log_level, "Pending action: %s (%s)", stop_id, pending->op_key);
}

static void
ghash_print_pending_for_rsc(gpointer key, gpointer value, gpointer user_data)
{
    const char *stop_id = key;
    char *rsc = user_data;
    struct recurring_op_s *pending = value;

    if (safe_str_eq(rsc, pending->rsc_id)) {
        crm_notice("%sction %s (%s) incomplete at shutdown",
                   pending->interval == 0 ? "A" : "Recurring a", stop_id, pending->op_key);
    }
}

static void
ghash_count_pending(gpointer key, gpointer value, gpointer user_data)
{
    int *counter = user_data;
    struct recurring_op_s *pending = value;

    if (pending->interval > 0) {
        /* Ignore recurring actions in the shutdown calculations */
        return;
    }

    (*counter)++;
}

gboolean
verify_stopped(enum crmd_fsa_state cur_state, int log_level)
{
    int counter = 0;
    gboolean rc = TRUE;
    const char *when = "lrm disconnect";

    GHashTableIter gIter;
    rsc_history_t *entry = NULL;

    crm_debug("Checking for active resources before exit");

    if (cur_state == S_TERMINATE) {
        log_level = LOG_ERR;
        when = "shutdown";

    } else if (is_set(fsa_input_register, R_SHUTDOWN)) {
        when = "shutdown... waiting";
    }

    if (pending_ops) {
        if (is_set(fsa_input_register, R_LRM_CONNECTED)) {
            /* Only log/complain about non-recurring actions */
            g_hash_table_foreach_remove(pending_ops, stop_recurring_actions, NULL);
        }
        g_hash_table_foreach(pending_ops, ghash_count_pending, &counter);
    }

    if (counter > 0) {
        do_crm_log(log_level, "%d pending LRM operations at %s%s", counter, when);

        if (cur_state == S_TERMINATE || !is_set(fsa_input_register, R_SENT_RSC_STOP)) {
            g_hash_table_foreach(pending_ops, ghash_print_pending, &log_level);
        } else {
            rc = FALSE;
        }
        goto bail;
    }

    if (resource_history == NULL) {
        goto bail;
    }

    counter = 0;
    g_hash_table_iter_init(&gIter, resource_history);
    while (g_hash_table_iter_next(&gIter, NULL, (void **)&entry)) {
        if (is_rsc_active(entry->id) == FALSE) {
            continue;
        }

        counter++;
        crm_trace("Found %s active", entry->id);
        g_hash_table_foreach(pending_ops, ghash_print_pending_for_rsc, entry->id);
    }

    if(counter) {
        crm_err("%d resources were active at %s.", counter, when);
    }
    
  bail:
    set_bit(fsa_input_register, R_SENT_RSC_STOP);
    return rc;
}

static char *
get_rsc_metadata(const char *type, const char *class, const char *provider)
{
    char *metadata = NULL;

    CRM_CHECK(type != NULL, return NULL);
    CRM_CHECK(class != NULL, return NULL);
    if (provider == NULL) {
        provider = "heartbeat";
    }

    crm_trace("Retreiving metadata for %s::%s:%s", type, class, provider);
    fsa_lrm_conn->cmds->get_metadata(fsa_lrm_conn, class, provider, type, &metadata, 0);

    if (metadata) {
        /* copy the metadata because the LRM likes using
         *   g_alloc instead of cl_malloc
         */
        char *m_copy = strdup(metadata);

        g_free(metadata);
        metadata = m_copy;

    } else {
        crm_warn("No metadata found for %s::%s:%s", type, class, provider);
    }

    return metadata;
}

typedef struct reload_data_s {
    char *key;
    char *metadata;
    time_t last_query;
    gboolean can_reload;
    GListPtr restart_list;
} reload_data_t;

static void
g_hash_destroy_reload(gpointer data)
{
    reload_data_t *reload = data;

    free(reload->key);
    free(reload->metadata);
    g_list_free_full(reload->restart_list, free);
    free(reload);
}

GHashTable *reload_hash = NULL;
static GListPtr
get_rsc_restart_list(lrmd_rsc_info_t * rsc, lrmd_event_data_t * op)
{
    int len = 0;
    char *key = NULL;
    char *copy = NULL;
    const char *value = NULL;
    const char *provider = NULL;

    xmlNode *param = NULL;
    xmlNode *params = NULL;
    xmlNode *actions = NULL;
    xmlNode *metadata = NULL;

    time_t now = time(NULL);
    reload_data_t *reload = NULL;

    if (reload_hash == NULL) {
        reload_hash = g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, g_hash_destroy_reload);
    }

    provider = rsc->provider;
    if (provider == NULL) {
        provider = "heartbeat";
    }

    len = strlen(rsc->type) + strlen(rsc->class) + strlen(provider) + 4;
    /* coverity[returned_null] Ignore */
    key = malloc( len);
    snprintf(key, len, "%s::%s:%s", rsc->type, rsc->class, provider);

    reload = g_hash_table_lookup(reload_hash, key);

    if (reload && ((now - 9) > reload->last_query)
        && safe_str_eq(op->op_type, RSC_START)) {
        reload = NULL;          /* re-query */
    }

    if (reload == NULL) {
        xmlNode *action = NULL;

        reload = calloc(1, sizeof(reload_data_t));
        g_hash_table_replace(reload_hash, key, reload);

        reload->last_query = now;
        reload->key = key;
        key = NULL;
        reload->metadata = get_rsc_metadata(rsc->type, rsc->class, provider);

        metadata = string2xml(reload->metadata);
        if (metadata == NULL) {
            crm_err("Metadata for %s::%s:%s is not valid XML",
                    rsc->provider, rsc->class, rsc->type);
            goto cleanup;
        }

        actions = find_xml_node(metadata, "actions", TRUE);

        for (action = __xml_first_child(actions); action != NULL; action = __xml_next(action)) {
            if (crm_str_eq((const char *)action->name, "action", TRUE)) {
                value = crm_element_value(action, "name");
                if (safe_str_eq("reload", value)) {
                    reload->can_reload = TRUE;
                    break;
                }
            }
        }

        if (reload->can_reload == FALSE) {
            goto cleanup;
        }

        params = find_xml_node(metadata, "parameters", TRUE);
        for (param = __xml_first_child(params); param != NULL; param = __xml_next(param)) {
            if (crm_str_eq((const char *)param->name, "parameter", TRUE)) {
                value = crm_element_value(param, "unique");
                if (crm_is_true(value)) {
                    value = crm_element_value(param, "name");
                    if (value == NULL) {
                        crm_err("%s: NULL param", key);
                        continue;
                    }
                    crm_debug("Attr %s is not reloadable", value);
                    copy = strdup(value);
                    CRM_CHECK(copy != NULL, continue);
                    reload->restart_list = g_list_append(reload->restart_list, copy);
                }
            }
        }
    }

  cleanup:
    free(key);
    free_xml(metadata);
    return reload->restart_list;
}

static void
append_restart_list(lrmd_rsc_info_t * rsc, lrmd_event_data_t * op, xmlNode * update, const char *version)
{
    int len = 0;
    char *list = NULL;
    char *digest = NULL;
    const char *value = NULL;
    xmlNode *restart = NULL;
    GListPtr restart_list = NULL;
    GListPtr lpc = NULL;

    if (op->interval > 0) {
        /* monitors are not reloadable */
        return;

    } else if (op->params == NULL) {
        crm_debug("%s has no parameters", ID(update));
        return;

    } else if (rsc == NULL) {
        return;

    } else if (crm_str_eq(CRMD_ACTION_STOP, op->op_type, TRUE)) {
        /* Stopped resources don't need to be reloaded */
        return;

    } else if (compare_version("1.0.8", version) > 0) {
        /* Caller version does not support reloads */
        return;
    }

    restart_list = get_rsc_restart_list(rsc, op);
    if (restart_list == NULL) {
        /* Resource does not support reloads */
        return;
    }

    restart = create_xml_node(NULL, XML_TAG_PARAMS);
    for (lpc = restart_list; lpc != NULL; lpc = lpc->next) {
        const char *param = (const char *)lpc->data;

        int start = len;

        CRM_CHECK(param != NULL, continue);
        value = g_hash_table_lookup(op->params, param);
        if (value != NULL) {
            crm_xml_add(restart, param, value);
        }
        len += strlen(param) + 2;
        list = realloc(list, len + 1);
        sprintf(list + start, " %s ", param);
    }

    digest = calculate_operation_digest(restart, version);
    crm_xml_add(update, XML_LRM_ATTR_OP_RESTART, list);
    crm_xml_add(update, XML_LRM_ATTR_RESTART_DIGEST, digest);

    crm_trace("%s: %s, %s", rsc->id, digest, list);
    crm_log_xml_trace(restart, "restart digest source");

    free_xml(restart);
    free(digest);
    free(list);
}

static gboolean
build_operation_update(xmlNode * parent, lrmd_rsc_info_t * rsc, lrmd_event_data_t * op, const char *src)
{
    int target_rc = 0;
    xmlNode *xml_op = NULL;
    const char *caller_version = CRM_FEATURE_SET;

    if (op == NULL) {
        return FALSE;

    } else if (AM_I_DC) {

    } else if (fsa_our_dc_version != NULL) {
        caller_version = fsa_our_dc_version;
    } else if (op->params == NULL) {
        caller_version = fsa_our_dc_version;
    } else {
        /* there is a small risk in formerly mixed clusters that
         *   it will be sub-optimal.
         * however with our upgrade policy, the update we send
         *   should still be completely supported anyway
         */
        caller_version = g_hash_table_lookup(op->params, XML_ATTR_CRM_VERSION);
        crm_debug("Falling back to operation originator version: %s", caller_version);
    }

    target_rc = rsc_op_expected_rc(op);
    xml_op = create_operation_update(parent, op, caller_version, target_rc, src, LOG_DEBUG);

    if (xml_op) {
        append_restart_list(rsc, op, xml_op, caller_version);
    }
    return TRUE;
}

gboolean
is_rsc_active(const char *rsc_id)
{
    rsc_history_t *entry = NULL;

    entry = g_hash_table_lookup(resource_history, rsc_id);
    if (entry == NULL || entry->last == NULL) {
        return FALSE;
    }

    crm_trace("Processing %s: %s.%d=%d",
              rsc_id, entry->last->op_type, entry->last->interval, entry->last->rc);
    if (entry->last->rc == PCMK_EXECRA_OK && safe_str_eq(entry->last->op_type, CRMD_ACTION_STOP)) {
        return FALSE;

    } else if (entry->last->rc == PCMK_EXECRA_OK
               && safe_str_eq(entry->last->op_type, CRMD_ACTION_MIGRATE)) {
        /* a stricter check is too complex...
         * leave that to the PE
         */
        return FALSE;

    } else if (entry->last->rc == PCMK_EXECRA_NOT_RUNNING) {
        return FALSE;

    } else if (entry->last->interval == 0 && entry->last->rc == PCMK_EXECRA_NOT_CONFIGURED) {
        /* Badly configured resources can't be reliably stopped */
        return FALSE;
    }

    return TRUE;
}

gboolean
build_active_RAs(xmlNode * rsc_list)
{
    GHashTableIter iter;
    rsc_history_t *entry = NULL;

    g_hash_table_iter_init(&iter, resource_history);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&entry)) {

        GList *gIter = NULL;
        xmlNode *xml_rsc = create_xml_node(rsc_list, XML_LRM_TAG_RESOURCE);

        crm_xml_add(xml_rsc, XML_ATTR_ID, entry->id);
        crm_xml_add(xml_rsc, XML_ATTR_TYPE, entry->rsc.type);
        crm_xml_add(xml_rsc, XML_AGENT_ATTR_CLASS, entry->rsc.class);
        crm_xml_add(xml_rsc, XML_AGENT_ATTR_PROVIDER, entry->rsc.provider);

        build_operation_update(xml_rsc, &(entry->rsc), entry->last, __FUNCTION__);
        build_operation_update(xml_rsc, &(entry->rsc), entry->failed, __FUNCTION__);
        for (gIter = entry->recurring_op_list; gIter != NULL; gIter = gIter->next) {
            build_operation_update(xml_rsc, &(entry->rsc), gIter->data, __FUNCTION__);
        }
    }

    return FALSE;
}

xmlNode *
do_lrm_query(gboolean is_replace)
{
    xmlNode *xml_result = NULL;
    xmlNode *xml_state = NULL;
    xmlNode *xml_data = NULL;
    xmlNode *rsc_list = NULL;

    crm_node_t *peer = crm_get_peer(0, fsa_our_uname);
    xml_state = do_update_node_cib(peer, node_update_cluster|node_update_peer, NULL, __FUNCTION__);

    /* The next two lines shouldn't be necessary for newer DCs */
    crm_xml_add(xml_state, XML_NODE_JOIN_STATE, CRMD_JOINSTATE_MEMBER);
    crm_xml_add(xml_state, XML_NODE_EXPECTED, CRMD_JOINSTATE_MEMBER);

    xml_data = create_xml_node(xml_state, XML_CIB_TAG_LRM);
    crm_xml_add(xml_data, XML_ATTR_ID, fsa_our_uuid);
    rsc_list = create_xml_node(xml_data, XML_LRM_TAG_RESOURCES);

    /* Build a list of active (not always running) resources */
    build_active_RAs(rsc_list);

    xml_result = create_cib_fragment(xml_state, XML_CIB_TAG_STATUS);
    crm_log_xml_trace(xml_state, "Current state of the LRM");
    free_xml(xml_state);

    return xml_result;
}

static void
notify_deleted(ha_msg_input_t * input, const char *rsc_id, int rc)
{
    lrmd_event_data_t *op = NULL;
    const char *from_sys = crm_element_value(input->msg, F_CRM_SYS_FROM);
    const char *from_host = crm_element_value(input->msg, F_CRM_HOST_FROM);

    crm_info("Notifying %s on %s that %s was%s deleted",
             from_sys, from_host, rsc_id, rc == pcmk_ok ? "" : " not");

    op = construct_op(input->xml, rsc_id, CRMD_ACTION_DELETE);
    CRM_ASSERT(op != NULL);

    if (rc == pcmk_ok) {
        op->op_status = PCMK_LRM_OP_DONE;
        op->rc = PCMK_EXECRA_OK;
    } else {
        op->op_status = PCMK_LRM_OP_ERROR;
        op->rc = PCMK_EXECRA_UNKNOWN_ERROR;
    }

    send_direct_ack(from_host, from_sys, NULL, op, rsc_id);
    lrmd_free_event(op);

    if (safe_str_neq(from_sys, CRM_SYSTEM_TENGINE)) {
        /* this isn't expected - trigger a new transition */
        time_t now = time(NULL);
        char *now_s = crm_itoa(now);

        crm_debug("Triggering a refresh after %s deleted %s from the LRM", from_sys, rsc_id);

        update_attr_delegate(
            fsa_cib_conn, cib_none, XML_CIB_TAG_CRMCONFIG, NULL, NULL, NULL, NULL,
            "last-lrm-refresh", now_s, FALSE, NULL);

        free(now_s);
    }
}

static gboolean
lrm_remove_deleted_rsc(gpointer key, gpointer value, gpointer user_data)
{
    struct delete_event_s *event = user_data;
    struct pending_deletion_op_s *op = value;

    if (safe_str_eq(event->rsc, op->rsc)) {
        notify_deleted(op->input, event->rsc, event->rc);
        return TRUE;
    }
    return FALSE;
}

static gboolean
lrm_remove_deleted_op(gpointer key, gpointer value, gpointer user_data)
{
    const char *rsc = user_data;
    struct recurring_op_s *pending = value;

    if (safe_str_eq(rsc, pending->rsc_id)) {
        crm_info("Removing op %s:%d for deleted resource %s",
                 pending->op_key, pending->call_id, rsc);
        return TRUE;
    }
    return FALSE;
}

/*
 * Remove the rsc from the CIB
 *
 * Avoids refreshing the entire LRM section of this host
 */
#define rsc_template "//"XML_CIB_TAG_STATE"[@uname='%s']//"XML_LRM_TAG_RESOURCE"[@id='%s']"

static int
delete_rsc_status(const char *rsc_id, int call_options, const char *user_name)
{
    char *rsc_xpath = NULL;
    int max = 0;
    int rc = pcmk_ok;

    CRM_CHECK(rsc_id != NULL, return -ENXIO);

    max = strlen(rsc_template) + strlen(rsc_id) + strlen(fsa_our_uname) + 1;
    rsc_xpath = calloc(1, max);
    snprintf(rsc_xpath, max, rsc_template, fsa_our_uname, rsc_id);

    rc = cib_internal_op(fsa_cib_conn, CIB_OP_DELETE, NULL, rsc_xpath,
                         NULL, NULL, call_options | cib_xpath, user_name);

    free(rsc_xpath);
    return rc;
}

static void
delete_rsc_entry(ha_msg_input_t * input, const char *rsc_id, GHashTableIter *rsc_gIter, int rc, const char *user_name)
{
    struct delete_event_s event;

    CRM_CHECK(rsc_id != NULL, return);

    if (rc == pcmk_ok) {
        char *rsc_id_copy = strdup(rsc_id);

        if (rsc_gIter)
            g_hash_table_iter_remove(rsc_gIter);
        else
            g_hash_table_remove(resource_history, rsc_id_copy);
        crm_debug("sync: Sending delete op for %s", rsc_id_copy);
        delete_rsc_status(rsc_id_copy, cib_quorum_override, user_name);

        g_hash_table_foreach_remove(pending_ops, lrm_remove_deleted_op, rsc_id_copy);

        free(rsc_id_copy);
    }

    if (input) {
        notify_deleted(input, rsc_id, rc);
    }

    event.rc = rc;
    event.rsc = rsc_id;
    g_hash_table_foreach_remove(deletion_ops, lrm_remove_deleted_rsc, &event);
}

/*
 * Remove the op from the CIB
 *
 * Avoids refreshing the entire LRM section of this host
 */

#define op_template "//"XML_CIB_TAG_STATE"[@uname='%s']//"XML_LRM_TAG_RESOURCE"[@id='%s']/"XML_LRM_TAG_RSC_OP"[@id='%s']"
#define op_call_template "//"XML_CIB_TAG_STATE"[@uname='%s']//"XML_LRM_TAG_RESOURCE"[@id='%s']/"XML_LRM_TAG_RSC_OP"[@id='%s' and @"XML_LRM_ATTR_CALLID"='%d']"

static void
delete_op_entry(lrmd_event_data_t * op, const char *rsc_id, const char *key, int call_id)
{
    xmlNode *xml_top = NULL;

    if (op != NULL) {
        xml_top = create_xml_node(NULL, XML_LRM_TAG_RSC_OP);
        crm_xml_add_int(xml_top, XML_LRM_ATTR_CALLID, op->call_id);
        crm_xml_add(xml_top, XML_ATTR_TRANSITION_KEY, op->user_data);

        if(op->interval > 0) {
            char *op_id = generate_op_key(op->rsc_id, op->op_type, op->interval);
            /* Avoid deleting last_failure too (if it was a result of this recurring op failing) */
            crm_xml_add(xml_top, XML_ATTR_ID, op_id);
            free(op_id);
        }

        crm_debug("async: Sending delete op for %s_%s_%d (call=%d)",
                  op->rsc_id, op->op_type, op->interval, op->call_id);

        fsa_cib_conn->cmds->delete(fsa_cib_conn, XML_CIB_TAG_STATUS, xml_top, cib_quorum_override);

    } else if (rsc_id != NULL && key != NULL) {
        int max = 0;
        char *op_xpath = NULL;

        if (call_id > 0) {
            max =
                strlen(op_call_template) + strlen(rsc_id) + strlen(fsa_our_uname) + strlen(key) +
                10;
            op_xpath = calloc(1, max);
            snprintf(op_xpath, max, op_call_template, fsa_our_uname, rsc_id, key, call_id);

        } else {
            max = strlen(op_template) + strlen(rsc_id) + strlen(fsa_our_uname) + strlen(key) + 1;
            op_xpath = calloc(1, max);
            snprintf(op_xpath, max, op_template, fsa_our_uname, rsc_id, key);
        }

        crm_debug("sync: Sending delete op for %s (call=%d)", rsc_id, call_id);
        fsa_cib_conn->cmds->delete(fsa_cib_conn, op_xpath, NULL, cib_quorum_override | cib_xpath);

        free(op_xpath);

    } else {
        crm_err("Not enough information to delete op entry: rsc=%p key=%p", rsc_id, key);
        return;
    }

    crm_log_xml_trace(xml_top, "op:cancel");
    free_xml(xml_top);
}

void lrm_clear_last_failure(const char *rsc_id)
{
    char *attr = NULL;
    GHashTableIter iter;
    rsc_history_t *entry = NULL;

    attr = generate_op_key(rsc_id, "last_failure", 0);
    delete_op_entry(NULL, rsc_id, attr, 0);
    free(attr);

    if (!resource_history) {
        return;
    }

    g_hash_table_iter_init(&iter, resource_history);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&entry)) {
        if (safe_str_eq(rsc_id, entry->id)) {
            lrmd_free_event(entry->failed);
            entry->failed = NULL;
        }
    }
}

static gboolean
cancel_op(const char *rsc_id, const char *key, int op, gboolean remove)
{
    int rc = pcmk_ok;
    struct recurring_op_s *pending = NULL;

    CRM_CHECK(op != 0, return FALSE);
    CRM_CHECK(rsc_id != NULL, return FALSE);
    if (key == NULL) {
        key = make_stop_id(rsc_id, op);
    }
    pending = g_hash_table_lookup(pending_ops, key);

    if (pending) {
        if (remove && pending->remove == FALSE) {
            pending->remove = TRUE;
            crm_debug("Scheduling %s for removal", key);
        }

        if (pending->cancelled) {
            crm_debug("Operation %s already cancelled", key);
            return TRUE;
        }

        pending->cancelled = TRUE;

    } else {
        crm_info("No pending op found for %s", key);
        return TRUE;
    }

    crm_debug("Cancelling op %d for %s (%s)", op, rsc_id, key);

    rc = fsa_lrm_conn->cmds->cancel(fsa_lrm_conn,
        pending->rsc_id,
        pending->op_type,
        pending->interval);

    if (rc == pcmk_ok) {
        crm_debug("Op %d for %s (%s): cancelled", op, rsc_id, key);
    } else {
        crm_debug("Op %d for %s (%s): Nothing to cancel", op, rsc_id, key);
        /* The caller needs to make sure the entry is
         * removed from the pending_ops list
         *
         * Usually by returning TRUE inside the worker function
         * supplied to g_hash_table_foreach_remove()
         *
         * Not removing the entry from pending_ops will block
         * the node from shutting down
         */
        return FALSE;
    }

    return TRUE;
}

struct cancel_data {
    gboolean done;
    gboolean remove;
    const char *key;
    lrmd_rsc_info_t *rsc;
};

static gboolean
cancel_action_by_key(gpointer key, gpointer value, gpointer user_data)
{
    struct cancel_data *data = user_data;
    struct recurring_op_s *op = (struct recurring_op_s *)value;

    if (safe_str_eq(op->op_key, data->key)) {
        data->done = TRUE;
        if (cancel_op(data->rsc->id, key, op->call_id, data->remove) == FALSE) {
            return TRUE;
        }
    }
    return FALSE;
}

static gboolean
cancel_op_key(lrmd_rsc_info_t * rsc, const char *key, gboolean remove)
{
    struct cancel_data data;

    CRM_CHECK(rsc != NULL, return FALSE);
    CRM_CHECK(key != NULL, return FALSE);

    data.key = key;
    data.rsc = rsc;
    data.done = FALSE;
    data.remove = remove;

    g_hash_table_foreach_remove(pending_ops, cancel_action_by_key, &data);
    return data.done;
}

static lrmd_rsc_info_t *
get_lrm_resource(xmlNode * resource, xmlNode * op_msg, gboolean do_create)
{
    lrmd_rsc_info_t *rsc = NULL;
    const char *id = ID(resource);
    const char *type = crm_element_value(resource, XML_ATTR_TYPE);
    const char *class = crm_element_value(resource, XML_AGENT_ATTR_CLASS);
    const char *provider = crm_element_value(resource, XML_AGENT_ATTR_PROVIDER);
    const char *long_id = crm_element_value(resource, XML_ATTR_ID_LONG);

    crm_trace("Retrieving %s from the LRM.", id);
    CRM_CHECK(id != NULL, return NULL);

    rsc = fsa_lrm_conn->cmds->get_rsc_info(fsa_lrm_conn, id, 0);
    if (!rsc && long_id) {
        rsc = fsa_lrm_conn->cmds->get_rsc_info(fsa_lrm_conn, long_id, 0);
    }

    if (!rsc && do_create) {
        CRM_CHECK(class != NULL, return NULL);
        CRM_CHECK(type != NULL, return NULL);

        crm_trace("Adding rsc %s before operation", id);

        fsa_lrm_conn->cmds->register_rsc(fsa_lrm_conn,
            id, class, provider, type, lrmd_opt_drop_recurring);

        rsc = fsa_lrm_conn->cmds->get_rsc_info(fsa_lrm_conn, id, 0);

        if (!rsc) {
            fsa_data_t *msg_data = NULL;

            crm_err("Could not add resource %s to LRM", id);
            register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
        }
    }

    return rsc;
}

static void
delete_resource(const char *id, lrmd_rsc_info_t * rsc, GHashTableIter *gIter,
                const char *sys, const char *host, const char *user, ha_msg_input_t * request)
{
    int rc = pcmk_ok;

    crm_info("Removing resource %s for %s (%s) on %s", id, sys, user ? user : "internal", host);

    if (rsc) {
        rc = fsa_lrm_conn->cmds->unregister_rsc(fsa_lrm_conn, id, 0);
    }

    if (rc == pcmk_ok) {
        crm_trace("Resource '%s' deleted", id);
    } else if (rc == -EINPROGRESS) {
        crm_info("Deletion of resource '%s' pending", id);
        if (request) {
            struct pending_deletion_op_s *op = NULL;
            char *ref = crm_element_value_copy(request->msg, XML_ATTR_REFERENCE);

            op = calloc(1, sizeof(struct pending_deletion_op_s));
            op->rsc = strdup(rsc->id);
            op->input = copy_ha_msg_input(request);
            g_hash_table_insert(deletion_ops, ref, op);
        }
        return;
    } else {
        crm_warn("Deletion of resource '%s' for %s (%s) on %s failed: %d",
                 id, sys, user ? user : "internal", host, rc);
    }

    delete_rsc_entry(request, id, gIter, rc, user);
}

/*	 A_LRM_INVOKE	*/
void
do_lrm_invoke(long long action,
              enum crmd_fsa_cause cause,
              enum crmd_fsa_state cur_state,
              enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    gboolean done = FALSE;
    gboolean create_rsc = TRUE;
    const char *crm_op = NULL;
    const char *from_sys = NULL;
    const char *from_host = NULL;
    const char *operation = NULL;
    ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);
    const char *user_name = NULL;

#if ENABLE_ACL
    user_name = crm_element_value(input->msg, F_CRM_USER);
    crm_trace("LRM command from user '%s'", user_name);
#endif

    crm_op = crm_element_value(input->msg, F_CRM_TASK);
    from_sys = crm_element_value(input->msg, F_CRM_SYS_FROM);
    if (safe_str_neq(from_sys, CRM_SYSTEM_TENGINE)) {
        from_host = crm_element_value(input->msg, F_CRM_HOST_FROM);
    }

    crm_trace("LRM command from: %s", from_sys);

    if (safe_str_eq(crm_op, CRM_OP_LRM_DELETE)) {
        operation = CRMD_ACTION_DELETE;

    } else if (safe_str_eq(operation, CRM_OP_LRM_REFRESH)) {
        crm_op = CRM_OP_LRM_REFRESH;

    } else if (safe_str_eq(crm_op, CRM_OP_LRM_FAIL)) {
        rsc_history_t *entry = NULL;
        lrmd_event_data_t *op = NULL;
        lrmd_rsc_info_t *rsc = NULL;
        xmlNode *xml_rsc = find_xml_node(input->xml, XML_CIB_TAG_RESOURCE, TRUE);

        CRM_CHECK(xml_rsc != NULL, return);

        /* The lrmd can not fail a resource, it does not understand the
         * concept of success or failure in relation to a resource, it simply
         * executes operations and reports the results. We determine what a failure is.
         * Becaues of this, if we want to fail a resource we have to fake what we
         * understand a failure to look like.
         *
         * To do this we create a fake lrmd operation event for the resource
         * we want to fail.  We then pass that event to the lrmd client callback
         * so it will be processed as if it actually came from the lrmd. */
        op = construct_op(input->xml, ID(xml_rsc), "asyncmon");
        free((char *) op->user_data);
        op->user_data = NULL;
        entry = g_hash_table_lookup(resource_history, op->rsc_id);
        /* Make sure the call id is greater than the last successful operation,
         * otherwise the failure will not result in a possible recovery of the resource
         * as it could appear the failure occurred before the successful start */
        if (entry && entry->last) {
            op->call_id = entry->last->call_id + 1;
            if (op->call_id < 0) {
                op->call_id = 1;
            }
        }
        op->interval = 0;
        op->op_status = PCMK_LRM_OP_DONE;
        op->rc = PCMK_EXECRA_UNKNOWN_ERROR;
        CRM_ASSERT(op != NULL);

#  if ENABLE_ACL
        if (user_name && is_privileged(user_name) == FALSE) {
            crm_err("%s does not have permission to fail %s", user_name, ID(xml_rsc));
            send_direct_ack(from_host, from_sys, NULL, op, ID(xml_rsc));
            lrmd_free_event(op);
            return;
        }
#  endif

        rsc = get_lrm_resource(xml_rsc, input->xml, create_rsc);
        if (rsc) {
            crm_info("Failing resource %s...", rsc->id);
            process_lrm_event(op);
            op->op_status = PCMK_LRM_OP_DONE;
            op->rc = PCMK_EXECRA_OK;
            lrmd_free_rsc_info(rsc);
        } else {
            crm_info("Cannot find/create resource in order to fail it...");
            crm_log_xml_warn(input->msg, "bad input");
        }

        send_direct_ack(from_host, from_sys, NULL, op, ID(xml_rsc));
        lrmd_free_event(op);
        return;

    } else if (input->xml != NULL) {
        operation = crm_element_value(input->xml, XML_LRM_ATTR_TASK);
    }

    if (safe_str_eq(crm_op, CRM_OP_LRM_REFRESH)) {
        int rc = pcmk_ok;
        xmlNode *fragment = do_lrm_query(TRUE);

        fsa_cib_update(XML_CIB_TAG_STATUS, fragment, cib_quorum_override, rc, user_name);
        crm_info("Forced a local LRM refresh: call=%d", rc);
        free_xml(fragment);

    } else if (safe_str_eq(crm_op, CRM_OP_LRM_QUERY)) {
        xmlNode *data = do_lrm_query(FALSE);
        xmlNode *reply = create_reply(input->msg, data);

        if (relay_message(reply, TRUE) == FALSE) {
            crm_err("Unable to route reply");
            crm_log_xml_err(reply, "reply");
        }
        free_xml(reply);
        free_xml(data);

    } else if (safe_str_eq(operation, CRM_OP_PROBED)) {
        update_attrd(NULL, CRM_OP_PROBED, XML_BOOLEAN_TRUE, user_name);

    } else if (safe_str_eq(crm_op, CRM_OP_REPROBE)) {
        GHashTableIter gIter;
        rsc_history_t *entry = NULL;

        crm_notice("Forcing the status of all resources to be redetected");

        g_hash_table_iter_init(&gIter, resource_history);
        while (g_hash_table_iter_next(&gIter, NULL, (void **)&entry)) {
            delete_resource(entry->id, &entry->rsc, &gIter, from_sys, from_host, user_name, NULL);
        }

        /* Now delete the copy in the CIB */
        erase_status_tag(fsa_our_uname, XML_CIB_TAG_LRM, cib_scope_local);

        /* And finally, _delete_ the value in attrd
         * Setting it to FALSE results in the PE sending us back here again
         */
        update_attrd(NULL, CRM_OP_PROBED, NULL, user_name);

    } else if (operation != NULL) {
        lrmd_rsc_info_t *rsc = NULL;
        xmlNode *params = NULL;
        xmlNode *xml_rsc = find_xml_node(input->xml, XML_CIB_TAG_RESOURCE, TRUE);

        CRM_CHECK(xml_rsc != NULL, return);

        /* only the first 16 chars are used by the LRM */
        params = find_xml_node(input->xml, XML_TAG_ATTRS, TRUE);

        if (safe_str_eq(operation, CRMD_ACTION_DELETE)) {
            create_rsc = FALSE;
        }

        rsc = get_lrm_resource(xml_rsc, input->xml, create_rsc);

        if (rsc == NULL && create_rsc) {
            crm_err("Invalid resource definition");
            crm_log_xml_warn(input->msg, "bad input");

        } else if (rsc == NULL) {
            lrmd_event_data_t *op = NULL;

            crm_notice("Not creating resource for a %s event: %s", operation, ID(input->xml));
            delete_rsc_entry(input, ID(xml_rsc), NULL, pcmk_ok, user_name);

            op = construct_op(input->xml, ID(xml_rsc), operation);
            op->op_status = PCMK_LRM_OP_DONE;
            op->rc = PCMK_EXECRA_OK;
            CRM_ASSERT(op != NULL);
            send_direct_ack(from_host, from_sys, NULL, op, ID(xml_rsc));
            lrmd_free_event(op);

        } else if (safe_str_eq(operation, CRMD_ACTION_CANCEL)) {
            lrmd_event_data_t *op = NULL;
            char *op_key = NULL;
            char *meta_key = NULL;
            int call = 0;
            const char *call_id = NULL;
            const char *op_task = NULL;
            const char *op_interval = NULL;

            CRM_CHECK(params != NULL, crm_log_xml_warn(input->xml, "Bad command");
                      return);

            meta_key = crm_meta_name(XML_LRM_ATTR_INTERVAL);
            op_interval = crm_element_value(params, meta_key);
            free(meta_key);

            meta_key = crm_meta_name(XML_LRM_ATTR_TASK);
            op_task = crm_element_value(params, meta_key);
            free(meta_key);

            meta_key = crm_meta_name(XML_LRM_ATTR_CALLID);
            call_id = crm_element_value(params, meta_key);
            free(meta_key);

            CRM_CHECK(op_task != NULL, crm_log_xml_warn(input->xml, "Bad command");
                      return);
            CRM_CHECK(op_interval != NULL, crm_log_xml_warn(input->xml, "Bad command");
                      return);

            op = construct_op(input->xml, rsc->id, op_task);
            CRM_ASSERT(op != NULL);
            op_key = generate_op_key(rsc->id, op_task, crm_parse_int(op_interval, "0"));

            crm_debug("PE requested op %s (call=%s) be cancelled",
                      op_key, call_id ? call_id : "NA");
            call = crm_parse_int(call_id, "0");
            if (call == 0) {
                /* the normal case when the PE cancels a recurring op */
                done = cancel_op_key(rsc, op_key, TRUE);

            } else {
                /* the normal case when the PE cancels an orphan op */
                done = cancel_op(rsc->id, NULL, call, TRUE);
            }

            if (done == FALSE) {
                crm_debug("Nothing known about operation %d for %s", call, op_key);
                delete_op_entry(NULL, rsc->id, op_key, call);

                /* needed?? surely not otherwise the cancel_op_(_key) wouldn't
                 * have failed in the first place
                 */
                g_hash_table_remove(pending_ops, op_key);
            }

            op->rc = PCMK_EXECRA_OK;
            op->op_status = PCMK_LRM_OP_DONE;
            send_direct_ack(from_host, from_sys, rsc, op, rsc->id);

            free(op_key);
            lrmd_free_event(op);

        } else if (safe_str_eq(operation, CRMD_ACTION_DELETE)) {
            int cib_rc = pcmk_ok;

            CRM_ASSERT(rsc != NULL);

            cib_rc = delete_rsc_status(rsc->id, cib_dryrun | cib_sync_call, user_name);
            if (cib_rc != pcmk_ok) {
                lrmd_event_data_t *op = NULL;

                crm_err
                    ("Attempt of deleting resource status '%s' from CIB for %s (user=%s) on %s failed: (rc=%d) %s",
                     rsc->id, from_sys, user_name ? user_name : "unknown", from_host, cib_rc,
                     pcmk_strerror(cib_rc));

                op = construct_op(input->xml, rsc->id, operation);
                op->op_status = PCMK_LRM_OP_ERROR;

                if (cib_rc == -EACCES) {
                    op->rc = PCMK_EXECRA_INSUFFICIENT_PRIV;
                } else {
                    op->rc = PCMK_EXECRA_UNKNOWN_ERROR;
                }
                send_direct_ack(from_host, from_sys, NULL, op, rsc->id);
                lrmd_free_event(op);
                return;
            }

            delete_resource(rsc->id, rsc, NULL, from_sys, from_host, user_name, input);

        } else if (rsc != NULL) {
            do_lrm_rsc_op(rsc, operation, input->xml, input->msg);
        }

        lrmd_free_rsc_info(rsc);

    } else {
        crm_err("Operation was neither a lrm_query, nor a rsc op.  %s", crm_str(crm_op));
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }
}

static lrmd_event_data_t *
construct_op(xmlNode * rsc_op, const char *rsc_id, const char *operation)
{
    lrmd_event_data_t *op = NULL;
    const char *op_delay = NULL;
    const char *op_timeout = NULL;
    const char *op_interval = NULL;
    GHashTable *params = NULL;

    const char *transition = NULL;

    CRM_LOG_ASSERT(rsc_id != NULL);

    op = calloc(1, sizeof(lrmd_event_data_t));
    op->type = lrmd_event_exec_complete;
    op->op_type = strdup(operation);
    op->op_status = PCMK_LRM_OP_PENDING;
    op->rc = -1;
    op->rsc_id = strdup(rsc_id);
    op->interval = 0;
    op->timeout = 0;
    op->start_delay = 0;

    if (rsc_op == NULL) {
        CRM_LOG_ASSERT(safe_str_eq(CRMD_ACTION_STOP, operation));
        op->user_data = NULL;
        /* the stop_all_resources() case
         * by definition there is no DC (or they'd be shutting
         *   us down).
         * So we should put our version here.
         */
        op->params = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                           g_hash_destroy_str, g_hash_destroy_str);

        g_hash_table_insert(op->params,
                            strdup(XML_ATTR_CRM_VERSION), strdup(CRM_FEATURE_SET));

        crm_trace("Constructed %s op for %s", operation, rsc_id);
        return op;
    }

    params = xml2list(rsc_op);
    g_hash_table_remove(params, CRM_META "_op_target_rc");

    op_delay = crm_meta_value(params, XML_OP_ATTR_START_DELAY);
    op_timeout = crm_meta_value(params, XML_ATTR_TIMEOUT);
    op_interval = crm_meta_value(params, XML_LRM_ATTR_INTERVAL);

    op->interval = crm_parse_int(op_interval, "0");
    op->timeout = crm_parse_int(op_timeout, "0");
    op->start_delay = crm_parse_int(op_delay, "0");

    if (safe_str_neq(operation, RSC_STOP)) {
        op->params = params;

    } else {
        rsc_history_t *entry = g_hash_table_lookup(resource_history, rsc_id);

        /* If we do not have stop parameters cached, use
         * whatever we are given */
        if (!entry || !entry->stop_params) {
            op->params = params;
        } else {
            /* Copy the cached parameter list so that we stop the resource
             * with the old attributes, not the new ones */
            op->params = g_hash_table_new_full(crm_str_hash, g_str_equal,
                g_hash_destroy_str, g_hash_destroy_str);

            g_hash_table_foreach(params, copy_meta_keys, op->params);
            g_hash_table_foreach(entry->stop_params, copy_instance_keys, op->params);
            g_hash_table_destroy(params);
            params = NULL;
        }
    }

    /* sanity */
    if (op->interval < 0) {
        op->interval = 0;
    }
    if (op->timeout <= 0) {
        op->timeout = op->interval;
    }
    if (op->start_delay < 0) {
        op->start_delay = 0;
    }

    transition = crm_element_value(rsc_op, XML_ATTR_TRANSITION_KEY);
    CRM_CHECK(transition != NULL, return op);

    op->user_data = strdup(transition);

    if (op->interval != 0) {
        if (safe_str_eq(operation, CRMD_ACTION_START)
            || safe_str_eq(operation, CRMD_ACTION_STOP)) {
            crm_err("Start and Stop actions cannot have an interval: %d", op->interval);
            op->interval = 0;
        }
    }

    crm_trace("Constructed %s op for %s: interval=%d", operation, rsc_id, op->interval);

    return op;
}

void
send_direct_ack(const char *to_host, const char *to_sys,
                lrmd_rsc_info_t * rsc, lrmd_event_data_t * op, const char *rsc_id)
{
    xmlNode *reply = NULL;
    xmlNode *update, *iter;
    xmlNode *fragment;
    crm_node_t *peer = NULL;

    CRM_CHECK(op != NULL, return);
    if (op->rsc_id == NULL) {
        CRM_LOG_ASSERT(rsc_id != NULL);
        op->rsc_id = strdup(rsc_id);
    }
    if (to_sys == NULL) {
        to_sys = CRM_SYSTEM_TENGINE;
    }

    peer = crm_get_peer(0, fsa_our_uname);
    update = do_update_node_cib(peer, node_update_none, NULL, __FUNCTION__);

    iter = create_xml_node(update, XML_CIB_TAG_LRM);
    crm_xml_add(iter, XML_ATTR_ID, fsa_our_uuid);
    iter = create_xml_node(iter, XML_LRM_TAG_RESOURCES);
    iter = create_xml_node(iter, XML_LRM_TAG_RESOURCE);

    crm_xml_add(iter, XML_ATTR_ID, op->rsc_id);

    build_operation_update(iter, rsc, op, __FUNCTION__);
    fragment = create_cib_fragment(update, XML_CIB_TAG_STATUS);

    reply = create_request(CRM_OP_INVOKE_LRM, fragment, to_host, to_sys, CRM_SYSTEM_LRMD, NULL);

    crm_log_xml_trace(update, "ACK Update");

    crm_debug("ACK'ing resource op %s_%s_%d from %s: %s",
             op->rsc_id, op->op_type, op->interval, op->user_data,
             crm_element_value(reply, XML_ATTR_REFERENCE));

    if (relay_message(reply, TRUE) == FALSE) {
        crm_log_xml_err(reply, "Unable to route reply");
    }

    free_xml(fragment);
    free_xml(update);
    free_xml(reply);
}

static gboolean
stop_recurring_action_by_rsc(gpointer key, gpointer value, gpointer user_data)
{
    lrmd_rsc_info_t *rsc = user_data;
    struct recurring_op_s *op = (struct recurring_op_s *)value;

    if (op->interval != 0 && safe_str_eq(op->rsc_id, rsc->id)) {
        if (cancel_op(rsc->id, key, op->call_id, FALSE) == FALSE) {
            return TRUE;
        }
    }

    return FALSE;
}

static gboolean
stop_recurring_actions(gpointer key, gpointer value, gpointer user_data)
{
    gboolean remove = FALSE;
    struct recurring_op_s *op = (struct recurring_op_s *)value;

    if (op->interval != 0) {
        remove = cancel_op(op->rsc_id, key, op->call_id, FALSE);
    }

    return remove;
}

void
do_lrm_rsc_op(lrmd_rsc_info_t * rsc, const char *operation, xmlNode * msg, xmlNode * request)
{
    int call_id = 0;
    char *op_id = NULL;
    lrmd_event_data_t *op = NULL;
    lrmd_key_value_t *params = NULL;
    fsa_data_t *msg_data = NULL;
    const char *transition = NULL;

    CRM_CHECK(rsc != NULL, return);

    if (msg != NULL) {
        transition = crm_element_value(msg, XML_ATTR_TRANSITION_KEY);
        if (transition == NULL) {
            crm_log_xml_err(msg, "Missing transition number");
        }
    }

    op = construct_op(msg, rsc->id, operation);

    /* stop the monitor before stopping the resource */
    if (crm_str_eq(operation, CRMD_ACTION_STOP, TRUE)
        || crm_str_eq(operation, CRMD_ACTION_DEMOTE, TRUE)
        || crm_str_eq(operation, CRMD_ACTION_PROMOTE, TRUE)
        || crm_str_eq(operation, CRMD_ACTION_MIGRATE, TRUE)) {
        g_hash_table_foreach_remove(pending_ops, stop_recurring_action_by_rsc, rsc);
    }

    /* now do the op */
    crm_debug("Performing key=%s op=%s_%s_%d", transition, rsc->id, operation, op->interval);

    if (fsa_state != S_NOT_DC && fsa_state != S_POLICY_ENGINE && fsa_state != S_TRANSITION_ENGINE) {
        if (safe_str_neq(operation, "fail")
            && safe_str_neq(operation, CRMD_ACTION_STOP)) {
            crm_info("Discarding attempt to perform action %s on %s"
                     " in state %s", operation, rsc->id, fsa_state2string(fsa_state));
            op->rc = 99;
            op->op_status = PCMK_LRM_OP_ERROR;
            send_direct_ack(NULL, NULL, rsc, op, rsc->id);
            lrmd_free_event(op);
            free(op_id);
            return;
        }
    }

    op_id = generate_op_key(rsc->id, op->op_type, op->interval);

    if (op->interval > 0) {
        /* cancel it so we can then restart it without conflict */
        cancel_op_key(rsc, op_id, FALSE);
    }

    if (op->params) {
        char *key = NULL;
        char *value = NULL;
        GHashTableIter iter;

        g_hash_table_iter_init(&iter, op->params);
        while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
            params = lrmd_key_value_add(params, key, value);
        }
    }

    call_id = fsa_lrm_conn->cmds->exec(fsa_lrm_conn,
        rsc->id,
        op->op_type,
        op->user_data,
        op->interval,
        op->timeout,
        op->start_delay,
        lrmd_opt_notify_changes_only,
        params);

    if (call_id <= 0) {
        crm_err("Operation %s on %s failed: %d", operation, rsc->id, call_id);
        register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);

    } else {
        /* record all operations so we can wait
         * for them to complete during shutdown
         */
        char *call_id_s = make_stop_id(rsc->id, call_id);
        struct recurring_op_s *pending = NULL;

        pending = calloc(1, sizeof(struct recurring_op_s));
        crm_trace("Recording pending op: %d - %s %s", call_id, op_id, call_id_s);

        pending->call_id = call_id;
        pending->interval = op->interval;
        pending->op_type = strdup(operation);
        pending->op_key = strdup(op_id);
        pending->rsc_id = strdup(rsc->id);
        g_hash_table_replace(pending_ops, call_id_s, pending);

        if (op->interval > 0 && op->start_delay > START_DELAY_THRESHOLD) {
            char *uuid = NULL;
            int dummy = 0, target_rc = 0;

            crm_info("Faking confirmation of %s: execution postponed for over 5 minutes", op_id);

            decode_transition_key(op->user_data, &uuid, &dummy, &dummy, &target_rc);
            free(uuid);

            op->rc = target_rc;
            op->op_status = PCMK_LRM_OP_DONE;
            send_direct_ack(NULL, NULL, rsc, op, rsc->id);
        }
    }

    free(op_id);
    lrmd_free_event(op);
    return;
}

int last_resource_update = 0;

static void
cib_rsc_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    switch (rc) {
        case pcmk_ok:
        case -pcmk_err_diff_failed:
        case -pcmk_err_diff_resync:
            crm_trace("Resource update %d complete: rc=%d", call_id, rc);
            break;
        default:
            crm_warn("Resource update %d failed: (rc=%d) %s", call_id, rc, pcmk_strerror(rc));
    }

    if(call_id == last_resource_update) {
        last_resource_update = 0;
        trigger_fsa(fsa_source);
    }
}

static int
do_update_resource(lrmd_rsc_info_t * rsc, lrmd_event_data_t * op)
{
/*
  <status>
  <nodes_status id=uname>
  <lrm>
  <lrm_resources>
  <lrm_resource id=...>
  </...>
*/
    int rc = pcmk_ok;
    xmlNode *update, *iter = NULL;
    int call_opt = cib_quorum_override;

    CRM_CHECK(op != NULL, return 0);

    if (fsa_state == S_ELECTION || fsa_state == S_PENDING) {
        crm_info("Sending update to local CIB in state: %s", fsa_state2string(fsa_state));
        call_opt |= cib_scope_local;
    }

    iter = create_xml_node(iter, XML_CIB_TAG_STATUS);
    update = iter;
    iter = create_xml_node(iter, XML_CIB_TAG_STATE);

    set_uuid(iter, XML_ATTR_UUID, fsa_our_uname);
    crm_xml_add(iter, XML_ATTR_UNAME, fsa_our_uname);
    crm_xml_add(iter, XML_ATTR_ORIGIN, __FUNCTION__);

    iter = create_xml_node(iter, XML_CIB_TAG_LRM);
    crm_xml_add(iter, XML_ATTR_ID, fsa_our_uuid);

    iter = create_xml_node(iter, XML_LRM_TAG_RESOURCES);
    iter = create_xml_node(iter, XML_LRM_TAG_RESOURCE);
    crm_xml_add(iter, XML_ATTR_ID, op->rsc_id);

    build_operation_update(iter, rsc, op, __FUNCTION__);

    if (rsc) {
        crm_xml_add(iter, XML_ATTR_TYPE, rsc->type);
        crm_xml_add(iter, XML_AGENT_ATTR_CLASS, rsc->class);
        crm_xml_add(iter, XML_AGENT_ATTR_PROVIDER, rsc->provider);

        CRM_CHECK(rsc->type != NULL, crm_err("Resource %s has no value for type", op->rsc_id));
        CRM_CHECK(rsc->class != NULL, crm_err("Resource %s has no value for class", op->rsc_id));

    } else {
        crm_warn("Resource %s no longer exists in the lrmd", op->rsc_id);
        goto cleanup;
    }

    /* make it an asyncronous call and be done with it
     *
     * Best case:
     *   the resource state will be discovered during
     *   the next signup or election.
     *
     * Bad case:
     *   we are shutting down and there is no DC at the time,
     *   but then why were we shutting down then anyway?
     *   (probably because of an internal error)
     *
     * Worst case:
     *   we get shot for having resources "running" when the really weren't
     *
     * the alternative however means blocking here for too long, which
     * isnt acceptable
     */
    fsa_cib_update(XML_CIB_TAG_STATUS, update, call_opt, rc, NULL);

    if(rc > 0) {
        last_resource_update = rc;
    }

    /* the return code is a call number, not an error code */
    crm_trace("Sent resource state update message: %d for %s=%d on %s", rc,
              op->op_type, op->interval, op->rsc_id);
    fsa_register_cib_callback(rc, FALSE, NULL, cib_rsc_callback);

  cleanup:
    free_xml(update);
    return rc;
}

void
do_lrm_event(long long action,
             enum crmd_fsa_cause cause,
             enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data)
{
    CRM_CHECK(FALSE, return);
}

gboolean
process_lrm_event(lrmd_event_data_t * op)
{
    char *op_id = NULL;
    char *op_key = NULL;

    int update_id = 0;
    int log_level = LOG_ERR;
    gboolean removed = FALSE;
    lrmd_rsc_info_t *rsc = NULL;

    struct recurring_op_s *pending = NULL;

    CRM_CHECK(op != NULL, return FALSE);

    if (op->type == lrmd_event_disconnect) {
        lrm_connection_destroy();
        return TRUE;
    } else if (op->type != lrmd_event_exec_complete) {
        return TRUE;
    }

    CRM_CHECK(op->rsc_id != NULL, return FALSE);
    op_id = make_stop_id(op->rsc_id, op->call_id);
    pending = g_hash_table_lookup(pending_ops, op_id);
    op_key = generate_op_key(op->rsc_id, op->op_type, op->interval);
    rsc = fsa_lrm_conn->cmds->get_rsc_info(fsa_lrm_conn, op->rsc_id, 0);

    switch (op->op_status) {
        case PCMK_LRM_OP_ERROR:
        case PCMK_LRM_OP_PENDING:
        case PCMK_LRM_OP_NOTSUPPORTED:
            break;
        case PCMK_LRM_OP_CANCELLED:
            log_level = LOG_INFO;
            break;
        case PCMK_LRM_OP_DONE:
            log_level = LOG_NOTICE;
            break;
        case PCMK_LRM_OP_TIMEOUT:
            log_level = LOG_DEBUG_3;
            crm_err("LRM operation %s (%d) %s (timeout=%dms)",
                    op_key, op->call_id, services_lrm_status_str(op->op_status), op->timeout);
            break;
        default:
            crm_err("Mapping unknown status (%d) to ERROR", op->op_status);
            op->op_status = PCMK_LRM_OP_ERROR;
    }

    if (op->op_status == PCMK_LRM_OP_ERROR
        && (op->rc == PCMK_EXECRA_RUNNING_MASTER || op->rc == PCMK_EXECRA_NOT_RUNNING)) {
        /* Leave it up to the TE/PE to decide if this is an error */
        op->op_status = PCMK_LRM_OP_DONE;
        log_level = LOG_INFO;
    }

    if (op->op_status != PCMK_LRM_OP_CANCELLED) {
        if (safe_str_eq(op->op_type, RSC_NOTIFY)) {
            /* Keep notify ops out of the CIB */
            send_direct_ack(NULL, NULL, NULL, op, op->rsc_id);
        } else {
            update_id = do_update_resource(rsc, op);
        }
    } else if (op->interval == 0) {
        /* This will occur when "crm resource cleanup" is called while actions are in-flight */
        crm_err("Op %s (call=%d): Cancelled", op_key, op->call_id);
        send_direct_ack(NULL, NULL, NULL, op, op->rsc_id);

    } else if (pending == NULL) {
        /* Operations that are cancelled may safely be removed
         * from the pending op list before the lrmd completion event
         * is received. Only report non-cancelled ops here. */
        if (op->op_status != PCMK_LRM_OP_CANCELLED) {
            crm_err("Op %s (call=%d): No 'pending' entry", op_key, op->call_id);
        }
    } else if (op->user_data == NULL) {
        crm_err("Op %s (call=%d): No user data", op_key, op->call_id);

    } else if (pending->remove) {
        delete_op_entry(op, op->rsc_id, op_key, op->call_id);

    } else {
        /* Before a stop is called, no need to direct ack */
        crm_trace("Op %s (call=%d): no delete event required", op_key, op->call_id);
    }

    if ((op->interval == 0) && g_hash_table_remove(pending_ops, op_id)) {
        removed = TRUE;
        crm_trace("Op %s (call=%d, stop-id=%s): Confirmed", op_key, op->call_id, op_id);
    }

    if (op->op_status == PCMK_LRM_OP_DONE) {
        do_crm_log(log_level,
                   "LRM operation %s (call=%d, rc=%d, cib-update=%d, confirmed=%s) %s",
                   op_key, op->call_id, op->rc, update_id, removed ? "true" : "false",
                   lrmd_event_rc2str(op->rc));
    } else {
        do_crm_log(log_level,
                   "LRM operation %s (call=%d, status=%d, cib-update=%d, confirmed=%s) %s",
                   op_key, op->call_id, op->op_status, update_id, removed ? "true" : "false",
                   services_lrm_status_str(op->op_status));
    }

    if (op->output) {
        char *prefix = g_strdup_printf("%s_%s_%d:%d", op->rsc_id, op->op_type, op->interval, op->call_id);

        if (op->rc) {
            crm_log_output(LOG_NOTICE, prefix, op->output);
        } else {
            crm_log_output(LOG_DEBUG, prefix, op->output);
        }
        g_free(prefix);
    }

    if (op->rsc_deleted) {
        crm_info("Deletion of resource '%s' complete after %s", op->rsc_id, op_key);
        delete_rsc_entry(NULL, op->rsc_id, NULL, pcmk_ok, NULL);
    }

    /* If a shutdown was escalated while operations were pending, 
     * then the FSA will be stalled right now... allow it to continue
     */
    mainloop_set_trigger(fsa_source);
    update_history_cache(rsc, op);

    lrmd_free_rsc_info(rsc);
    free(op_key);
    free(op_id);

    return TRUE;
}
