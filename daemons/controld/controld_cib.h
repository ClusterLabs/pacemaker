/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CONTROLD_CIB__H
#define PCMK__CONTROLD_CIB__H

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/cib/internal.h>   // PCMK__CIB_REQUEST_MODIFY
#include <controld_globals.h>   // controld_globals.cib_conn

#define fsa_cib_update(section, data, options, call_id)                     \
    if (controld_globals.cib_conn != NULL) {                                \
        call_id = cib_internal_op(controld_globals.cib_conn,                \
                                  PCMK__CIB_REQUEST_MODIFY, NULL, section,  \
                                  data, NULL, options, NULL);               \
                                                                            \
    } else {                                                                \
        crm_err("No CIB manager connection available");                     \
    }

static inline void
fsa_cib_anon_update(const char *section, xmlNode *data) {
    if (controld_globals.cib_conn == NULL) {
        crm_err("No CIB connection available");
    } else {
        const int opts = cib_scope_local|cib_quorum_override|cib_can_create;

        controld_globals.cib_conn->cmds->modify(controld_globals.cib_conn,
                                                section, data, opts);
    }
}

static inline void
fsa_cib_anon_update_discard_reply(const char *section, xmlNode *data) {
    if (controld_globals.cib_conn == NULL) {
        crm_err("No CIB connection available");
    } else {
        const int opts = cib_scope_local
                         |cib_quorum_override
                         |cib_can_create
                         |cib_discard_reply;

        controld_globals.cib_conn->cmds->modify(controld_globals.cib_conn,
                                                section, data, opts);
    }
}

unsigned int cib_op_timeout(void);
bool controld_action_is_recordable(const char *action);

// Subsections of node_state
enum controld_section_e {
    controld_section_lrm,
    controld_section_lrm_unlocked,
    controld_section_attrs,
    controld_section_all,
    controld_section_all_unlocked
};

void controld_delete_node_state(const char *uname,
                                enum controld_section_e section, int options);
int controld_delete_resource_history(const char *rsc_id, const char *node,
                                     const char *user_name, int call_options);

/* Convenience macro for registering a CIB callback
 * (assumes that data can be freed with free())
 */
#  define fsa_register_cib_callback(id, data, fn) do {                      \
    cib_t *cib_conn = controld_globals.cib_conn;                            \
                                                                            \
    CRM_ASSERT(cib_conn != NULL);                                           \
    cib_conn->cmds->register_callback_full(cib_conn, id, cib_op_timeout(),  \
                                           FALSE, data, #fn, fn, free);     \
    } while(0)

void controld_add_resource_history_xml_as(const char *func, xmlNode *parent,
                                          const lrmd_rsc_info_t *rsc,
                                          lrmd_event_data_t *op,
                                          const char *node_name);

#define controld_add_resource_history_xml(parent, rsc, op, node_name)   \
    controld_add_resource_history_xml_as(__func__, (parent), (rsc),     \
                                         (op), (node_name))

bool controld_record_pending_op(const char *node_name,
                                const lrmd_rsc_info_t *rsc,
                                lrmd_event_data_t *op);

void controld_update_resource_history(const char *node_name,
                                      const lrmd_rsc_info_t *rsc,
                                      lrmd_event_data_t *op, time_t lock_time);

void controld_delete_action_history(const lrmd_event_data_t *op);

void controld_cib_delete_last_failure(const char *rsc_id, const char *node,
                                      const char *action, guint interval_ms);

void controld_delete_action_history_by_key(const char *rsc_id, const char *node,
                                           const char *key, int call_id);

void controld_disconnect_cib_manager(void);

int crmd_cib_smart_opt(void);

#endif // PCMK__CONTROLD_CIB__H
