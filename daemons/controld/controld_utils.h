/*
 * Copyright 2004-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRMD_UTILS__H
#  define CRMD_UTILS__H

#  include <crm/crm.h>
#  include <crm/common/xml.h>
#  include <crm/cib/internal.h>     // CIB_OP_MODIFY
#  include <controld_fsa.h>         // fsa_cib_conn
#  include <controld_alerts.h>

#  define FAKE_TE_ID	"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"


#  define fsa_cib_update(section, data, options, call_id, user_name)	\
	if(fsa_cib_conn != NULL) {					\
	    call_id = cib_internal_op(                                  \
		fsa_cib_conn, CIB_OP_MODIFY, NULL, section, data,	\
		NULL, options, user_name);				\
									\
	} else {							\
		crm_err("No CIB manager connection available");			\
	}

static inline void
fsa_cib_anon_update(const char *section, xmlNode *data) {
    if (fsa_cib_conn == NULL) {
        crm_err("No CIB connection available");
    } else {
        int opts = cib_scope_local | cib_quorum_override | cib_can_create;

        fsa_cib_conn->cmds->modify(fsa_cib_conn, section, data, opts);
    }
}

static inline void
fsa_cib_anon_update_discard_reply(const char *section, xmlNode *data) {
    if (fsa_cib_conn == NULL) {
        crm_err("No CIB connection available");
    } else {
        int opts = cib_scope_local | cib_quorum_override | cib_can_create | cib_discard_reply;

        fsa_cib_conn->cmds->modify(fsa_cib_conn, section, data, opts);
    }
}

extern gboolean fsa_has_quorum;
extern bool controld_shutdown_lock_enabled;
extern int last_peer_update;
extern int last_resource_update;

enum node_update_flags {
    node_update_none = 0x0000,
    node_update_quick = 0x0001,
    node_update_cluster = 0x0010,
    node_update_peer = 0x0020,
    node_update_join = 0x0040,
    node_update_expected = 0x0100,
    node_update_all = node_update_cluster|node_update_peer|node_update_join|node_update_expected,
};

crm_exit_t crmd_exit(crm_exit_t exit_code);
_Noreturn void crmd_fast_exit(crm_exit_t exit_code);
void pe_subsystem_free(void);
void controld_stop_sched_timer(void);
void controld_free_sched_timer(void);
void controld_expect_sched_reply(char *ref);

void fsa_dump_actions(uint64_t action, const char *text);
void fsa_dump_inputs(int log_level, const char *text, long long input_register);

gboolean update_dc(xmlNode * msg);
void crm_update_peer_join(const char *source, crm_node_t * node, enum crm_join_phase phase);
xmlNode *create_node_state_update(crm_node_t *node, int flags,
                                  xmlNode *parent, const char *source);
void populate_cib_nodes(enum node_update_flags flags, const char *source);
void crm_update_quorum(gboolean quorum, gboolean force_update);
void controld_close_attrd_ipc(void);
void update_attrd(const char *host, const char *name, const char *value, const char *user_name, gboolean is_remote_node);
void update_attrd_remote_node_removed(const char *host, const char *user_name);
void update_attrd_clear_failures(const char *host, const char *rsc,
                                 const char *op, const char *interval_spec,
                                 gboolean is_remote_node);

int crmd_join_phase_count(enum crm_join_phase phase);
void crmd_join_phase_log(int level);

void crmd_peer_down(crm_node_t *peer, bool full);
unsigned int cib_op_timeout(void);

bool feature_set_compatible(const char *dc_version, const char *join_version);
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

const char *get_node_id(xmlNode *lrm_rsc_op);

/* Convenience macro for registering a CIB callback
 * (assumes that data can be freed with free())
 */
#  define fsa_register_cib_callback(id, flag, data, fn) do {            \
    CRM_ASSERT(fsa_cib_conn);                                           \
    fsa_cib_conn->cmds->register_callback_full(                         \
        fsa_cib_conn, id, cib_op_timeout(),                             \
            flag, data, #fn, fn, free);                                 \
    } while(0)

#endif
