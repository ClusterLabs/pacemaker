/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRMD_UTILS__H
#  define CRMD_UTILS__H

#  include <crm/crm.h>
#  include <crm/transition.h>
#  include <crm/common/xml.h>
#  include <crm/cib/internal.h> /* For CIB_OP_MODIFY */
#  include "controld_alerts.h"

#  define FAKE_TE_ID	"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"


#  define fsa_cib_update(section, data, options, call_id, user_name)	\
	if(fsa_cib_conn != NULL) {					\
	    call_id = cib_internal_op(                                  \
		fsa_cib_conn, CIB_OP_MODIFY, NULL, section, data,	\
		NULL, options, user_name);				\
									\
	} else {							\
		crm_err("No CIB connection available");			\
	}

#  define fsa_cib_anon_update(section, data, options)			\
	if(fsa_cib_conn != NULL) {					\
	    fsa_cib_conn->cmds->modify(					\
		fsa_cib_conn, section, data, options);			\
									\
	} else {							\
		crm_err("No CIB connection available");			\
	}

extern gboolean fsa_has_quorum;
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

gboolean crm_timer_stop(fsa_timer_t * timer);
gboolean crm_timer_start(fsa_timer_t * timer);
gboolean crm_timer_popped(gpointer data);
gboolean is_timer_started(fsa_timer_t * timer);

crm_exit_t crmd_exit(crm_exit_t exit_code);
crm_exit_t crmd_fast_exit(crm_exit_t exit_code);
void pe_subsystem_free(void);

void fsa_dump_actions(long long action, const char *text);
void fsa_dump_inputs(int log_level, const char *text, long long input_register);

gboolean update_dc(xmlNode * msg);
void crm_update_peer_join(const char *source, crm_node_t * node, enum crm_join_phase phase);
xmlNode *create_node_state_update(crm_node_t *node, int flags,
                                  xmlNode *parent, const char *source);
void populate_cib_nodes(enum node_update_flags flags, const char *source);
void crm_update_quorum(gboolean quorum, gboolean force_update);
void erase_status_tag(const char *uname, const char *tag, int options);
void update_attrd(const char *host, const char *name, const char *value, const char *user_name, gboolean is_remote_node);
void update_attrd_remote_node_removed(const char *host, const char *user_name);
void update_attrd_clear_failures(const char *host, const char *rsc,
                                 const char *op, const char *interval_spec,
                                 gboolean is_remote_node);

int crmd_join_phase_count(enum crm_join_phase phase);
void crmd_join_phase_log(int level);

const char *get_timer_desc(fsa_timer_t * timer);
void st_fail_count_reset(const char * target);
void st_fail_count_increment(const char *target);
void abort_for_stonith_failure(enum transition_action abort_action,
                               const char *target, xmlNode *reason);
void crmd_peer_down(crm_node_t *peer, bool full);
unsigned int cib_op_timeout(void);

bool feature_set_compatible(const char *dc_version, const char *join_version);

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
