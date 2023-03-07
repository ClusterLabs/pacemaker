/*
 * Copyright 2004-2023 the Pacemaker project contributors
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

#  define FAKE_TE_ID	"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

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
void controld_shutdown_schedulerd_ipc(void);
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
void update_attrd_list(GList *attrs, uint32_t opts);
void update_attrd_remote_node_removed(const char *host, const char *user_name);
void update_attrd_clear_failures(const char *host, const char *rsc,
                                 const char *op, const char *interval_spec,
                                 gboolean is_remote_node);

int crmd_join_phase_count(enum crm_join_phase phase);
void crmd_join_phase_log(int level);

void crmd_peer_down(crm_node_t *peer, bool full);

bool feature_set_compatible(const char *dc_version, const char *join_version);

const char *get_node_id(xmlNode *lrm_rsc_op);

#endif
