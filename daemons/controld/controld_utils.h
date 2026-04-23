/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRMD_UTILS__H
#define CRMD_UTILS__H

#include <stdbool.h>
#include <stdint.h>                 // UINT32_C(), uint32_t

#include <glib.h>                   // gboolean
#include <libxml/tree.h>            // xmlNode

#include <crm/crm.h>
#include <crm/cluster.h>            // enum controld_join_phase
#include <crm/cluster/internal.h>   // pcmk__node_status_t
#include <crm/common/xml.h>

#  define FAKE_TE_ID	"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

//! Flags determining how the controller updates node information in the CIB
enum controld_node_update_flags {
    //! This flag has no effect
    controld_node_update_none     = UINT32_C(0),

    //! Skip loading the node list from the cluster layer
    controld_node_update_quick    = (UINT32_C(1) << 0),

    //! Update \c PCMK__XA_IN_CCM with the time the node became a cluster member
    controld_node_update_cluster  = (UINT32_C(1) << 1),

    //! Update \c PCMK_XA_CRMD with the time the node joined the CPG
    controld_node_update_peer     = (UINT32_C(1) << 2),

    //! Update \c PCMK__XA_JOIN with the node's join state
    controld_node_update_join     = (UINT32_C(1) << 3),

    //! Update \c PCMK_XA_EXPECTED with the node's expected join state
    controld_node_update_expected = (UINT32_C(1) << 4),

    //! Convenience alias to update all of the attributes mentioned above
    controld_node_update_all      = controld_node_update_cluster
                                    |controld_node_update_peer
                                    |controld_node_update_join
                                    |controld_node_update_expected,
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
void crm_update_peer_join(const char *source, pcmk__node_status_t *node,
                          enum controld_join_phase phase);
xmlNode *create_node_state_update(pcmk__node_status_t *node, uint32_t flags,
                                  xmlNode *parent, const char *source);
void populate_cib_nodes(uint32_t flags, const char *source);
void crm_update_quorum(gboolean quorum, gboolean force_update);
void controld_close_attrd_ipc(void);
void update_attrd(const char *host, const char *name, const char *value,
                  bool is_remote_node);
void update_attrd_list(GList *attrs, uint32_t opts);
void controld_purge_node_attrs(const char *node_name, bool from_cache);
void update_attrd_clear_failures(const char *host, const char *rsc,
                                 const char *op, const char *interval_spec,
                                 gboolean is_remote_node);

int crmd_join_phase_count(enum controld_join_phase phase);
void crmd_join_phase_log(int level);

void crmd_peer_down(pcmk__node_status_t *peer, bool full);

bool feature_set_compatible(const char *dc_version, const char *join_version);
bool controld_is_local_node(const char *name);
pcmk__node_status_t *controld_get_local_node_status(void);
const char *get_node_id(xmlNode *lrm_rsc_op);

#endif
