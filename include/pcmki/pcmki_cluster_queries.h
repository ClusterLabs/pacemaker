/*
 * Copyright 2020-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PCMKI_PCMKI_CLUSTER_QUERIES__H
#  define PCMK__PCMKI_PCMKI_CLUSTER_QUERIES__H

#include <stdbool.h>
#include <stdint.h>

#include <crm/crm.h>
#include <crm/common/output_internal.h>
#include <crm/common/ipc_controld.h>
#include <crm/common/ipc_pacemakerd.h>

// CIB queries
int pcmk__list_nodes(pcmk__output_t *out, const char *node_types,
                     bool bash_export);

// Controller queries
int pcmk__controller_status(pcmk__output_t *out, const char *node_name,
                            unsigned int message_timeout_ms);
int pcmk__designated_controller(pcmk__output_t *out,
                                unsigned int message_timeout_ms);
int pcmk__pacemakerd_status(pcmk__output_t *out, const char *ipc_name,
                            unsigned int message_timeout_ms, bool show_output,
                            enum pcmk_pacemakerd_state *state);
int pcmk__query_node_info(pcmk__output_t *out, uint32_t *node_id,
                          char **node_name, char **uuid, char **state,
                          bool *have_quorum, bool *is_remote, bool show_output,
                          unsigned int message_timeout_ms);

/*!
 * \internal
 * \brief Get the node name corresponding to a node ID from the controller
 *
 * \param[in,out] out                 Output object
 * \param[in]     node_id             ID of node whose name to get (or 0 for
 *                                    the local node)
 * \param[out]    node_name           If not \p NULL, where to store the node
 *                                    name
 * \param[in]     message_timeout_ms  How long to wait for a reply from the
 *                                    \p pacemaker-controld API. If 0,
 *                                    \p pcmk_ipc_dispatch_sync will be used.
 *                                    Otherwise, \p pcmk_ipc_dispatch_poll will
 *                                    be used.
 *
 * \return Standard Pacemaker return code
 *
 * \note The caller is responsible for freeing \p *node_name using \p free().
 */
static inline int
pcmk__query_node_name(pcmk__output_t *out, uint32_t nodeid, char **node_name,
                      unsigned int message_timeout_ms)
{
    return pcmk__query_node_info(out, &nodeid, node_name, NULL, NULL, NULL,
                                 NULL, false, message_timeout_ms);
}

// pacemakerd queries
int pcmk__pacemakerd_status(pcmk__output_t *out, const char *ipc_name,
                            unsigned int message_timeout_ms, bool show_output,
                            enum pcmk_pacemakerd_state *state);

#endif
