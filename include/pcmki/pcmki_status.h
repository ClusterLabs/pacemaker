/*
 * Copyright 2022-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef PCMK__INCLUDED_PACEMAKER_INTERNAL_H
#error "Include <pacemaker-internal.h> instead of <pcmki/pcmki_status.h> directly"
#endif

#ifndef PCMK__PCMKI_PCMKI_STATUS__H
#define PCMK__PCMKI_PCMKI_STATUS__H

#include <stdbool.h>
#include <stdint.h>

#include <crm/cib/cib_types.h>
#include <crm/common/scheduler.h>
#include <crm/common/ipc_pacemakerd.h>
#include <crm/common/output_internal.h>
#include <pcmki/pcmki_fence.h>

#ifdef __cplusplus
extern "C" {
#endif

int pcmk__output_cluster_status(pcmk_scheduler_t *scheduler,
                                stonith_t *stonith, cib_t *cib,
                                xmlNode *current_cib,
                                enum pcmk_pacemakerd_state pcmkd_state,
                                enum pcmk__fence_history fence_history,
                                uint32_t show, uint32_t show_opts,
                                const char *only_node, const char *only_rsc,
                                const char *neg_location_prefix);

int pcmk__status(pcmk__output_t *out, cib_t *cib,
                 enum pcmk__fence_history fence_history, uint32_t show,
                 uint32_t show_opts, const char *only_node,
                 const char *only_rsc, const char *neg_location_prefix,
                 unsigned int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif // PCMK__PCMKI_PCMKI_STATUS__H
