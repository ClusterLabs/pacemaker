/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef PCMK__PCMKI_PCMKI_STATUS__H
#define PCMK__PCMKI_PCMKI_STATUS__H

#include <stdbool.h>
#include <stdint.h>

#include <crm/cib/cib_types.h>
#include <crm/pengine/pe_types.h>
#include <crm/common/output_internal.h>
#include <pcmki/pcmki_fence.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \internal
 * \brief Print one-line status suitable for use with monitoring software
 *
 * \param[in] data_set  Working set of CIB state
 *
 * \return Standard Pacemaker return code
 *
 * \note This function's output (and the return code when the program exits)
 *       should conform to https://www.monitoring-plugins.org/doc/guidelines.html
 *
 * \note This function is planned to be deprecated and then removed in the
 *       future.  It should only be called from crm_mon, and no additional
 *       callers should be added.
 */
int pcmk__output_simple_status(pcmk__output_t *out, pe_working_set_t *data_set);

int pcmk__output_cluster_status(pcmk__output_t *out, stonith_t *st, cib_t *cib,
                                xmlNode *current_cib, enum pcmk__fence_history fence_history,
                                uint32_t show, uint32_t show_opts, char *only_node,
                                char *only_rsc, const char *neg_location_prefix,
                                bool simple_output);

int pcmk__status(pcmk__output_t *out, cib_t *cib,
                 enum pcmk__fence_history fence_history, uint32_t show,
                 uint32_t show_opts, char *only_node, char *only_rsc,
                 const char *neg_location_prefix, bool simple_output,
                 enum pcmk_pacemakerd_state *pcmkd_state);

#ifdef __cplusplus
}
#endif

#endif
