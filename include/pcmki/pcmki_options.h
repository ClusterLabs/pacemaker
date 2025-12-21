/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PCMKI_PCMKI_OPTIONS__H
#define PCMK__PCMKI_PCMKI_OPTIONS__H

#include <stdbool.h>

#include <crm/common/output_internal.h>

#ifdef __cplusplus
extern "C" {
#endif

int pcmk__list_cluster_options(pcmk__output_t *out, bool all);
int pcmk__list_fencing_params(pcmk__output_t *out, bool all);
int pcmk__list_primitive_meta(pcmk__output_t *out, bool all);

#ifdef __cplusplus
}
#endif

#endif  // PCMK__PCMKI_PCMKI_OPTIONS__H
