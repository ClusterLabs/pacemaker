/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PCMKI_PCMKI_OPTIONS__H
#define PCMK__PCMKI_PCMKI_OPTIONS__H

#include <crm/common/output_internal.h>

int pcmk__list_cluster_options(pcmk__output_t *out, bool all);
int pcmk__list_fencing_params(pcmk__output_t *out, bool all);

#endif  // PCMK__PCMKI_PCMKI_OPTIONS__H
