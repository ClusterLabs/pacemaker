/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PCMKI_PCMKI_RESULT_CODE__H
#  define PCMK__PCMKI_PCMKI_RESULT_CODE__H

#include <stdint.h>

#include <crm/crm.h>
#include <crm/common/output_internal.h>

int pcmk__show_result_code(pcmk__output_t *out, int code,
                           enum pcmk_result_type type, uint32_t flags);
int pcmk__list_result_codes(pcmk__output_t *out, enum pcmk_result_type type,
                            uint32_t flags);

#endif // PCMK__PCMKI_PCMKI_RESULT_CODE__H
