/*
 * Copyright 2022-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef PCMK__INCLUDED_PACEMAKER_INTERNAL_H
#error "Include <pacemaker-internal.h> instead of <pcmki/pcmki_rule.h> directly"
#endif

#ifndef PCMK__PCMKI_PCMKI_RULE__H
#define PCMK__PCMKI_PCMKI_RULE__H

#include <libxml/tree.h>                // xmlNode

#include <crm/common/internal.h>        // pcmk__output_t
#include <crm/common/iso8601.h>         // crm_time_t

#ifdef __cplusplus
extern "C" {
#endif

int pcmk__check_rules(pcmk__output_t *out, xmlNode *input,
                      const crm_time_t *date_time, const char **rule_ids);

#ifdef __cplusplus
}
#endif

#endif // PCMK__PCMKI_PCMKI_RULE__H
