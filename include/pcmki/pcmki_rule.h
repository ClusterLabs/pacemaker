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

#include <crm/common/internal.h>
#include <crm/common/iso8601.h>
#include <crm/crm.h>

#ifdef __cplusplus
extern "C" {
#endif

int pcmk__check_rules(pcmk__output_t *out, xmlNodePtr input,
                      const crm_time_t *date_time, const char *const *rule_ids);

/*!
 * \internal
 * \brief Check whether a given rule is in effect
 *
 * \param[in,out] out       Output object
 * \param[in]     input     The CIB XML to check (if \c NULL, use current CIB)
 * \param[in]     date      Check whether the rule is in effect at this date and
 *                          time (if \c NULL, use current date and time)
 * \param[in]     rule_ids  The ID of the rule to check
 *
 * \return Standard Pacemaker return code
 */
static inline int
pcmk__check_rule(pcmk__output_t *out, xmlNodePtr input, const crm_time_t *date,
                 const char *rule_id)
{
    const char *rule_ids[] = {rule_id, NULL};
    return pcmk__check_rules(out, input, date, rule_ids);
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__PCMKI_PCMKI_RULE__H
