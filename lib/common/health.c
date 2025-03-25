/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>                          // NULL

#include <crm/common/scheduler.h>           // pcmk_scheduler_t
#include <crm/common/scheduler_internal.h>  // pcmk_scheduler_t private data
#include <crm/common/scores.h>              // pcmk_parse_score(), etc.

/*!
 * \internal
 * \brief Ensure a health strategy value is allowed
 *
 * \param[in] value  Configured health strategy
 *
 * \return true if \p value is an allowed health strategy value, otherwise false
 */
bool
pcmk__validate_health_strategy(const char *value)
{
    return pcmk__strcase_any_of(value,
                                PCMK_VALUE_NONE,
                                PCMK_VALUE_CUSTOM,
                                PCMK_VALUE_ONLY_GREEN,
                                PCMK_VALUE_PROGRESSIVE,
                                PCMK_VALUE_MIGRATE_ON_RED,
                                NULL);
}

/*!
 * \internal
 * \brief Parse node health strategy from a user-provided string
 *
 * \param[in] value  User-provided configuration value for node-health-strategy
 *
 * \return Node health strategy corresponding to \p value
 */
enum pcmk__health_strategy
pcmk__parse_health_strategy(const char *value)
{
    if (pcmk__str_eq(value, PCMK_VALUE_NONE,
                     pcmk__str_null_matches|pcmk__str_casei)) {
        return pcmk__health_strategy_none;
    }
    if (pcmk__str_eq(value, PCMK_VALUE_MIGRATE_ON_RED, pcmk__str_casei)) {
        return pcmk__health_strategy_no_red;
    }
    if (pcmk__str_eq(value, PCMK_VALUE_ONLY_GREEN, pcmk__str_casei)) {
        return pcmk__health_strategy_only_green;
    }
    if (pcmk__str_eq(value, PCMK_VALUE_PROGRESSIVE, pcmk__str_casei)) {
        return pcmk__health_strategy_progressive;
    }
    if (pcmk__str_eq(value, PCMK_VALUE_CUSTOM, pcmk__str_casei)) {
        return pcmk__health_strategy_custom;
    } else {
        pcmk__config_err("Using default of \"" PCMK_VALUE_NONE "\" for "
                         PCMK_OPT_NODE_HEALTH_STRATEGY
                         " because '%s' is not a valid value",
                         value);
        return pcmk__health_strategy_none;
    }
}

/*!
 * \internal
 * \brief Parse a health score from a cluster option value
 *
 * \param[in] option     Name of option to parse
 * \param[in] scheduler  Scheduler data
 *
 * \return Integer score parsed from \p option value (or 0 if invalid)
 */
int
pcmk__health_score(const char *option, const pcmk_scheduler_t *scheduler)
{
    int score = 0;
    int rc = pcmk_rc_ok;
    const char *value = NULL;

    CRM_CHECK((option != NULL) && (scheduler != NULL), return 0);

    value = pcmk__cluster_option(scheduler->priv->options, option);
    rc = pcmk_parse_score(value, &score, 0);
    if (rc != pcmk_rc_ok) {
        crm_warn("Using 0 for %s because '%s' is invalid: %s",
                 option, value, pcmk_rc_str(rc));
    }
    return score;
}
