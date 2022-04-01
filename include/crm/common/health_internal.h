/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_HEALTH_INTERNAL__H
#define PCMK__CRM_COMMON_HEALTH_INTERNAL__H

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \internal
 * \brief Possible node health strategies
 *
 * \note It would be nice to use this in pe_working_set_t but that will have to
 *       wait for an API backward compatibility break.
 */
enum pcmk__health_strategy {
    pcmk__health_strategy_none,
    pcmk__health_strategy_no_red,
    pcmk__health_strategy_only_green,
    pcmk__health_strategy_progressive,
    pcmk__health_strategy_custom,
};

enum pcmk__health_strategy pcmk__parse_health_strategy(const char *value);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_HEALTH_INTERNAL__H
