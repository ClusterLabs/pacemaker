/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>
#include "pe_status_private.h"

/*!
 * \internal
 * \brief Set the node health values to use for "red", "yellow", and "green"
 *
 * \param[in] data_set  Cluster working set
 */
void
pe__unpack_node_health_scores(pe_working_set_t *data_set)
{
    switch (pe__health_strategy(data_set)) {
        case pcmk__health_strategy_none:
            pcmk__score_red = 0;
            pcmk__score_yellow = 0;
            pcmk__score_green = 0;
            break;

        case pcmk__health_strategy_no_red:
            pcmk__score_red = -INFINITY;
            pcmk__score_yellow = 0;
            pcmk__score_green = 0;
            break;

        case pcmk__health_strategy_only_green:
            pcmk__score_red = -INFINITY;
            pcmk__score_yellow = -INFINITY;
            pcmk__score_green = 0;
            break;

        default: // progressive or custom
            pcmk__score_red = pe__health_score(PCMK__OPT_NODE_HEALTH_RED,
                                               data_set);
            pcmk__score_green = pe__health_score(PCMK__OPT_NODE_HEALTH_GREEN,
                                                 data_set);
            pcmk__score_yellow = pe__health_score(PCMK__OPT_NODE_HEALTH_YELLOW,
                                                  data_set);
            break;
    }

    if ((pcmk__score_red != 0) || (pcmk__score_yellow != 0)
        || (pcmk__score_green != 0)) {
        crm_debug("Values of node health scores: "
                  PCMK__VALUE_RED "=%d "
                  PCMK__VALUE_YELLOW "=%d "
                  PCMK__VALUE_GREEN "=%d",
                  pcmk__score_red, pcmk__score_yellow, pcmk__score_green);
    }
}
