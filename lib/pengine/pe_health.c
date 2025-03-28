/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/scores.h>      // pcmk_parse_score(), etc.
#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>
#include "pe_status_private.h"

/*!
 * \internal
 * \brief Set the node health values to use for \c PCMK_VALUE_RED,
 *        \c PCMK_VALUE_YELLOW, and \c PCMK_VALUE_GREEN
 *
 * \param[in,out] scheduler  Scheduler data
 */
void
pe__unpack_node_health_scores(pcmk_scheduler_t *scheduler)
{
    switch (pe__health_strategy(scheduler)) {
        case pcmk__health_strategy_none:
            pcmk__score_red = 0;
            pcmk__score_yellow = 0;
            pcmk__score_green = 0;
            break;

        case pcmk__health_strategy_no_red:
            pcmk__score_red = -PCMK_SCORE_INFINITY;
            pcmk__score_yellow = 0;
            pcmk__score_green = 0;
            break;

        case pcmk__health_strategy_only_green:
            pcmk__score_red = -PCMK_SCORE_INFINITY;
            pcmk__score_yellow = -PCMK_SCORE_INFINITY;
            pcmk__score_green = 0;
            break;

        default: // progressive or custom
            pcmk__score_red = pcmk__health_score(PCMK_OPT_NODE_HEALTH_RED,
                                                 scheduler);
            pcmk__score_green = pcmk__health_score(PCMK_OPT_NODE_HEALTH_GREEN,
                                                   scheduler);
            pcmk__score_yellow = pcmk__health_score(PCMK_OPT_NODE_HEALTH_YELLOW,
                                                    scheduler);
            break;
    }

    if ((pcmk__score_red != 0) || (pcmk__score_yellow != 0)
        || (pcmk__score_green != 0)) {
        pcmk__debug("Values of node health scores: "
                    PCMK_VALUE_RED "=%d "
                    PCMK_VALUE_YELLOW "=%d "
                    PCMK_VALUE_GREEN "=%d",
                    pcmk__score_red, pcmk__score_yellow, pcmk__score_green);
    }
}

struct health_sum {
    const pcmk_node_t *node; // Node that health score is being summed for
    int sum;                 // Sum of health scores checked so far
};

/*!
 * \internal
 * \brief Add node attribute value to an integer, if it is a health attribute
 *
 * \param[in]     key        Name of node attribute
 * \param[in]     value      String value of node attribute
 * \param[in,out] user_data  Address of integer to which \p value should be
 *                           added if \p key is a node health attribute
 */
static void
add_node_health_value(gpointer key, gpointer value, gpointer user_data)
{
    if (pcmk__starts_with((const char *) key, "#health")) {
        struct health_sum *health_sum = user_data;
        int score = 0;
        int rc = pcmk_parse_score((const char *) value, &score, 0);

        if (rc != pcmk_rc_ok) {
            pcmk__warn("Ignoring %s for %s because '%s' is not a valid value: "
                       "%s",
                       (const char *) key, pcmk__node_name(health_sum->node),
                       (const char *) value, pcmk_rc_str(rc));
            return;
        }

        health_sum->sum = pcmk__add_scores(score, health_sum->sum);
        pcmk__trace("Combined '%s' into node health score (now %s)",
                    (const char *) value, pcmk_readable_score(health_sum->sum));
    }
}

/*!
 * \internal
 * \brief Sum a node's health attribute scores
 *
 * \param[in] node         Node whose health attributes should be added
 * \param[in] base_health  Add this number to the total
 *
 * \return Sum of all health attribute scores of \p node plus \p base_health
 */
int
pe__sum_node_health_scores(const pcmk_node_t *node, int base_health)
{
    struct health_sum health_sum = { node, base_health, };

    pcmk__assert(node != NULL);
    g_hash_table_foreach(node->priv->attrs, add_node_health_value,
                         &health_sum);
    return health_sum.sum;
}

/*!
 * \internal
 * \brief Check the general health status for a node
 *
 * \param[in,out] node  Node to check
 *
 * \return  A negative value if any health attribute for \p node is red,
 *          otherwise 0 if any attribute is yellow, otherwise a positive value.
 */
int
pe__node_health(pcmk_node_t *node)
{
    GHashTableIter iter;
    const char *name = NULL;
    const char *value = NULL;
    enum pcmk__health_strategy strategy;
    int score = 0;
    int rc = 1;

    pcmk__assert(node != NULL);

    strategy = pe__health_strategy(node->priv->scheduler);
    if (strategy == pcmk__health_strategy_none) {
        return rc;
    }

    g_hash_table_iter_init(&iter, node->priv->attrs);
    while (g_hash_table_iter_next(&iter, (gpointer *) &name,
                                  (gpointer *) &value)) {
        if (pcmk__starts_with(name, "#health")) {
            int parse_rc = pcmk_rc_ok;

            /* It's possible that pcmk__score_red equals pcmk__score_yellow,
             * or pcmk__score_yellow equals pcmk__score_green, so check the
             * textual value first to be able to distinguish those.
             */
            if (pcmk__str_eq(value, PCMK_VALUE_RED, pcmk__str_casei)) {
                return -1;
            } else if (pcmk__str_eq(value, PCMK_VALUE_YELLOW,
                                    pcmk__str_casei)) {
                rc = 0;
                continue;
            }

            parse_rc = pcmk_parse_score(value, &score, 0);
            if (parse_rc != pcmk_rc_ok) {
                pcmk__warn("Ignoring %s for %s because '%s' is not a valid "
                           "value: %s",
                           name, pcmk__node_name(node), value,
                           pcmk_rc_str(parse_rc));
                continue;
            }

            // The value is an integer, so compare numerically
            if (score <= pcmk__score_red) {
                return -1;
            } else if ((score <= pcmk__score_yellow)
                       && (pcmk__score_yellow != pcmk__score_green)) {
                rc = 0;
            }
        }
    }
    return rc;
}
