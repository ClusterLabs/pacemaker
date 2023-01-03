/*
 * Copyright 2004-2023 the Pacemaker project contributors
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
 * \param[in,out] data_set  Cluster working set
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
        int score = char2score((const char *) value);
        int *health = (int *) user_data;

        *health = pcmk__add_scores(score, *health);
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
pe__sum_node_health_scores(const pe_node_t *node, int base_health)
{
    CRM_ASSERT(node != NULL);
    g_hash_table_foreach(node->details->attrs, add_node_health_value,
                         &base_health);
    return base_health;
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
pe__node_health(pe_node_t *node)
{
    GHashTableIter iter;
    const char *name = NULL;
    const char *value = NULL;
    enum pcmk__health_strategy strategy;
    int score = 0;
    int rc = 1;

    CRM_ASSERT(node != NULL);

    strategy = pe__health_strategy(node->details->data_set);
    if (strategy == pcmk__health_strategy_none) {
        return rc;
    }

    g_hash_table_iter_init(&iter, node->details->attrs);
    while (g_hash_table_iter_next(&iter, (gpointer *) &name,
                                  (gpointer *) &value)) {
        if (pcmk__starts_with(name, "#health")) {
            /* It's possible that pcmk__score_red equals pcmk__score_yellow,
             * or pcmk__score_yellow equals pcmk__score_green, so check the
             * textual value first to be able to distinguish those.
             */
            if (pcmk__str_eq(value, PCMK__VALUE_RED, pcmk__str_casei)) {
                return -1;
            } else if (pcmk__str_eq(value, PCMK__VALUE_YELLOW,
                                    pcmk__str_casei)) {
                rc = 0;
                continue;
            }

            // The value is an integer, so compare numerically
            score = char2score(value);
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
