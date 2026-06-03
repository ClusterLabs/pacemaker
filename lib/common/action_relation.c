/*
 * Copyright 2024-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdlib.h>                 // free()

#include <crm/common/scheduler.h>

/*!
 * \internal
 * \brief Free an action relation
 *
 * \param[in,out] user_data  Action relation to free
 */
void
pcmk__free_action_relation(void *user_data)
{
    pcmk__action_relation_t *relation = user_data;

    free(relation->task1);
    free(relation->task2);
    free(relation);
}
