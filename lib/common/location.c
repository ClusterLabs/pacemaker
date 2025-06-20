/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdlib.h>                 // free()
#include <glib.h>                   // gpointer, g_list_free_full()

#include <crm/common/scheduler.h>

/*!
 * \internal
 * \brief Free a location constraint
 *
 * \param[in,out] user_data  Location constraint to free
 */
void
pcmk__free_location(gpointer user_data)
{
    pcmk__location_t *location = user_data;

    g_list_free_full(location->nodes, pcmk__free_node_copy);
    free(location->id);
    free(location);
}
