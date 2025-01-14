/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>      // NULL
#include <glib.h>       // GHashTable, etc.

#include "pacemaker-attrd.h"

// Track the last known node XML ID for each node name
static GHashTable *node_xml_ids = NULL;

/*!
 * \internal
 * \brief Get last known XML ID for a given node
 *
 * \param[in] node_name  Name of node to check
 *
 * \return Last known XML ID for node (or NULL if none known)
 *
 * \note The return value may become invalid if attrd_set_node_xml_id() or
 *       attrd_forget_node_xml_id() is later called for \p node_name.
 */
const char *
attrd_get_node_xml_id(const char *node_name)
{
    if (node_xml_ids == NULL) {
        return NULL;
    }
    return g_hash_table_lookup(node_xml_ids, node_name);
}

/*!
 * \internal
 * \brief Set last known XML ID for a given node
 *
 * \param[in] node_name    Name of node to set
 * \param[in] node_xml_id  New XML ID to set for node
 */
void
attrd_set_node_xml_id(const char *node_name, const char *node_xml_id)
{
    if (node_xml_ids == NULL) {
        node_xml_ids = pcmk__strikey_table(free, free);
    }
    pcmk__insert_dup(node_xml_ids, node_name, node_xml_id);
}

/*!
 * \internal
 * \brief Forget last known XML ID for a given node
 *
 * \param[in] node_name    Name of node to forget
 */
void
attrd_forget_node_xml_id(const char *node_name)
{
    if (node_xml_ids == NULL) {
        return;
    }
    g_hash_table_remove(node_xml_ids, node_name);
}

/*!
 * \internal
 * \brief Free the node XML ID cache
 */
void
attrd_cleanup_xml_ids(void)
{
    if (node_xml_ids != NULL) {
        g_hash_table_destroy(node_xml_ids);
        node_xml_ids = NULL;
    }
}
