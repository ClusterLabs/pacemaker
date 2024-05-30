/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_XML_COMPAT__H
#define PCMK__CRM_COMMON_XML_COMPAT__H

#include <glib.h>               // gboolean
#include <libxml/tree.h>        // xmlNode

#include <crm/common/nvpair.h>  // crm_xml_add()
#include <crm/common/xml_names.h>   // PCMK_XE_CLONE

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker XML API
 * \ingroup core
 * \deprecated Do not include this header directly. The XML APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Do not use (will be removed in a future release)
#define XML_PARANOIA_CHECKS 0

//! \deprecated This function will be removed in a future release
xmlDoc *getDocPtr(xmlNode *node);

//! \deprecated This function will be removed in a future release
xmlNode *find_entity(xmlNode *parent, const char *node_name, const char *id);

//! \deprecated This function will be removed in a future release
char *xml_get_path(const xmlNode *xml);

//! \deprecated This function will be removed in a future release
void xml_log_changes(uint8_t level, const char *function, const xmlNode *xml);

//! \deprecated This function will be removed in a future release
void xml_log_patchset(uint8_t level, const char *function, const xmlNode *xml);

//!  \deprecated Use xml_apply_patchset() instead
gboolean apply_xml_diff(xmlNode *old_xml, xmlNode *diff, xmlNode **new_xml);

//! \deprecated Do not use (will be removed in a future release)
void crm_destroy_xml(gpointer data);

//! \deprecated Check children member directly
gboolean xml_has_children(const xmlNode *root);

//! \deprecated Use crm_xml_add() with "true" or "false" instead
static inline const char *
crm_xml_add_boolean(xmlNode *node, const char *name, gboolean value)
{
    return crm_xml_add(node, name, (value? "true" : "false"));
}

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use name member directly
static inline const char *
crm_element_name(const xmlNode *xml)
{
    return (xml == NULL)? NULL : (const char *) xml->name;
}

//! \deprecated Do not use
char *crm_xml_escape(const char *text);

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
xmlNode *copy_xml(xmlNode *src_node);

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
gboolean cli_config_update(xmlNode **xml, int *best_version, gboolean to_logs);

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Call \c crm_log_init() or \c crm_log_cli_init() instead
void crm_xml_init(void);

//! \deprecated Exit with \c crm_exit() instead
void crm_xml_cleanup(void);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
void pcmk_free_xml_subtree(xmlNode *xml);

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
void free_xml(xmlNode *child);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
xmlNode *expand_idref(xmlNode *input, xmlNode *top);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_XML_COMPAT__H
