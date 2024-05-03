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

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use name member directly
static inline const char *
crm_element_name(const xmlNode *xml)
{
    return (xml == NULL)? NULL : (const char *) xml->name;
}

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

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
void crm_xml_set_id(xmlNode *xml, const char *format, ...) G_GNUC_PRINTF(2, 3);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
void crm_xml_sanitize_id(char *id);

//! \deprecated Do not use
char *calculate_on_disk_digest(xmlNode *input);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_XML_COMPAT__H
