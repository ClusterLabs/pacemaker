/*
 * Copyright 2004-2025 the Pacemaker project contributors
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
#include <libxml/xpath.h>           // xmlXPathObject

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
void crm_xml_sanitize_id(char *id);

//! \deprecated Do not use
char *calculate_on_disk_digest(xmlNode *input);

//! \deprecated Do not use
char *calculate_operation_digest(xmlNode *input, const char *version);

//! \deprecated Do not use
char *calculate_xml_versioned_digest(xmlNode *input, gboolean sort,
                                     gboolean do_filter, const char *version);

//! \deprecated Do not use
xmlXPathObjectPtr xpath_search(const xmlNode *xml_top, const char *path);

//! \deprecated Do not use
static inline int numXpathResults(xmlXPathObjectPtr xpathObj)
{
    if ((xpathObj == NULL) || (xpathObj->nodesetval == NULL)) {
        return 0;
    }
    return xpathObj->nodesetval->nodeNr;
}

//! \deprecated Do not use
xmlNode *getXpathResult(xmlXPathObjectPtr xpathObj, int index);

//! \deprecated Do not use
void freeXpathObject(xmlXPathObjectPtr xpathObj);

//! \deprecated Do not use
void dedupXpathResults(xmlXPathObjectPtr xpathObj);

//! \deprecated Do not use
void crm_foreach_xpath_result(xmlNode *xml, const char *xpath,
                              void (*helper)(xmlNode*, void*), void *user_data);

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
xmlNode *get_xpath_object(const char *xpath, xmlNode *xml_obj, int error_level);

//! \deprecated Do not use
typedef const xmlChar *pcmkXmlStr;

//! \deprecated Do not use
bool xml_tracking_changes(xmlNode *xml);

//! \deprecated Do not use
bool xml_document_dirty(xmlNode *xml);

//! \deprecated Do not use
void xml_accept_changes(xmlNode *xml);

//! \deprecated Do not use
void xml_track_changes(xmlNode *xml, const char *user, xmlNode *acl_source,
                       bool enforce_acls);

//! \deprecated Do not use
void xml_calculate_changes(xmlNode *old_xml, xmlNode *new_xml);

//! \deprecated Do not use
void xml_calculate_significant_changes(xmlNode *old_xml, xmlNode *new_xml);

//! \deprecated Do not use
bool xml_patch_versions(const xmlNode *patchset, int add[3], int del[3]);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_XML_COMPAT__H
