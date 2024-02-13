/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_XML_COMPAT__H
#  define PCMK__CRM_COMMON_XML_COMPAT__H

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
int add_node_nocopy(xmlNode * parent, const char *name, xmlNode * child);

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

//! \deprecated Use name member directly
static inline const char *
crm_element_name(const xmlNode *xml)
{
    return (xml == NULL)? NULL : (const char *) xml->name;
}

//! \deprecated Do not use
char *crm_xml_escape(const char *text);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
xmlNode *copy_xml(xmlNode *src_node);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
xmlNode *add_node_copy(xmlNode *new_parent, xmlNode *xml_node);

//! \deprecated Do not use
void purge_diff_markers(xmlNode *a_node);

//! \deprecated Do not use
xmlNode *diff_xml_object(xmlNode *left, xmlNode *right, gboolean suppress);

//! \deprecated Do not use
xmlNode *subtract_xml_object(xmlNode *parent, xmlNode *left, xmlNode *right,
                             gboolean full, gboolean *changed,
                             const char *marker);

//! \deprecated Do not use
gboolean can_prune_leaf(xmlNode *xml_node);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
xmlNode *create_xml_node(xmlNode *parent, const char *name);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
xmlNode *pcmk_create_xml_text_node(xmlNode *parent, const char *name,
                                   const char *content);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
xmlNode *pcmk_create_html_node(xmlNode *parent, const char *element_name,
                               const char *id, const char *class_name,
                               const char *text);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
xmlNode *first_named_child(const xmlNode *parent, const char *name);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
xmlNode *find_xml_node(const xmlNode *root, const char *search_path,
                       gboolean must_find);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
xmlNode *crm_next_same_xml(const xmlNode *sibling);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
void xml_remove_prop(xmlNode *obj, const char *name);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
gboolean replace_xml_child(xmlNode *parent, xmlNode *child, xmlNode *update,
                           gboolean delete_only);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
gboolean update_xml_child(xmlNode *child, xmlNode *to_update);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
int find_xml_children(xmlNode **children, xmlNode *root, const char *tag,
                      const char *field, const char *value,
                      gboolean search_matches);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
xmlNode *get_xpath_object_relative(const char *xpath, xmlNode *xml_obj,
                                   int error_level);

//! \deprecated Do not use
void fix_plus_plus_recursive(xmlNode *target);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
gboolean add_message_xml(xmlNode *msg, const char *field, xmlNode *xml);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
xmlNode *get_message_xml(const xmlNode *msg, const char *field);

//! \deprecated Do not use
const char *xml_latest_schema(void);

//! \deprecated Do not use
const char *get_schema_name(int version);

//! \deprecated Do not use
int get_schema_version(const char *name);

//! \deprecated Do not use
int update_validation(xmlNode **xml_blob, int *best, int max,
                      gboolean transform, gboolean to_logs);

//! \deprecated Do not use
gboolean validate_xml(xmlNode *xml_blob, const char *validation,
                      gboolean to_logs);

//! \deprecated Do not use
gboolean validate_xml_verbose(const xmlNode *xml_blob);

//! \deprecated Do not use
gboolean cli_config_update(xmlNode **xml, int *best_version, gboolean to_logs);

//! \deprecated Do not use
static inline const char *
crm_map_element_name(const xmlNode *xml)
{
    if (xml == NULL) {
        return NULL;
    } else if (strcmp((const char *) xml->name, "master") == 0) {
        // Can't use PCMK__XE_PROMOTABLE_LEGACY because it's internal
        return PCMK_XE_CLONE;
    } else {
        return (const char *) xml->name;
    }
}

//! \deprecated Do not use
void copy_in_properties(xmlNode *target, const xmlNode *src);

//! \deprecated Do not use
void expand_plus_plus(xmlNode * target, const char *name, const char *value);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_XML_COMPAT__H
