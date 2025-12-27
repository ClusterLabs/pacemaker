/*
 * Copyright 2017-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <xml_element_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_XML_ELEMENT_INTERNAL__H
#define PCMK__CRM_COMMON_XML_ELEMENT_INTERNAL__H

/*
 * Internal-only wrappers for and extensions to libxml2 for processing XML
 * elements
 */

#include <stdbool.h>                        // bool
#include <stdint.h>                         // uint32_t
#include <stdio.h>                          // NULL
#include <string.h>                         // strcmp()

#include <glib.h>                           // guint
#include <libxml/tree.h>                    // xmlNode, etc.

#include <crm/common/iso8601.h>             // crm_time_t
#include <crm/common/strings_internal.h>    // pcmk__str_copy()
#include <crm/common/xml_names.h>           // PCMK_XA_ID

#ifdef __cplusplus
extern "C" {
#endif

const char *pcmk__xe_add_last_written(xmlNode *xe);

bool pcmk__xe_foreach_attr(xmlNode *xml, bool (*fn)(xmlAttr *, void *),
                           void *user_data);
bool pcmk__xe_foreach_const_attr(const xmlNode *xml,
                                 bool (*fn)(const xmlAttr *, void *),
                                 void *user_data);

xmlNode *pcmk__xe_first_child(const xmlNode *parent, const char *node_name,
                              const char *attr_n, const char *attr_v);

void pcmk__xe_remove_attr(xmlNode *element, const char *name);
bool pcmk__xe_remove_attr_cb(xmlNode *xml, void *user_data);
void pcmk__xe_remove_matching_attrs(xmlNode *element, bool force,
                                    bool (*match)(xmlAttrPtr, void *),
                                    void *user_data);
int pcmk__xe_delete_match(xmlNode *xml, xmlNode *search);
int pcmk__xe_replace_match(xmlNode *xml, xmlNode *replace);
int pcmk__xe_update_match(xmlNode *xml, xmlNode *update, uint32_t flags);

/*!
 * \internal
 * \brief Check whether an XML element is of a particular type
 *
 * \param[in] xml   XML element to compare
 * \param[in] name  XML element name to compare
 *
 * \return \c true if \p xml is of type \p name, otherwise \c false
 */
static inline bool
pcmk__xe_is(const xmlNode *xml, const char *name)
{
    return (xml != NULL) && (xml->name != NULL) && (name != NULL)
           && (strcmp((const char *) xml->name, name) == 0);
}

xmlNode *pcmk__xe_create(xmlNode *parent, const char *name);
xmlNode *pcmk__xe_next(const xmlNode *node, const char *element_name);

void pcmk__xe_set_content(xmlNode *node, const char *format, ...)
    G_GNUC_PRINTF(2, 3);

int pcmk__xe_get_score(const xmlNode *xml, const char *name, int *score,
                       int default_score);

int pcmk__xe_copy_attrs(xmlNode *target, const xmlNode *src, uint32_t flags);
void pcmk__xe_sort_attrs(xmlNode *xml);

void pcmk__xe_set_id(xmlNode *xml, const char *format, ...)
    G_GNUC_PRINTF(2, 3);

/*!
 * \internal
 * \brief Like pcmk__xe_set_props, but takes a va_list instead of
 *        arguments directly.
 *
 * \param[in,out] node   XML to add attributes to
 * \param[in]     pairs  NULL-terminated list of name/value pairs to add
 */
void
pcmk__xe_set_propv(xmlNodePtr node, va_list pairs);

/*!
 * \internal
 * \brief Add a NULL-terminated list of name/value pairs to the given
 *        XML node as properties.
 *
 * \param[in,out] node XML node to add properties to
 * \param[in]     ...  NULL-terminated list of name/value pairs
 *
 * \note A NULL name terminates the arguments; a NULL value will be skipped.
 */
void
pcmk__xe_set_props(xmlNodePtr node, ...)
G_GNUC_NULL_TERMINATED;

/*!
 * \internal
 * \brief Get first attribute of an XML element
 *
 * \param[in] xe  XML element to check
 *
 * \return First attribute of \p xe (or NULL if \p xe is NULL or has none)
 */
static inline xmlAttr *
pcmk__xe_first_attr(const xmlNode *xe)
{
    return (xe == NULL)? NULL : xe->properties;
}

/*!
 * \internal
 * \brief Iterate over child elements of \p xml
 *
 * This function iterates over the children of \p xml, performing the
 * callback function \p handler on each node.  If the callback returns
 * a value other than pcmk_rc_ok, the iteration stops and the value is
 * returned.  It is therefore possible that not all children will be
 * visited.
 *
 * \param[in,out] xml                 The starting XML node.  Can be NULL.
 * \param[in]     child_element_name  The name that the node must match in order
 *                                    for \p handler to be run.  If NULL, all
 *                                    child elements will match.
 * \param[in]     handler             The callback function.
 * \param[in,out] userdata            User data to pass to the callback function.
 *                                    Can be NULL.
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__xe_foreach_child(xmlNode *xml, const char *child_element_name,
                       int (*handler)(xmlNode *xml, void *userdata),
                       void *userdata);

const char *pcmk__xe_get(const xmlNode *xml, const char *attr_name);
int pcmk__xe_set(xmlNode *xml, const char *attr_name, const char *value);

int pcmk__xe_get_datetime(const xmlNode *xml, const char *attr, crm_time_t **t);
int pcmk__xe_get_flags(const xmlNode *xml, const char *name, uint32_t *dest,
                       uint32_t default_value);

int pcmk__xe_get_guint(const xmlNode *xml, const char *attr, guint *dest);
void pcmk__xe_set_guint(xmlNode *xml, const char *attr, guint value);

int pcmk__xe_get_int(const xmlNode *xml, const char *name, int *dest);
void pcmk__xe_set_int(xmlNode *xml, const char *attr, int value);

int pcmk__xe_get_ll(const xmlNode *xml, const char *name, long long *dest);
int pcmk__xe_set_ll(xmlNode *xml, const char *attr, long long value);

int pcmk__xe_get_time(const xmlNode *xml, const char *attr, time_t *dest);
void pcmk__xe_set_time(xmlNode *xml, const char *attr, time_t value);

int pcmk__xe_get_timeval(const xmlNode *xml, const char *sec_attr,
                         const char *usec_attr, struct timeval *dest);
void pcmk__xe_set_timeval(xmlNode *xml, const char *sec_attr,
                          const char *usec_attr, const struct timeval *value);

int pcmk__xe_get_bool(const xmlNode *xml, const char *attr, bool *dest);
void pcmk__xe_set_bool(xmlNode *xml, const char *attr, bool value);
bool pcmk__xe_attr_is_true(const xmlNode *node, const char *name);

/*!
 * \internal
 * \brief Retrieve a copy of the value of an XML attribute
 *
 * This is like \c pcmk__xe_get() but allocates new memory for the result.
 *
 * \param[in] xml   XML element whose attribute to get
 * \param[in] attr  Attribute name
 *
 * \return Value of specified attribute (or \c NULL if not set)
 *
 * \note The caller is responsible for freeing the result using \c free().
 */
static inline char *
pcmk__xe_get_copy(const xmlNode *xml, const char *attr)
{
    return pcmk__str_copy(pcmk__xe_get(xml, attr));
}

/*!
 * \internal
 * \brief Retrieve the value of the \c PCMK_XA_ID XML attribute
 *
 * \param[in] xml  XML element to check
 *
 * \return Value of the \c PCMK_XA_ID attribute (may be \c NULL)
 */
static inline const char *
pcmk__xe_id(const xmlNode *xml)
{
    return pcmk__xe_get(xml, PCMK_XA_ID);
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_XML_ELEMENT_INTERNAL__H
