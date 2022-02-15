/*
 * Copyright 2004-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_NVPAIR__H
#  define PCMK__CRM_COMMON_NVPAIR__H

#  include <sys/time.h>     // struct timeval
#  include <glib.h>         // gpointer, gboolean, guint
#  include <libxml/tree.h>  // xmlNode
#  include <crm/crm.h>


#  ifdef __cplusplus
extern "C" {
#  endif

/**
 * \file
 * \brief Functionality for manipulating name/value pairs
 * \ingroup core
 */

typedef struct pcmk_nvpair_s {
    char *name;
    char *value;
} pcmk_nvpair_t;

GSList *pcmk_prepend_nvpair(GSList *nvpairs, const char *name, const char *value);
void pcmk_free_nvpairs(GSList *nvpairs);
GSList *pcmk_sort_nvpairs(GSList *list);
GSList *pcmk_xml_attrs2nvpairs(xmlNode *xml);
void pcmk_nvpairs2xml_attrs(GSList *list, xmlNode *xml);

xmlNode *crm_create_nvpair_xml(xmlNode *parent, const char *id,
                               const char *name, const char *value);
void hash2nvpair(gpointer key, gpointer value, gpointer user_data);
void hash2field(gpointer key, gpointer value, gpointer user_data);
void hash2metafield(gpointer key, gpointer value, gpointer user_data);
void hash2smartfield(gpointer key, gpointer value, gpointer user_data);
GHashTable *xml2list(xmlNode *parent);

const char *crm_xml_add(xmlNode *node, const char *name, const char *value);
const char *crm_xml_replace(xmlNode *node, const char *name, const char *value);
const char *crm_xml_add_int(xmlNode *node, const char *name, int value);
const char *crm_xml_add_ll(xmlNode *node, const char *name, long long value);
const char *crm_xml_add_ms(xmlNode *node, const char *name, guint ms);
const char *crm_xml_add_timeval(xmlNode *xml, const char *name_sec,
                                const char *name_usec,
                                const struct timeval *value);

const char *crm_element_value(const xmlNode *data, const char *name);
int crm_element_value_int(const xmlNode *data, const char *name, int *dest);
int crm_element_value_ll(const xmlNode *data, const char *name, long long *dest);
int crm_element_value_ms(const xmlNode *data, const char *name, guint *dest);
int crm_element_value_epoch(const xmlNode *xml, const char *name, time_t *dest);
int crm_element_value_timeval(const xmlNode *data, const char *name_sec,
                              const char *name_usec, struct timeval *dest);
char *crm_element_value_copy(const xmlNode *data, const char *name);

/*!
 * \brief Copy an element from one XML object to another
 *
 * \param[in]     obj1     Source XML
 * \param[in,out] obj2     Destination XML
 * \param[in]     element  Name of element to copy
 *
 * \return Pointer to copied value (from source)
 */
static inline const char *
crm_copy_xml_element(xmlNode *obj1, xmlNode *obj2, const char *element)
{
    const char *value = crm_element_value(obj1, element);

    crm_xml_add(obj2, element, value);
    return value;
}

/*!
 * \brief Add a boolean attribute to an XML object
 *
 * Add an attribute with the value \c XML_BOOLEAN_TRUE or \c XML_BOOLEAN_FALSE
 * as appropriate to an XML object.
 *
 * \param[in,out] node   XML object to add attribute to
 * \param[in]     name   Name of attribute to add
 * \param[in]     value  Boolean whose value will be tested
 *
 * \return Pointer to newly created XML attribute's content, or \c NULL on error
 */
static inline const char *
crm_xml_add_boolean(xmlNode *node, const char *name, gboolean value)
{
    return crm_xml_add(node, name, (value? "true" : "false"));
}

#  ifdef __cplusplus
}
#  endif

#endif // PCMK__CRM_COMMON_NVPAIR__H
