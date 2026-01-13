/*
 * Copyright 2006-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <schemas_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_SCHEMAS_INTERNAL__H
#define PCMK__CRM_COMMON_SCHEMAS_INTERNAL__H

#include <stdbool.h>
#include <glib.h>           // GList, gboolean
#include <libxml/relaxng.h> // xmlRelaxNGValidityErrorFunc
#include <libxml/tree.h>    // xmlNode

#ifdef __cplusplus
extern "C" {
#endif

void pcmk__schema_init(void);
void pcmk__schema_cleanup(void);

void pcmk__load_schemas_from_dir(const char *dir);
void pcmk__sort_schemas(void);
GList *pcmk__schema_files_later_than(const char *name);
void pcmk__build_schema_xml_node(xmlNode *parent, const char *name,
                                 GList **already_included);
const char *pcmk__remote_schema_dir(void);
GList *pcmk__get_schema(const char *name);
const char *pcmk__highest_schema_name(void);
int pcmk__cmp_schemas_by_name(const char *schema1_name,
                              const char *schema2_name);
bool pcmk__validate_xml(xmlNode *xml, xmlRelaxNGValidityErrorFunc error_handler,
                        void *error_handler_context);
bool pcmk__configured_schema_validates(xmlNode *xml);
int pcmk__update_schema(xmlNode **xml, const char *max_schema_name,
                        bool to_logs);
void pcmk__warn_if_schema_deprecated(const char *schema);

int pcmk__update_configured_schema(xmlNode **xml, bool to_logs);

#ifdef __cplusplus
}
#endif

#endif // PCMK__SCHEMAS_INTERNAL__H
