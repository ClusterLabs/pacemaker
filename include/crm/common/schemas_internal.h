/*
 * Copyright 2006-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__SCHEMAS_INTERNAL__H
#  define PCMK__SCHEMAS_INTERNAL__H

#include <glib.h>           // GList, gboolean
#include <libxml/tree.h>    // xmlNode, xmlRelaxNGValidityErrorFunc

void crm_schema_init(void);
void crm_schema_cleanup(void);

void pcmk__load_schemas_from_dir(const char *dir);
void pcmk__sort_schemas(void);
GList *pcmk__schema_files_later_than(const char *name);
void pcmk__build_schema_xml_node(xmlNode *parent, const char *name,
                                 GList **already_included);
const char *pcmk__remote_schema_dir(void);
GList *pcmk__get_schema(const char *name);
int pcmk__cmp_schemas_by_name(const char *schema1_name,
                              const char *schema2_name);
gboolean pcmk__validate_xml(xmlNode *xml_blob, const char *validation,
                            xmlRelaxNGValidityErrorFunc error_handler,
                            void *error_handler_context);
int pcmk__update_schema(xmlNode **xml, int *best, int max, bool transform,
                        bool to_logs);

#endif // PCMK__SCHEMAS_INTERNAL__H
