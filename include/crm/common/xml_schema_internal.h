/*
 * Copyright 2015-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__SCHEMA_INTERNAL__H
#define PCMK__SCHEMA_INTERNAL__H

/*
 * Internal-only functions for handling RelaxNG XML schemas
 */

#include <glib.h>           // GList, gboolean
#include <libxml/relaxng.h> // xmlRelaxNGValidityErrorFunc
#include <libxml/tree.h>    // xmlNode

void crm_schema_init(void);
void crm_schema_cleanup(void);

void pcmk__load_schemas_from_dir(const char *dir);
GList *pcmk__schema_files_later_than(const char *name);
void pcmk__build_schema_xml_node(xmlNode *parent, const char *name,
                                 GList **already_included);

gboolean pcmk__validate_xml(xmlNode *xml_blob, const char *validation,
                            xmlRelaxNGValidityErrorFunc error_handler,
                            void *error_handler_context);

void pcmk__log_known_schemas(void);
const char *pcmk__remote_schema_dir(void);
void pcmk__sort_schemas(void);

#endif  // PCMK__SCHEMA_INTERNAL__H
