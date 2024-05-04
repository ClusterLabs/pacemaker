/*
 * Copyright 2022-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_XPATH_INTERNAL__H
#define PCMK__CRM_COMMON_XPATH_INTERNAL__H

#include <glib.h>               // GString
#include <libxml/tree.h>        // xmlNode

/*
 * Internal-only wrappers for and extensions to libxml2 XPath utilities
 */

GString *pcmk__element_xpath(const xmlNode *xml);
char *pcmk__xpath_node_id(const char *xpath, const char *node);

void pcmk__warn_multiple_name_matches(pcmk__output_t *out, xmlNode *search,
                                      const char *name);

#endif  // PCMK__CRM_COMMON_XPATH_INTERNAL__H
