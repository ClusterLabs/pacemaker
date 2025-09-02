/*
 * Copyright 2017-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_XML_IO_INTERNAL__H
#define PCMK__CRM_COMMON_XML_IO_INTERNAL__H

/*
 * Internal-only wrappers for and extensions to libxml2 I/O
 */

#include <stdbool.h>        // bool
#include <stdint.h>         // uint32_t, etc.

#include <glib.h>           // GString
#include <libxml/tree.h>    // xmlNode

#ifdef __cplusplus
extern "C" {
#endif

xmlNode *pcmk__xml_read(const char *filename);
xmlNode *pcmk__xml_parse(const char *input);

void pcmk__xml_string(const xmlNode *data, uint32_t options, GString *buffer,
                      int depth);

int pcmk__xml2fd(int fd, xmlNode *cur);
int pcmk__xml_write_fd(const xmlNode *xml, const char *filename, int fd);
int pcmk__xml_write_file(const xmlNode *xml, const char *filename,
                         bool compress);
void pcmk__xml_write_temp_file(const xmlNode *xml, const char *desc,
                               const char *filename);

#ifdef __cplusplus
}
#endif

#endif  // PCMK__XML_IO_INTERNAL__H
