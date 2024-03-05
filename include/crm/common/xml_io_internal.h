/*
 * Copyright 2017-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__XML_IO_INTERNAL__H
#define PCMK__XML_IO_INTERNAL__H

/*
 * Internal-only wrappers for and extensions to libxml2 I/O
 */

#include <stdbool.h>        // bool

#include <glib.h>           // GString
#include <libxml/tree.h>    // xmlNode

xmlNode *pcmk__xml_read(const char *filename);
xmlNode *pcmk__xml_parse(const char *input);

void pcmk__xml_string(const xmlNode *data, uint32_t options, GString *buffer,
                      int depth);

int pcmk__xml2fd(int fd, xmlNode *cur);
int pcmk__xml_write_fd(const xmlNode *xml, const char *filename, int fd,
                       bool compress, unsigned int *nbytes);
int pcmk__xml_write_file(const xmlNode *xml, const char *filename,
                         bool compress, unsigned int *nbytes);

#endif  // PCMK__XML_IO_INTERNAL__H
