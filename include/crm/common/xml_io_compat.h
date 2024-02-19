/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_XML_IO_COMPAT__H
#define PCMK__CRM_COMMON_XML_IO_COMPAT__H

#include <glib.h>               // gboolean
#include <libxml/tree.h>        // xmlNode

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker XML I/O API
 * \ingroup core
 * \deprecated Do not include this header directly. The XML APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
xmlNode *filename2xml(const char *filename);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
xmlNode *stdin2xml(void);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
xmlNode *string2xml(const char *input);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
int write_xml_fd(const xmlNode *xml, const char *filename, int fd,
                 gboolean compress);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
int write_xml_file(const xmlNode *xml, const char *filename, gboolean compress);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
char *dump_xml_formatted(const xmlNode *xml);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
char *dump_xml_formatted_with_text(const xmlNode *xml);

//! \deprecated Do not use Pacemaker for general-purpose XML manipulation
char *dump_xml_unformatted(const xmlNode *xml);

#ifdef __cplusplus
}
#endif

#endif  // PCMK__CRM_COMMON_XML_IO_COMPAT__H
