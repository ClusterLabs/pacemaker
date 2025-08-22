/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_XML_IO_COMPAT__H
#define PCMK__CRM_COMMON_XML_IO_COMPAT__H

#include <libxml/tree.h>    // xmlNode

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker XML I/O API
 * \ingroup core
 * \deprecated Do not include this header directly. The XML APIs in this header,
 *             and the header itself, will be removed in a future release.
 */

//! \deprecated Do not use
#define CRM_BZ2_BLOCKS 4

//! \deprecated Do not use
#define CRM_BZ2_WORK 20

//! \deprecated Do not use
#define CRM_BZ2_THRESHOLD (128 * 1024)

//! \deprecated Do not use
void save_xml_to_file(const xmlNode *xml, const char *desc,
                      const char *filename);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_XML_IO_COMPAT__H
