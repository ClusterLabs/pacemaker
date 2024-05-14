/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_XML_IO__H
#define PCMK__CRM_COMMON_XML_IO__H

#include <libxml/tree.h>    // xmlNode

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Wrappers for and extensions to XML input/output functions
 * \ingroup core
 */

/* Define compression parameters for IPC messages
 *
 * Compression costs a LOT, so we don't want to do it unless we're hitting
 * message limits. Currently, we use 128KB as the threshold, because higher
 * values don't play well with the heartbeat stack. With an earlier limit of
 * 10KB, compressing 184 of 1071 messages accounted for 23% of the total CPU
 * used by the cib.
 */
#define CRM_BZ2_BLOCKS      4
#define CRM_BZ2_WORK        20
#define CRM_BZ2_THRESHOLD   (128 * 1024)

void save_xml_to_file(const xmlNode *xml, const char *desc,
                      const char *filename);

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/xml_io_compat.h>
#endif

#ifdef __cplusplus
}
#endif

#endif  // PCMK__CRM_COMMON_XML_IO__H
