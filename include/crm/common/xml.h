/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_XML__H
#define PCMK__CRM_COMMON_XML__H

#include <stdbool.h>                // bool

#include <libxml/tree.h>            // xmlNode

// xml.h is a wrapper for the following headers
#include <crm/common/xml_element.h>
#include <crm/common/xml_io.h>
#include <crm/common/xml_names.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Wrappers for and extensions to libxml2
 * \ingroup core
 */

/* @COMPAT Create and apply patchset functions must remain public and
 * undeprecated until we create replacements
 */

xmlNode *xml_create_patchset(int format, const xmlNode *source, xmlNode *target,
                             bool *config, bool manage_version);
int xml_apply_patchset(xmlNode *xml, const xmlNode *patchset,
                       bool check_version);

#ifdef __cplusplus
}
#endif

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/xml_compat.h>
#endif

#endif
