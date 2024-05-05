/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_XML__H
#define PCMK__CRM_COMMON_XML__H

#include <stdbool.h>

#include <libxml/tree.h>            // xmlNode

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

typedef const xmlChar *pcmkXmlStr;

bool xml_tracking_changes(xmlNode * xml);
bool xml_document_dirty(xmlNode *xml);
void xml_track_changes(xmlNode * xml, const char *user, xmlNode *acl_source, bool enforce_acls);
void xml_calculate_changes(xmlNode *old_xml, xmlNode *new_xml);
void xml_calculate_significant_changes(xmlNode *old_xml, xmlNode *new_xml);
void xml_accept_changes(xmlNode * xml);
bool xml_patch_versions(const xmlNode *patchset, int add[3], int del[3]);

xmlNode *xml_create_patchset(
    int format, xmlNode *source, xmlNode *target, bool *config, bool manage_version);
int xml_apply_patchset(xmlNode *xml, xmlNode *patchset, bool check_version);

void patchset_process_digest(xmlNode *patch, xmlNode *source, xmlNode *target, bool with_digest);

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/xml_compat.h>
#endif

#ifdef __cplusplus
}
#endif

#endif
