/*
 * Copyright 2018-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRMCOMMON_PRIVATE__H
#  define CRMCOMMON_PRIVATE__H

/* This header is for the sole use of libcrmcommon, so that functions can be
 * declared with G_GNUC_INTERNAL for efficiency.
 */

enum xml_private_flags {
     xpf_none        = 0x0000,
     xpf_dirty       = 0x0001,
     xpf_deleted     = 0x0002,
     xpf_created     = 0x0004,
     xpf_modified    = 0x0008,

     xpf_tracking    = 0x0010,
     xpf_processed   = 0x0020,
     xpf_skip        = 0x0040,
     xpf_moved       = 0x0080,

     xpf_acl_enabled = 0x0100,
     xpf_acl_read    = 0x0200,
     xpf_acl_write   = 0x0400,
     xpf_acl_deny    = 0x0800,

     xpf_acl_create  = 0x1000,
     xpf_acl_denied  = 0x2000,
     xpf_lazy        = 0x4000,
};

typedef struct xml_node_private_s {
        long check;
        uint32_t flags;
} xml_node_private_t;

typedef struct xml_doc_private_s {
        long check;
        uint32_t flags;
        char *user;
        GListPtr acls;
        GListPtr deleted_objs;
} xml_doc_private_t;

G_GNUC_INTERNAL
void pcmk__set_xml_flag(xmlNode *xml, enum xml_private_flags flag);

G_GNUC_INTERNAL
bool pcmk__tracking_xml_changes(xmlNode *xml, bool lazy);

G_GNUC_INTERNAL
int pcmk__element_xpath(const char *prefix, xmlNode *xml, char *buffer,
                        int offset, size_t buffer_size);

G_GNUC_INTERNAL
void pcmk__free_acls(GList *acls);

G_GNUC_INTERNAL
void pcmk__unpack_acl(xmlNode *source, xmlNode *target, const char *user);

G_GNUC_INTERNAL
bool pcmk__check_acl(xmlNode *xml, const char *name,
                     enum xml_private_flags mode);

G_GNUC_INTERNAL
void pcmk__apply_acl(xmlNode *xml);

G_GNUC_INTERNAL
void pcmk__apply_creation_acl(xmlNode *xml, bool check_top);

G_GNUC_INTERNAL
void pcmk__mark_xml_attr_dirty(xmlAttr *a);

static inline xmlAttr *
pcmk__first_xml_attr(const xmlNode *xml)
{
    return xml? xml->properties : NULL;
}

static inline const char *
pcmk__xml_attr_value(const xmlAttr *attr)
{
    return ((attr == NULL) || (attr->children == NULL))? NULL
           : (const char *) attr->children->content;
}

#endif  // CRMCOMMON_PRIVATE__H
