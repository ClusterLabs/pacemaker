/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRM_COMMON_XML__H
#  define CRM_COMMON_XML__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Wrappers for and extensions to libxml2
 * \ingroup core
 */

#  include <stdio.h>
#  include <sys/types.h>
#  include <unistd.h>

#  include <stdlib.h>
#  include <errno.h>
#  include <fcntl.h>

#  include <libxml/tree.h>
#  include <libxml/xpath.h>

#  include <crm/crm.h>
#  include <crm/common/nvpair.h>

/* Define compression parameters for IPC messages
 *
 * Compression costs a LOT, so we don't want to do it unless we're hitting
 * message limits. Currently, we use 128KB as the threshold, because higher
 * values don't play well with the heartbeat stack. With an earlier limit of
 * 10KB, compressing 184 of 1071 messages accounted for 23% of the total CPU
 * used by the cib.
 */
#  define CRM_BZ2_BLOCKS		4
#  define CRM_BZ2_WORK		20
#  define CRM_BZ2_THRESHOLD	128 * 1024

#  define XML_PARANOIA_CHECKS 0

typedef const xmlChar *pcmkXmlStr;

gboolean add_message_xml(xmlNode * msg, const char *field, xmlNode * xml);
xmlNode *get_message_xml(xmlNode * msg, const char *field);

xmlDoc *getDocPtr(xmlNode * node);

/*
 * Replacement function for xmlCopyPropList which at the very least,
 * doesn't work the way *I* would expect it to.
 *
 * Copy all the attributes/properties from src into target.
 *
 * Not recursive, does not return anything.
 *
 */
void copy_in_properties(xmlNode * target, xmlNode * src);
void expand_plus_plus(xmlNode * target, const char *name, const char *value);
void fix_plus_plus_recursive(xmlNode * target);

/*
 * Create a node named "name" as a child of "parent"
 * If parent is NULL, creates an unconnected node.
 *
 * Returns the created node
 *
 */
xmlNode *create_xml_node(xmlNode * parent, const char *name);

/*
 * Create a node named "name" as a child of "parent", giving it the provided
 * text content.
 * If parent is NULL, creates an unconnected node.
 *
 * Returns the created node
 *
 */
xmlNode *pcmk_create_xml_text_node(xmlNode * parent, const char *name, const char *content);

/*
 * Create a new HTML node named "element_name" as a child of "parent", giving it the
 * provided text content.  Optionally, apply a CSS #id and #class.
 *
 * Returns the created node.
 */
xmlNode *pcmk_create_html_node(xmlNode * parent, const char *element_name, const char *id,
                               const char *class_name, const char *text);

/*
 *
 */
void purge_diff_markers(xmlNode * a_node);

/*
 * Returns a deep copy of src_node
 *
 */
xmlNode *copy_xml(xmlNode * src_node);

/*
 * Add a copy of xml_node to new_parent
 */
xmlNode *add_node_copy(xmlNode * new_parent, xmlNode * xml_node);

int add_node_nocopy(xmlNode * parent, const char *name, xmlNode * child);

/*
 * XML I/O Functions
 *
 * Whitespace between tags is discarded.
 */
xmlNode *filename2xml(const char *filename);

xmlNode *stdin2xml(void);

xmlNode *string2xml(const char *input);

int write_xml_fd(xmlNode * xml_node, const char *filename, int fd, gboolean compress);
int write_xml_file(xmlNode * xml_node, const char *filename, gboolean compress);

char *dump_xml_formatted(xmlNode * msg);
/* Also dump the text node with xml_log_option_text enabled */ 
char *dump_xml_formatted_with_text(xmlNode * msg);

char *dump_xml_unformatted(xmlNode * msg);

/*
 * Diff related Functions
 */
xmlNode *diff_xml_object(xmlNode * left, xmlNode * right, gboolean suppress);

xmlNode *subtract_xml_object(xmlNode * parent, xmlNode * left, xmlNode * right,
                             gboolean full, gboolean * changed, const char *marker);

gboolean can_prune_leaf(xmlNode * xml_node);

/*
 * Searching & Modifying
 */
xmlNode *find_xml_node(xmlNode * cib, const char *node_path, gboolean must_find);

void xml_remove_prop(xmlNode * obj, const char *name);

gboolean replace_xml_child(xmlNode * parent, xmlNode * child, xmlNode * update,
                           gboolean delete_only);

gboolean update_xml_child(xmlNode * child, xmlNode * to_update);

int find_xml_children(xmlNode ** children, xmlNode * root,
                      const char *tag, const char *field, const char *value,
                      gboolean search_matches);

xmlNode *get_xpath_object(const char *xpath, xmlNode * xml_obj, int error_level);
xmlNode *get_xpath_object_relative(const char *xpath, xmlNode * xml_obj, int error_level);

static inline const char *
crm_element_name(const xmlNode *xml)
{
    return xml? (const char *)(xml->name) : NULL;
}

static inline const char *
crm_map_element_name(const xmlNode *xml)
{
    const char *name = crm_element_name(xml);

    if (strcmp(name, "master") == 0) {
        return "clone";
    } else {
        return name;
    }
}

gboolean xml_has_children(const xmlNode * root);

char *calculate_on_disk_digest(xmlNode * local_cib);
char *calculate_operation_digest(xmlNode * local_cib, const char *version);
char *calculate_xml_versioned_digest(xmlNode * input, gboolean sort, gboolean do_filter,
                                     const char *version);

/* schema-related functions (from schemas.c) */
gboolean validate_xml(xmlNode * xml_blob, const char *validation, gboolean to_logs);
gboolean validate_xml_verbose(xmlNode * xml_blob);

/*!
 * \brief Update CIB XML to most recent schema version
 *
 * "Update" means either actively employ XSLT-based transformation(s)
 * (if intermediate product to transform valid per its declared schema version,
 * transformation available, proceeded successfully with a result valid per
 * expectated newer schema version), or just try to bump the marked validating
 * schema until all gradually rising schema versions attested or the first
 * such attempt subsequently fails to validate.   Which of the two styles will
 * be used depends on \p transform parameter (positive/negative, respectively).
 *
 * \param[in,out] xml_blob   XML tree representing CIB, may be swapped with
 *                           an "updated" one
 * \param[out]    best       The highest configuration version (per its index
 *                           in the global schemas table) it was possible to
 *                           reach during the update steps while ensuring
 *                           the validity of the result; if no validation
 *                           success was observed against possibly multiple
 *                           schemas, the value is less or equal the result
 *                           of \c get_schema_version applied on the input
 *                           \p xml_blob value (unless that function maps it
 *                           to -1, then 0 would be used instead)
 * \param[in]     max        When \p transform is positive, this allows to
 *                           set upper boundary schema (per its index in the
 *                           global schemas table) beyond which it's forbidden
 *                           to update by the means of XSLT transformation
 * \param[in]     transform  Whether to employ XSLT-based transformation so
 *                           as to allow overcoming possible incompatibilities
 *                           between major schema versions (see above)
 * \param[in]     to_logs    If true, output notable progress info to
 *                           internal log streams; if false, to stderr
 *
 * \return \c pcmk_ok if no non-recoverable error encountered (up to
 *         caller to evaluate if the update satisfies the requirements
 *         per returned \p best value), negative value carrying the reason
 *         otherwise
 */
int update_validation(xmlNode **xml_blob, int *best, int max,
                      gboolean transform, gboolean to_logs);

int get_schema_version(const char *name);
const char *get_schema_name(int version);
const char *xml_latest_schema(void);
gboolean cli_config_update(xmlNode ** xml, int *best_version, gboolean to_logs);

/*!
 * \brief Initialize the CRM XML subsystem
 *
 * This method sets global XML settings and loads pacemaker schemas into the cache.
 */
void crm_xml_init(void);
void crm_xml_cleanup(void);

void pcmk_free_xml_subtree(xmlNode *xml);
void free_xml(xmlNode * child);

xmlNode *first_named_child(const xmlNode *parent, const char *name);
xmlNode *crm_next_same_xml(const xmlNode *sibling);

xmlNode *sorted_xml(xmlNode * input, xmlNode * parent, gboolean recursive);
xmlXPathObjectPtr xpath_search(xmlNode * xml_top, const char *path);
void crm_foreach_xpath_result(xmlNode *xml, const char *xpath,
                              void (*helper)(xmlNode*, void*), void *user_data);
xmlNode *expand_idref(xmlNode * input, xmlNode * top);

void freeXpathObject(xmlXPathObjectPtr xpathObj);
xmlNode *getXpathResult(xmlXPathObjectPtr xpathObj, int index);
void dedupXpathResults(xmlXPathObjectPtr xpathObj);

static inline int numXpathResults(xmlXPathObjectPtr xpathObj)
{
    if(xpathObj == NULL || xpathObj->nodesetval == NULL) {
        return 0;
    }
    return xpathObj->nodesetval->nodeNr;
}

bool xml_tracking_changes(xmlNode * xml);
bool xml_document_dirty(xmlNode *xml);
void xml_track_changes(xmlNode * xml, const char *user, xmlNode *acl_source, bool enforce_acls);
void xml_calculate_changes(xmlNode *old_xml, xmlNode *new_xml);
void xml_calculate_significant_changes(xmlNode *old_xml, xmlNode *new_xml);
void xml_accept_changes(xmlNode * xml);
void xml_log_changes(uint8_t level, const char *function, xmlNode *xml);
void xml_log_patchset(uint8_t level, const char *function, xmlNode *xml);
bool xml_patch_versions(xmlNode *patchset, int add[3], int del[3]);

xmlNode *xml_create_patchset(
    int format, xmlNode *source, xmlNode *target, bool *config, bool manage_version);
int xml_apply_patchset(xmlNode *xml, xmlNode *patchset, bool check_version);

void patchset_process_digest(xmlNode *patch, xmlNode *source, xmlNode *target, bool with_digest);

/* exclusive (should any combination make sense -> explicitly enumerated),
   with intentional symbolic constant duality (easier to adapt to growth) */
enum pcmk_acl_cred_type {
#define PCMK_ACL_CRED_UNSET PCMK_ACL_CRED_UNSET
    PCMK_ACL_CRED_UNSET = 0,
#define PCMK_ACL_CRED_USER PCMK_ACL_CRED_USER
    PCMK_ACL_CRED_USER,
    /* XXX no proper support for groups yet */
};

/* need to be ORable */
enum pcmk_acl_verdict {
    PCMK_ACL_VERDICT_WRITABLE = 1 << 0,
    PCMK_ACL_VERDICT_READABLE = 1 << 1,
    PCMK_ACL_VERDICT_DENIED   = 1 << 2,
};

/*!
 * \brief Mark CIB with namespace-encoded result of ACLs eval'd per credential
 *
 * \param[in] cred_type        credential type that \p cred represents
 * \param[in] cred             credential whose ACL perspective to switch to
 * \param[in] cib_doc          XML document representing CIB
 * \param[out] acl_evaled_doc  XML document representing CIB, with said
 *                             namespace-based annotations throughout
 *
 * \return  0 if ACLs were not applicable, >0 if it was and all went fine
 *          (this is the only case when it's safe to touch \p acl_evaled_doc
 *          afterwards, the result is #PCMK_ACL_VERDICT_WRITABLE,
 *          #PCMK_ACL_VERDICT_READABLE and #PCMK_ACL_VERDICT_DENIED bits
 *          ORed respectively), -2 on run-time unrecognized \p cred_type,
 *          -3 on unsupported validation schema version (see below),
 *          or -1 on any other/generic issue
 *
 * \note Only supported schemas are those following acls-2.0.rng, that is,
 *       those validated with pacemaker-2.0.rng and newer (artificially caped
 *       at 4.0, not including it (the future cannot be predicted,
 *       compatibility needs to be confirmed, then, hopefully leading to
 *       this comment being updated).
 */
int pcmk_acl_evaled_as_namespaces(enum pcmk_acl_cred_type cred_type,
                                  const char *cred, xmlDoc *cib_doc,
                                  xmlDoc **acl_evaled_doc);

void save_xml_to_file(xmlNode * xml, const char *desc, const char *filename);
char *xml_get_path(xmlNode *xml);

char * crm_xml_escape(const char *text);
void crm_xml_sanitize_id(char *id);
void crm_xml_set_id(xmlNode *xml, const char *format, ...) G_GNUC_PRINTF(2, 3);

/*!
 * \brief xmlNode destructor which can be used in glib collections
 */
void crm_destroy_xml(gpointer data);

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/xml_compat.h>
#endif

#ifdef __cplusplus
}
#endif

#endif
