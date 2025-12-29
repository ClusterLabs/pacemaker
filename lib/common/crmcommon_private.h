/*
 * Copyright 2018-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__COMMON_CRMCOMMON_PRIVATE__H
#define PCMK__COMMON_CRMCOMMON_PRIVATE__H

/* This header is for the sole use of libcrmcommon, so that functions can be
 * declared with G_GNUC_INTERNAL for efficiency.
 */

#include <stdint.h>         // uint8_t, uint32_t
#include <stdbool.h>        // bool
#include <sys/types.h>      // size_t

#include <glib.h>           // G_GNUC_INTERNAL, G_GNUC_PRINTF, gchar, etc.
#include <libxml/tree.h>    // xmlNode, xmlAttr
#include <libxml/xmlstring.h>           // xmlChar
#include <qb/qbipcc.h>      // struct qb_ipc_response_header

#include <crm/common/internal.h>
#include <crm/common/ipc.h>             // pcmk_ipc_api_t, crm_ipc_t, etc.
#include <crm/common/iso8601.h>         // crm_time_t
#include <crm/common/mainloop.h>        // mainloop_io_t
#include <crm/common/results.h>         // crm_exit_t
#include <crm/common/rules.h>           // pcmk_rule_input_t

#ifdef __cplusplus
extern "C" {
#endif

// Decent chunk size for processing large amounts of data
#define PCMK__BUFFER_SIZE 4096

#if defined(PCMK__UNIT_TESTING)
#undef G_GNUC_INTERNAL
#define G_GNUC_INTERNAL
#endif

/*!
 * \internal
 * \brief Information about an XML node that was deleted
 *
 * When change tracking is enabled and we delete an XML node using
 * \c pcmk__xml_free(), we free it and add its path and position to a list in
 * its document's private data. This allows us to display changes, generate
 * patchsets, etc.
 *
 * Note that this does not happen when deleting an XML attribute using
 * \c pcmk__xa_remove(). In that case:
 * * If \c force is \c true, we remove the attribute without any tracking.
 * * If \c force is \c false, we mark the attribute as deleted but leave it in
 *   place until we commit changes.
 */
typedef struct pcmk__deleted_xml_s {
    gchar *path;        //!< XPath expression identifying the deleted node
    int position;       //!< Position of the deleted node among its siblings
} pcmk__deleted_xml_t;

/*!
 * \internal
 * \brief Private data for an XML node
 */
typedef struct xml_node_private_s {
    uint32_t check;         //!< Magic number for checking integrity
    uint32_t flags;         //!< Group of <tt>enum pcmk__xml_flags</tt>
    xmlNode *match;         //!< Pointer to matching node (defined by caller)
} xml_node_private_t;

/*!
 * \internal
 * \brief Private data for an XML document
 */
typedef struct xml_doc_private_s {
    uint32_t check;         //!< Magic number for checking integrity
    uint32_t flags;         //!< Group of <tt>enum pcmk__xml_flags</tt>
    char *acl_user;         //!< User affected by \c acls (for logging)

    //! ACLs to check requested changes against (list of \c xml_acl_t)
    GList *acls;

    //! XML nodes marked as deleted (list of \c pcmk__deleted_xml_t)
    GList *deleted_objs;
} xml_doc_private_t;

// XML private data magic numbers
#define PCMK__XML_DOC_PRIVATE_MAGIC     0x81726354UL
#define PCMK__XML_NODE_PRIVATE_MAGIC    0x54637281UL

// XML entity references
#define PCMK__XML_ENTITY_AMP    "&amp;"
#define PCMK__XML_ENTITY_GT     "&gt;"
#define PCMK__XML_ENTITY_LT     "&lt;"
#define PCMK__XML_ENTITY_QUOT   "&quot;"

#define pcmk__set_xml_flags(xml_priv, flags_to_set) do {                    \
        (xml_priv)->flags = pcmk__set_flags_as(__func__, __LINE__,          \
            PCMK__LOG_NEVER, "XML", "XML node", (xml_priv)->flags,          \
            (flags_to_set), #flags_to_set);                                 \
    } while (0)

#define pcmk__clear_xml_flags(xml_priv, flags_to_clear) do {                \
        (xml_priv)->flags = pcmk__clear_flags_as(__func__, __LINE__,        \
            PCMK__LOG_NEVER, "XML", "XML node", (xml_priv)->flags,          \
            (flags_to_clear), #flags_to_clear);                             \
    } while (0)

G_GNUC_INTERNAL
const char *pcmk__xml_element_type_text(xmlElementType type);

G_GNUC_INTERNAL
void pcmk__xml_tree_foreach_remove(xmlNode *xml, bool (*fn)(xmlNode *));

G_GNUC_INTERNAL
bool pcmk__xml_reset_node_flags(xmlNode *xml, void *user_data);

G_GNUC_INTERNAL
void pcmk__xml_set_parent_flags(xmlNode *xml, uint64_t flags);

G_GNUC_INTERNAL
void pcmk__xml_new_private_data(xmlNode *xml);

G_GNUC_INTERNAL
void pcmk__xml_free_private_data(xmlNode *xml);

G_GNUC_INTERNAL
void pcmk__xml_free_node(xmlNode *xml);

G_GNUC_INTERNAL
xmlDoc *pcmk__xml_new_doc(void);

G_GNUC_INTERNAL
int pcmk__xml_position(const xmlNode *xml, enum pcmk__xml_flags ignore_if_set);

G_GNUC_INTERNAL
bool pcmk__xc_matches(const xmlNode *comment1, const xmlNode *comment2);

G_GNUC_INTERNAL
void pcmk__xc_update(xmlNode *parent, xmlNode *target, xmlNode *update);

G_GNUC_INTERNAL
void pcmk__free_acls(GList *acls);

G_GNUC_INTERNAL
bool pcmk__is_user_in_group(const char *user, const char *group);

G_GNUC_INTERNAL
void pcmk__apply_acls(xmlDoc *doc);

G_GNUC_INTERNAL
void pcmk__check_creation_acls(xmlNode *xml);

G_GNUC_INTERNAL
int pcmk__xa_remove(xmlAttr *attr, bool force);

G_GNUC_INTERNAL
void pcmk__mark_xml_attr_dirty(xmlAttr *a);

G_GNUC_INTERNAL
bool pcmk__xa_filterable(const char *name);

G_GNUC_INTERNAL
void pcmk__log_xmllib_err(void *ctx, const char *fmt, ...)
G_GNUC_PRINTF(2, 3);

G_GNUC_INTERNAL
void pcmk__mark_xml_node_dirty(xmlNode *xml);

G_GNUC_INTERNAL
bool pcmk__dump_xml_attr(const xmlAttr *attr, void *user_data);

G_GNUC_INTERNAL
int pcmk__xe_set_score(xmlNode *target, const char *name, const char *value);

G_GNUC_INTERNAL
bool pcmk__xml_is_name_start_char(const char *utf8, int *len);

G_GNUC_INTERNAL
bool pcmk__xml_is_name_char(const char *utf8, int *len);

/*
 * Date/times
 */

// For use with pcmk__add_time_from_xml()
enum pcmk__time_component {
    pcmk__time_unknown,
    pcmk__time_years,
    pcmk__time_months,
    pcmk__time_weeks,
    pcmk__time_days,
    pcmk__time_hours,
    pcmk__time_minutes,
    pcmk__time_seconds,
};

G_GNUC_INTERNAL
const char *pcmk__time_component_attr(enum pcmk__time_component component);

G_GNUC_INTERNAL
int pcmk__add_time_from_xml(crm_time_t *t, enum pcmk__time_component component,
                            const xmlNode *xml);

G_GNUC_INTERNAL
void pcmk__set_time_if_earlier(crm_time_t *target, const crm_time_t *source);


/*
 * IPC
 */

#define PCMK__IPC_VERSION 1

#define PCMK__CONTROLD_API_MAJOR "1"
#define PCMK__CONTROLD_API_MINOR "0"

// IPC behavior that varies by daemon
typedef struct pcmk__ipc_methods_s {
    /*!
     * \internal
     * \brief Allocate any private data needed by daemon IPC
     *
     * \param[in,out] api  IPC API connection
     *
     * \return Standard Pacemaker return code
     */
    int (*new_data)(pcmk_ipc_api_t *api);

    /*!
     * \internal
     * \brief Free any private data used by daemon IPC
     *
     * \param[in,out] api_data  Data allocated by new_data() method
     */
    void (*free_data)(void *api_data);

    /*!
     * \internal
     * \brief Perform daemon-specific handling after successful connection
     *
     * Some daemons require clients to register before sending any other
     * commands. The controller requires a CRM_OP_HELLO (with no reply), and
     * the CIB manager, executor, and fencer require a CRM_OP_REGISTER (with a
     * reply). Ideally this would be consistent across all daemons, but for now
     * this allows each to do its own authorization.
     *
     * \param[in,out] api  IPC API connection
     *
     * \return Standard Pacemaker return code
     */
    int (*post_connect)(pcmk_ipc_api_t *api);

    /*!
     * \internal
     * \brief Check whether an IPC request results in a reply
     *
     * \param[in,out] api      IPC API connection
     * \param[in]     request  IPC request XML
     *
     * \return true if request would result in an IPC reply, false otherwise
     */
    bool (*reply_expected)(pcmk_ipc_api_t *api, const xmlNode *request);

    /*!
     * \internal
     * \brief Perform daemon-specific handling of an IPC message
     *
     * \param[in,out] api  IPC API connection
     * \param[in,out] msg  Message read from IPC connection
     *
     * \return true if more IPC reply messages should be expected
     */
    bool (*dispatch)(pcmk_ipc_api_t *api, xmlNode *msg);

    /*!
     * \internal
     * \brief Perform daemon-specific handling of an IPC disconnect
     *
     * \param[in,out] api  IPC API connection
     */
    void (*post_disconnect)(pcmk_ipc_api_t *api);
} pcmk__ipc_methods_t;

// Implementation of pcmk_ipc_api_t
struct pcmk_ipc_api_s {
    enum pcmk_ipc_server server;          // Daemon this IPC API instance is for
    enum pcmk_ipc_dispatch dispatch_type; // How replies should be dispatched
    crm_ipc_t *ipc;                       // IPC connection
    mainloop_io_t *mainloop_io;     // If using mainloop, I/O source for IPC
    bool free_on_disconnect;        // Whether disconnect should free object
    pcmk_ipc_callback_t cb;         // Caller-registered callback (if any)
    void *user_data;                // Caller-registered data (if any)
    void *api_data;                 // For daemon-specific use
    pcmk__ipc_methods_t *cmds;      // Behavior that varies by daemon
};

typedef struct pcmk__ipc_header_s {
    struct qb_ipc_response_header qb;
    uint32_t size;
    uint32_t flags;
    uint8_t version;
    uint16_t part_id;               // If this is a multipart message, which part is this?
} pcmk__ipc_header_t;

G_GNUC_INTERNAL
int pcmk__send_ipc_request(pcmk_ipc_api_t *api, const xmlNode *request);

G_GNUC_INTERNAL
void pcmk__call_ipc_callback(pcmk_ipc_api_t *api,
                             enum pcmk_ipc_event event_type,
                             crm_exit_t status, void *event_data);

G_GNUC_INTERNAL
bool pcmk__valid_ipc_header(const pcmk__ipc_header_t *header);

G_GNUC_INTERNAL
pcmk__ipc_methods_t *pcmk__attrd_api_methods(void);

G_GNUC_INTERNAL
pcmk__ipc_methods_t *pcmk__controld_api_methods(void);

G_GNUC_INTERNAL
pcmk__ipc_methods_t *pcmk__pacemakerd_api_methods(void);

G_GNUC_INTERNAL
pcmk__ipc_methods_t *pcmk__schedulerd_api_methods(void);


/*
 * Logging
 */

//! XML is newly created
#define PCMK__XML_PREFIX_CREATED "++"

//! XML has been deleted
#define PCMK__XML_PREFIX_DELETED "--"

//! XML has been modified
#define PCMK__XML_PREFIX_MODIFIED "+ "

//! XML has been moved
#define PCMK__XML_PREFIX_MOVED "+~"

/*
 * Output
 */
G_GNUC_INTERNAL
int pcmk__bare_output_new(pcmk__output_t **out, const char *fmt_name,
                          const char *filename, char **argv);

G_GNUC_INTERNAL
void pcmk__register_option_messages(pcmk__output_t *out);

G_GNUC_INTERNAL
void pcmk__register_patchset_messages(pcmk__output_t *out);

G_GNUC_INTERNAL
bool pcmk__output_text_get_fancy(pcmk__output_t *out);

/*
 * Rules
 */

// How node attribute values may be compared in rules
enum pcmk__comparison {
    pcmk__comparison_unknown,
    pcmk__comparison_defined,
    pcmk__comparison_undefined,
    pcmk__comparison_eq,
    pcmk__comparison_ne,
    pcmk__comparison_lt,
    pcmk__comparison_lte,
    pcmk__comparison_gt,
    pcmk__comparison_gte,
};

// How node attribute values may be parsed in rules
enum pcmk__type {
    pcmk__type_unknown,
    pcmk__type_string,
    pcmk__type_integer,
    pcmk__type_number,
    pcmk__type_version,
};

// Where to obtain reference value for a node attribute comparison
enum pcmk__reference_source {
    pcmk__source_unknown,
    pcmk__source_literal,
    pcmk__source_instance_attrs,
    pcmk__source_meta_attrs,
};

G_GNUC_INTERNAL
enum pcmk__comparison pcmk__parse_comparison(const char *op);

G_GNUC_INTERNAL
enum pcmk__type pcmk__parse_type(const char *type, enum pcmk__comparison op,
                                 const char *value1, const char *value2);

G_GNUC_INTERNAL
enum pcmk__reference_source pcmk__parse_source(const char *source);

G_GNUC_INTERNAL
int pcmk__cmp_by_type(const char *value1, const char *value2,
                      enum pcmk__type type);

G_GNUC_INTERNAL
int pcmk__unpack_duration(const xmlNode *duration, const crm_time_t *start,
                          crm_time_t **end);

G_GNUC_INTERNAL
int pcmk__evaluate_date_spec(const xmlNode *date_spec, const crm_time_t *now);

G_GNUC_INTERNAL
int pcmk__evaluate_attr_expression(const xmlNode *expression,
                                   const pcmk_rule_input_t *rule_input);

G_GNUC_INTERNAL
int pcmk__evaluate_rsc_expression(const xmlNode *expr,
                                  const pcmk_rule_input_t *rule_input);

G_GNUC_INTERNAL
int pcmk__evaluate_op_expression(const xmlNode *expr,
                                 const pcmk_rule_input_t *rule_input);


/*
 * Schemas
 */
typedef struct {
    unsigned char v[2];
} pcmk__schema_version_t;

enum pcmk__schema_validator {
    pcmk__schema_validator_none,
    pcmk__schema_validator_rng
};

typedef struct {
    int schema_index;
    char *name;

    /*!
     * List of XSLT stylesheets for upgrading from this schema version to the
     * next one. Sorted by the order in which they should be applied to the CIB.
     */
    GList *transforms;

    void *cache;
    enum pcmk__schema_validator validator;
    pcmk__schema_version_t version;
} pcmk__schema_t;

G_GNUC_INTERNAL
GList *pcmk__find_x_0_schema(void);

#ifdef __cplusplus
}
#endif

#endif  // PCMK__COMMON_CRMCOMMON_PRIVATE__H
