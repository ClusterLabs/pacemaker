/*
 * Copyright 2018-2020 the Pacemaker project contributors
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

#include <stdint.h>         // uint8_t, uint32_t
#include <stdbool.h>        // bool
#include <sys/types.h>      // size_t
#include <glib.h>           // GList
#include <libxml/tree.h>    // xmlNode, xmlAttr
#include <qb/qbipcc.h>      // struct qb_ipc_response_header

/*
 * XML and ACLs
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

typedef struct xml_private_s {
        long check;
        uint32_t flags;
        char *user;
        GList *acls;
        GList *deleted_objs;
} xml_private_t;

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
     * \param[in] api  IPC API connection
     *
     * \return Standard Pacemaker return code
     */
    int (*new_data)(pcmk_ipc_api_t *api);

    /*!
     * \internal
     * \brief Free any private data used by daemon IPC
     *
     * \param[in] api_data  Data allocated by new_data() method
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
     * \param[in] api  IPC API connection
     *
     * \return Standard Pacemaker return code
     */
    int (*post_connect)(pcmk_ipc_api_t *api);

    /*!
     * \internal
     * \brief Check whether an IPC request results in a reply
     *
     * \parma[in] api      IPC API connection
     * \param[in] request  IPC request XML
     *
     * \return true if request would result in an IPC reply, false otherwise
     */
    bool (*reply_expected)(pcmk_ipc_api_t *api, xmlNode *request);

    /*!
     * \internal
     * \brief Perform daemon-specific handling of an IPC message
     *
     * \param[in] api  IPC API connection
     * \param[in] msg  Message read from IPC connection
     */
    void (*dispatch)(pcmk_ipc_api_t *api, xmlNode *msg);

    /*!
     * \internal
     * \brief Perform daemon-specific handling of an IPC disconnect
     *
     * \param[in] api  IPC API connection
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
    uint32_t size_uncompressed;
    uint32_t size_compressed;
    uint32_t flags;
    uint8_t version;
} pcmk__ipc_header_t;

G_GNUC_INTERNAL
int pcmk__send_ipc_request(pcmk_ipc_api_t *api, xmlNode *request);

G_GNUC_INTERNAL
void pcmk__call_ipc_callback(pcmk_ipc_api_t *api,
                             enum pcmk_ipc_event event_type,
                             crm_exit_t status, void *event_data);

G_GNUC_INTERNAL
unsigned int pcmk__ipc_buffer_size(unsigned int max);

G_GNUC_INTERNAL
bool pcmk__valid_ipc_header(const pcmk__ipc_header_t *header);

G_GNUC_INTERNAL
pcmk__ipc_methods_t *pcmk__controld_api_methods(void);

#endif  // CRMCOMMON_PRIVATE__H
