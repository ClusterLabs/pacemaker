/*
 * Copyright 2006-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRM_INTERNAL__H
#  define CRM_INTERNAL__H

#  include <config.h>
#  include <portability.h>

#  include <glib.h>
#  include <stdbool.h>
#  include <libxml/tree.h>

/* Public API headers can guard deprecated code with this symbol, thus
 * preventing internal code (which includes this header) from using it, while
 * still allowing external code (which can't include this header) to use it,
 * for backward compatibility.
 */
#define PCMK__NO_COMPAT

#  include <crm/lrmd.h>
#  include <crm/common/logging.h>
#  include <crm/common/ipcs_internal.h>
#  include <crm/common/options_internal.h>
#  include <crm/common/internal.h>

/* Dynamic loading of libraries */
void *find_library_function(void **handle, const char *lib, const char *fn, int fatal);

/* char2score */
extern int node_score_red;
extern int node_score_green;
extern int node_score_yellow;

/* Assorted convenience functions */
void crm_make_daemon(const char *name, gboolean daemonize, const char *pidfile);

static inline long long
crm_clear_bit(const char *function, int line, const char *target, long long word, long long bit)
{
    long long rc = (word & ~bit);

    if (rc == word) {
        /* Unchanged */
    } else if (target) {
        crm_trace("Bit 0x%.8llx for %s cleared by %s:%d", bit, target, function, line);
    } else {
        crm_trace("Bit 0x%.8llx cleared by %s:%d", bit, function, line);
    }

    return rc;
}

static inline long long
crm_set_bit(const char *function, int line, const char *target, long long word, long long bit)
{
    long long rc = (word | bit);

    if (rc == word) {
        /* Unchanged */
    } else if (target) {
        crm_trace("Bit 0x%.8llx for %s set by %s:%d", bit, target, function, line);
    } else {
        crm_trace("Bit 0x%.8llx set by %s:%d", bit, function, line);
    }

    return rc;
}

#  define set_bit(word, bit) word = crm_set_bit(__FUNCTION__, __LINE__, NULL, word, bit)
#  define clear_bit(word, bit) word = crm_clear_bit(__FUNCTION__, __LINE__, NULL, word, bit)

char *generate_hash_key(const char *crm_msg_reference, const char *sys);

void strip_text_nodes(xmlNode * xml);
void pcmk_panic(const char *origin);
pid_t pcmk_locate_sbd(void);


/*
 * XML attribute names used only by internal code
 */

#define PCMK__XA_ATTR_DAMPENING         "attr_dampening"
#define PCMK__XA_ATTR_FORCE             "attrd_is_force_write"
#define PCMK__XA_ATTR_INTERVAL          "attr_clear_interval"
#define PCMK__XA_ATTR_IS_PRIVATE        "attr_is_private"
#define PCMK__XA_ATTR_IS_REMOTE         "attr_is_remote"
#define PCMK__XA_ATTR_NAME              "attr_name"
#define PCMK__XA_ATTR_NODE_ID           "attr_host_id"
#define PCMK__XA_ATTR_NODE_NAME         "attr_host"
#define PCMK__XA_ATTR_OPERATION         "attr_clear_operation"
#define PCMK__XA_ATTR_PATTERN           "attr_regex"
#define PCMK__XA_ATTR_RESOURCE          "attr_resource"
#define PCMK__XA_ATTR_SECTION           "attr_section"
#define PCMK__XA_ATTR_SET               "attr_set"
#define PCMK__XA_ATTR_USER              "attr_user"
#define PCMK__XA_ATTR_UUID              "attr_key"
#define PCMK__XA_ATTR_VALUE             "attr_value"
#define PCMK__XA_ATTR_VERSION           "attr_version"
#define PCMK__XA_ATTR_WRITER            "attr_writer"
#define PCMK__XA_MODE                   "mode"
#define PCMK__XA_TASK                   "task"


/*
 * IPC service names that are only used internally
 */

#  define PCMK__SERVER_BASED_RO		"cib_ro"
#  define PCMK__SERVER_BASED_RW		"cib_rw"
#  define PCMK__SERVER_BASED_SHM		"cib_shm"

/*
 * IPC commands that can be sent to Pacemaker daemons
 */

#define PCMK__ATTRD_CMD_ATTR_REMOVE     "attr-remove"
#define PCMK__ATTRD_CMD_PEER_REMOVE     "peer-remove"
#define PCMK__ATTRD_CMD_PEER_CLEAR      "peer-clear"
#define PCMK__ATTRD_CMD_UPDATE          "update"
#define PCMK__ATTRD_CMD_UPDATE_BOTH     "update-both"
#define PCMK__ATTRD_CMD_UPDATE_DELAY    "update-delay"
#define PCMK__ATTRD_CMD_QUERY           "query"
#define PCMK__ATTRD_CMD_REFRESH         "refresh"
#define PCMK__ATTRD_CMD_FLUSH           "flush"
#define PCMK__ATTRD_CMD_SYNC            "sync"
#define PCMK__ATTRD_CMD_SYNC_RESPONSE   "sync-response"
#define PCMK__ATTRD_CMD_CLEAR_FAILURE   "clear-failure"


/*
 * Environment variables used by Pacemaker
 */

#define PCMK__ENV_PHYSICAL_HOST         "physical_host"


#  if SUPPORT_COROSYNC
#    include <qb/qbipc_common.h>
#    include <corosync/corotypes.h>
typedef struct qb_ipc_request_header cs_ipc_header_request_t;
typedef struct qb_ipc_response_header cs_ipc_header_response_t;
#  else
typedef struct {
    int size __attribute__ ((aligned(8)));
    int id __attribute__ ((aligned(8)));
} __attribute__ ((aligned(8))) cs_ipc_header_request_t;

typedef struct {
    int size __attribute__ ((aligned(8)));
    int id __attribute__ ((aligned(8)));
    int error __attribute__ ((aligned(8)));
} __attribute__ ((aligned(8))) cs_ipc_header_response_t;

#  endif

static inline void *
realloc_safe(void *ptr, size_t size)
{
    void *new_ptr;

    // realloc(p, 0) can replace free(p) but this wrapper can't
    CRM_ASSERT(size > 0);

    new_ptr = realloc(ptr, size);
    if (new_ptr == NULL) {
        free(ptr);
        abort();
    }
    return new_ptr;
}

const char *crm_xml_add_last_written(xmlNode *xml_node);
void crm_xml_dump(xmlNode * data, int options, char **buffer, int *offset, int *max, int depth);
void crm_buffer_add_char(char **buffer, int *offset, int *max, char c);

/* IPC Proxy Backend Shared Functions */
typedef struct remote_proxy_s {
    char *node_name;
    char *session_id;

    gboolean is_local;

    crm_ipc_t *ipc;
    mainloop_io_t *source;
    uint32_t last_request_id;
    lrmd_t *lrm;

} remote_proxy_t;

remote_proxy_t *remote_proxy_new(
    lrmd_t *lrmd, struct ipc_client_callbacks *proxy_callbacks,
    const char *node_name, const char *session_id, const char *channel);

int  remote_proxy_check(lrmd_t *lrmd, GHashTable *hash);
void remote_proxy_cb(lrmd_t *lrmd, const char *node_name, xmlNode *msg);
void remote_proxy_ack_shutdown(lrmd_t *lrmd);
void remote_proxy_nack_shutdown(lrmd_t *lrmd);

int  remote_proxy_dispatch(const char *buffer, ssize_t length, gpointer userdata);
void remote_proxy_disconnected(gpointer data);
void remote_proxy_free(gpointer data);

void remote_proxy_relay_event(remote_proxy_t *proxy, xmlNode *msg);
void remote_proxy_relay_response(remote_proxy_t *proxy, xmlNode *msg, int msg_id);

#endif                          /* CRM_INTERNAL__H */
