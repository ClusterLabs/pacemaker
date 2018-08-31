/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRM_CLUSTER_INTERNAL__H
#  define CRM_CLUSTER_INTERNAL__H

#  include <crm/cluster.h>

typedef struct crm_ais_host_s AIS_Host;
typedef struct crm_ais_msg_s AIS_Message;

struct crm_ais_host_s {
    uint32_t id;
    uint32_t pid;
    gboolean local;
    enum crm_ais_msg_types type;
    uint32_t size;
    char uname[MAX_NAME];

} __attribute__ ((packed));

struct crm_ais_msg_s {
    cs_ipc_header_response_t header __attribute__ ((aligned(8)));
    uint32_t id;
    gboolean is_compressed;

    AIS_Host host;
    AIS_Host sender;

    uint32_t size;
    uint32_t compressed_size;
    /* 584 bytes */
    char data[0];

} __attribute__ ((packed));

/* *INDENT-OFF* */
enum crm_proc_flag {
    crm_proc_none       = 0x00000001,

    // Cluster layers
    crm_proc_cpg        = 0x04000000,

    // Daemons
    crm_proc_execd      = 0x00000010,
    crm_proc_based      = 0x00000100,
    crm_proc_controld   = 0x00000200,
    crm_proc_attrd      = 0x00001000,
    crm_proc_schedulerd = 0x00010000,
    crm_proc_fenced     = 0x00100000,
};
/* *INDENT-ON* */

/*!
 * \internal
 * \brief Return the process bit corresponding to the current cluster stack
 *
 * \return Process flag if detectable, otherwise 0
 */
static inline uint32_t
crm_get_cluster_proc()
{
    switch (get_cluster_type()) {
        case pcmk_cluster_corosync:
            return crm_proc_cpg;

        default:
            break;
    }
    return crm_proc_none;
}

static inline const char *
peer2text(enum crm_proc_flag proc)
{
    const char *text = "unknown";

    switch (proc) {
        case crm_proc_none:
            text = "none";
            break;
        case crm_proc_based:
            text = "pacemaker-based";
            break;
        case crm_proc_controld:
            text = "pacemaker-controld";
            break;
        case crm_proc_schedulerd:
            text = "pacemaker-schedulerd";
            break;
        case crm_proc_execd:
            text = "pacemaker-execd";
            break;
        case crm_proc_attrd:
            text = "pacemaker-attrd";
            break;
        case crm_proc_fenced:
            text = "pacemaker-fenced";
            break;
        case crm_proc_cpg:
            text = "corosync-cpg";
            break;
    }
    return text;
}

static inline const char *
ais_dest(const AIS_Host *host)
{
    if (host->local) {
        return "local";
    } else if (host->size > 0) {
        return host->uname;
    } else {
        return "<all>";
    }
}

#  define ais_data_len(msg) (msg->is_compressed?msg->compressed_size:msg->size)

/*
typedef enum {
   CS_OK = 1,
   CS_ERR_LIBRARY = 2,
   CS_ERR_VERSION = 3,
   CS_ERR_INIT = 4,
   CS_ERR_TIMEOUT = 5,
   CS_ERR_TRY_AGAIN = 6,
   CS_ERR_INVALID_PARAM = 7,
   CS_ERR_NO_MEMORY = 8,
   CS_ERR_BAD_HANDLE = 9,
   CS_ERR_BUSY = 10,
   CS_ERR_ACCESS = 11,
   CS_ERR_NOT_EXIST = 12,
   CS_ERR_NAME_TOO_LONG = 13,
   CS_ERR_EXIST = 14,
   CS_ERR_NO_SPACE = 15,
   CS_ERR_INTERRUPT = 16,
   CS_ERR_NAME_NOT_FOUND = 17,
   CS_ERR_NO_RESOURCES = 18,
   CS_ERR_NOT_SUPPORTED = 19,
   CS_ERR_BAD_OPERATION = 20,
   CS_ERR_FAILED_OPERATION = 21,
   CS_ERR_MESSAGE_ERROR = 22,
   CS_ERR_QUEUE_FULL = 23,
   CS_ERR_QUEUE_NOT_AVAILABLE = 24,
   CS_ERR_BAD_FLAGS = 25,
   CS_ERR_TOO_BIG = 26,
   CS_ERR_NO_SECTIONS = 27,
   CS_ERR_CONTEXT_NOT_FOUND = 28,
   CS_ERR_TOO_MANY_GROUPS = 30,
   CS_ERR_SECURITY = 100
} cs_error_t;
 */
static inline const char *
ais_error2text(int error)
{
    const char *text = "unknown";

#  if SUPPORT_COROSYNC
    switch (error) {
        case CS_OK:
            text = "OK";
            break;
        case CS_ERR_LIBRARY:
            text = "Library error";
            break;
        case CS_ERR_VERSION:
            text = "Version error";
            break;
        case CS_ERR_INIT:
            text = "Initialization error";
            break;
        case CS_ERR_TIMEOUT:
            text = "Timeout";
            break;
        case CS_ERR_TRY_AGAIN:
            text = "Try again";
            break;
        case CS_ERR_INVALID_PARAM:
            text = "Invalid parameter";
            break;
        case CS_ERR_NO_MEMORY:
            text = "No memory";
            break;
        case CS_ERR_BAD_HANDLE:
            text = "Bad handle";
            break;
        case CS_ERR_BUSY:
            text = "Busy";
            break;
        case CS_ERR_ACCESS:
            text = "Access error";
            break;
        case CS_ERR_NOT_EXIST:
            text = "Doesn't exist";
            break;
        case CS_ERR_NAME_TOO_LONG:
            text = "Name too long";
            break;
        case CS_ERR_EXIST:
            text = "Exists";
            break;
        case CS_ERR_NO_SPACE:
            text = "No space";
            break;
        case CS_ERR_INTERRUPT:
            text = "Interrupt";
            break;
        case CS_ERR_NAME_NOT_FOUND:
            text = "Name not found";
            break;
        case CS_ERR_NO_RESOURCES:
            text = "No resources";
            break;
        case CS_ERR_NOT_SUPPORTED:
            text = "Not supported";
            break;
        case CS_ERR_BAD_OPERATION:
            text = "Bad operation";
            break;
        case CS_ERR_FAILED_OPERATION:
            text = "Failed operation";
            break;
        case CS_ERR_MESSAGE_ERROR:
            text = "Message error";
            break;
        case CS_ERR_QUEUE_FULL:
            text = "Queue full";
            break;
        case CS_ERR_QUEUE_NOT_AVAILABLE:
            text = "Queue not available";
            break;
        case CS_ERR_BAD_FLAGS:
            text = "Bad flags";
            break;
        case CS_ERR_TOO_BIG:
            text = "Too big";
            break;
        case CS_ERR_NO_SECTIONS:
            text = "No sections";
            break;
    }
#  endif
    return text;
}

static inline const char *
msg_type2text(enum crm_ais_msg_types type)
{
    const char *text = "unknown";

    switch (type) {
        case crm_msg_none:
            text = "unknown";
            break;
        case crm_msg_ais:
            text = "ais";
            break;
        case crm_msg_cib:
            text = "cib";
            break;
        case crm_msg_crmd:
            text = "crmd";
            break;
        case crm_msg_pe:
            text = "pengine";
            break;
        case crm_msg_te:
            text = "tengine";
            break;
        case crm_msg_lrmd:
            text = "lrmd";
            break;
        case crm_msg_attrd:
            text = "attrd";
            break;
        case crm_msg_stonithd:
            text = "stonithd";
            break;
        case crm_msg_stonith_ng:
            text = "stonith-ng";
            break;
    }
    return text;
}

gboolean check_message_sanity(const AIS_Message * msg, const char *data);

#  if SUPPORT_COROSYNC

gboolean send_cpg_iov(struct iovec * iov);

char *get_corosync_uuid(crm_node_t *peer);
char *corosync_node_name(uint64_t /*cmap_handle_t */ cmap_handle, uint32_t nodeid);
char *corosync_cluster_name(void);
int corosync_cmap_has_config(const char *prefix);

gboolean corosync_initialize_nodelist(void *cluster, gboolean force_member, xmlNode * xml_parent);

gboolean send_cluster_message_cs(xmlNode * msg, gboolean local,
                                 crm_node_t * node, enum crm_ais_msg_types dest);

enum cluster_type_e find_corosync_variant(void);

void terminate_cs_connection(crm_cluster_t * cluster);
gboolean init_cs_connection(crm_cluster_t * cluster);
gboolean init_cs_connection_once(crm_cluster_t * cluster);
#  endif

crm_node_t *crm_update_peer_proc(const char *source, crm_node_t * peer,
                                 uint32_t flag, const char *status);
crm_node_t *crm_update_peer_state(const char *source, crm_node_t * node,
                                  const char *state, int membership);

void crm_update_peer_uname(crm_node_t *node, const char *uname);
void crm_update_peer_expected(const char *source, crm_node_t * node, const char *expected);
void crm_reap_unseen_nodes(uint64_t ring_id);

gboolean cluster_connect_quorum(gboolean(*dispatch) (unsigned long long, gboolean),
                                void (*destroy) (gpointer));

gboolean node_name_is_valid(const char *key, const char *name);

crm_node_t * crm_find_peer_full(unsigned int id, const char *uname, int flags);
crm_node_t * crm_find_peer(unsigned int id, const char *uname);

#endif
