/*
 * Copyright 2004-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRM_CLUSTER_INTERNAL__H
#  define CRM_CLUSTER_INTERNAL__H

#  include <crm/cluster.h>

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
crm_get_cluster_proc(void)
{
    switch (get_cluster_type()) {
        case pcmk_cluster_corosync:
            return crm_proc_cpg;

        default:
            break;
    }
    return crm_proc_none;
}

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

#  if SUPPORT_COROSYNC
char *pcmk__corosync_cluster_name(void);
bool pcmk__corosync_add_nodes(xmlNode *xml_parent);
#  endif

crm_node_t *crm_update_peer_proc(const char *source, crm_node_t * peer,
                                 uint32_t flag, const char *status);
crm_node_t *crm_update_peer_state(const char *source, crm_node_t * node,
                                  const char *state, uint64_t membership);

void crm_update_peer_uname(crm_node_t *node, const char *uname);
void crm_update_peer_expected(const char *source, crm_node_t * node, const char *expected);
void crm_reap_unseen_nodes(uint64_t ring_id);

void pcmk__corosync_quorum_connect(gboolean (*dispatch)(unsigned long long,
                                                        gboolean),
                                   void (*destroy) (gpointer));
crm_node_t * crm_find_peer_full(unsigned int id, const char *uname, int flags);
crm_node_t * crm_find_peer(unsigned int id, const char *uname);

void crm_peer_caches_refresh(xmlNode *cib);
crm_node_t *crm_find_known_peer_full(unsigned int id, const char *uname, int flags);

#endif
