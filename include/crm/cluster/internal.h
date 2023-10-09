/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRM_CLUSTER_INTERNAL__H
#  define CRM_CLUSTER_INTERNAL__H

#  include <stdint.h>       // uint32_t, uint64_t
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

/*!
 * \internal
 * \brief Get log-friendly string description of a Corosync return code
 *
 * \param[in] error  Corosync return code
 *
 * \return Log-friendly string description corresponding to \p error
 */
static inline const char *
pcmk__cs_err_str(int error)
{
#  if SUPPORT_COROSYNC
    switch (error) {
        case CS_OK:                         return "OK";
        case CS_ERR_LIBRARY:                return "Library error";
        case CS_ERR_VERSION:                return "Version error";
        case CS_ERR_INIT:                   return "Initialization error";
        case CS_ERR_TIMEOUT:                return "Timeout";
        case CS_ERR_TRY_AGAIN:              return "Try again";
        case CS_ERR_INVALID_PARAM:          return "Invalid parameter";
        case CS_ERR_NO_MEMORY:              return "No memory";
        case CS_ERR_BAD_HANDLE:             return "Bad handle";
        case CS_ERR_BUSY:                   return "Busy";
        case CS_ERR_ACCESS:                 return "Access error";
        case CS_ERR_NOT_EXIST:              return "Doesn't exist";
        case CS_ERR_NAME_TOO_LONG:          return "Name too long";
        case CS_ERR_EXIST:                  return "Exists";
        case CS_ERR_NO_SPACE:               return "No space";
        case CS_ERR_INTERRUPT:              return "Interrupt";
        case CS_ERR_NAME_NOT_FOUND:         return "Name not found";
        case CS_ERR_NO_RESOURCES:           return "No resources";
        case CS_ERR_NOT_SUPPORTED:          return "Not supported";
        case CS_ERR_BAD_OPERATION:          return "Bad operation";
        case CS_ERR_FAILED_OPERATION:       return "Failed operation";
        case CS_ERR_MESSAGE_ERROR:          return "Message error";
        case CS_ERR_QUEUE_FULL:             return "Queue full";
        case CS_ERR_QUEUE_NOT_AVAILABLE:    return "Queue not available";
        case CS_ERR_BAD_FLAGS:              return "Bad flags";
        case CS_ERR_TOO_BIG:                return "Too big";
        case CS_ERR_NO_SECTIONS:            return "No sections";
    }
#  endif
    return "Corosync error";
}

#  if SUPPORT_COROSYNC

#if 0
/* This is the new way to do it, but we still support all Corosync 2 versions,
 * and this isn't always available. A better alternative here would be to check
 * for support in the configure script and enable this conditionally.
 */
#define pcmk__init_cmap(handle) cmap_initialize_map((handle), CMAP_MAP_ICMAP)
#else
#define pcmk__init_cmap(handle) cmap_initialize(handle)
#endif

char *pcmk__corosync_cluster_name(void);
bool pcmk__corosync_add_nodes(xmlNode *xml_parent);
#  endif

crm_node_t *crm_update_peer_proc(const char *source, crm_node_t * peer,
                                 uint32_t flag, const char *status);
crm_node_t *pcmk__update_peer_state(const char *source, crm_node_t *node,
                                    const char *state, uint64_t membership);

void pcmk__update_peer_expected(const char *source, crm_node_t *node,
                                const char *expected);
void pcmk__reap_unseen_nodes(uint64_t ring_id);

void pcmk__corosync_quorum_connect(gboolean (*dispatch)(unsigned long long,
                                                        gboolean),
                                   void (*destroy) (gpointer));
crm_node_t *pcmk__search_node_caches(unsigned int id, const char *uname,
                                     uint32_t flags);
crm_node_t *pcmk__search_cluster_node_cache(unsigned int id, const char *uname,
                                            const char *uuid);

void pcmk__refresh_node_caches_from_cib(xmlNode *cib);
crm_node_t *pcmk__search_known_node_cache(unsigned int id, const char *uname,
                                          uint32_t flags);

crm_node_t *pcmk__get_peer(unsigned int id, const char *uname,
                           const char *uuid);
crm_node_t *pcmk__get_peer_full(unsigned int id, const char *uname,
                                const char *uuid, int flags);

#endif
