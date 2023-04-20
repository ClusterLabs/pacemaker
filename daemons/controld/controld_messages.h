/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef XML_CRM_MESSAGES__H
#  define XML_CRM_MESSAGES__H

#  include <crm/crm.h>
#  include <crm/common/ipc_internal.h>
#  include <crm/common/xml.h>
#  include <crm/cluster/internal.h>
#  include <controld_fsa.h>

typedef struct ha_msg_input_s {
    xmlNode *msg;
    xmlNode *xml;

} ha_msg_input_t;

extern void delete_ha_msg_input(ha_msg_input_t * orig);

extern void *fsa_typed_data_adv(fsa_data_t * fsa_data, enum fsa_data_type a_type,
                                const char *caller);

#  define fsa_typed_data(x) fsa_typed_data_adv(msg_data, x, __func__)

extern void register_fsa_error_adv(enum crmd_fsa_cause cause, enum crmd_fsa_input input,
                                   fsa_data_t * cur_data, void *new_data, const char *raised_from);

#define register_fsa_error(cause, input, new_data)  \
    register_fsa_error_adv(cause, input, msg_data, new_data, __func__)

void register_fsa_input_adv(enum crmd_fsa_cause cause,
                            enum crmd_fsa_input input, void *data,
                            uint64_t with_actions, gboolean prepend,
                            const char *raised_from);

extern void fsa_dump_queue(int log_level);
extern void route_message(enum crmd_fsa_cause cause, xmlNode * input);

#  define crmd_fsa_stall(suppress) do {                                 \
    if(suppress == FALSE && msg_data != NULL) {                         \
        register_fsa_input_adv(                                         \
            ((fsa_data_t*)msg_data)->fsa_cause, I_WAIT_FOR_EVENT,       \
            ((fsa_data_t*)msg_data)->data, action, TRUE, __func__);     \
    } else {                                                            \
        register_fsa_input_adv(                                         \
            C_FSA_INTERNAL, I_WAIT_FOR_EVENT,                           \
            NULL, action, TRUE, __func__);                              \
    }                                                                   \
    } while(0)

#define register_fsa_input(cause, input, data)          \
    register_fsa_input_adv(cause, input, data, A_NOTHING, FALSE, __func__)

#define register_fsa_input_before(cause, input, data)   \
    register_fsa_input_adv(cause, input, data, A_NOTHING, TRUE, __func__)

#define register_fsa_input_later(cause, input, data)    \
    register_fsa_input_adv(cause, input, data, A_NOTHING, FALSE, __func__)

void delete_fsa_input(fsa_data_t * fsa_data);

fsa_data_t *get_message(void);

extern gboolean relay_message(xmlNode * relay_message, gboolean originated_locally);

gboolean crmd_is_proxy_session(const char *session);
void crmd_proxy_send(const char *session, xmlNode *msg);

bool controld_authorize_ipc_message(const xmlNode *client_msg,
                                    pcmk__client_t *curr_client,
                                    const char *proxy_session);

extern gboolean send_request(xmlNode * msg, char **msg_reference);

extern ha_msg_input_t *copy_ha_msg_input(ha_msg_input_t * orig);

void broadcast_remote_state_message(const char *node_name, bool node_up);

#endif
