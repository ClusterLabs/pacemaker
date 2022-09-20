/*
 * Copyright 2008-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__REMOTE_INTERNAL__H
#  define PCMK__REMOTE_INTERNAL__H

// internal functions from remote.c

typedef struct pcmk__remote_s pcmk__remote_t;

int pcmk__remote_send_xml(pcmk__remote_t *remote, xmlNode *msg);
int pcmk__remote_ready(pcmk__remote_t *remote, int timeout_ms);
int pcmk__read_remote_message(pcmk__remote_t *remote, int timeout_ms);
xmlNode *pcmk__remote_message_xml(pcmk__remote_t *remote);
int pcmk__connect_remote(const char *host, int port, int timeout_ms,
                         int *timer_id, int *sock_fd, void *userdata,
                         void (*callback) (void *userdata, int rc, int sock));
int pcmk__accept_remote_connection(int ssock, int *csock);
void pcmk__sockaddr2str(void *sa, char *s);

#  ifdef HAVE_GNUTLS_GNUTLS_H
#    include <gnutls/gnutls.h>

gnutls_session_t *pcmk__new_tls_session(int csock, unsigned int conn_type,
                                        gnutls_credentials_type_t cred_type,
                                        void *credentials);
int pcmk__init_tls_dh(gnutls_dh_params_t *dh_params);
int pcmk__read_handshake_data(pcmk__client_t *client);

/*!
 * \internal
 * \brief Perform client TLS handshake after establishing TCP socket
 *
 * \param[in,out] remote      Newly established remote connection
 * \param[in]     timeout_ms  Abort if handshake is not complete within this
 *
 * \return Standard Pacemaker return code
 */
int pcmk__tls_client_handshake(pcmk__remote_t *remote, int timeout_ms);

#  endif    // HAVE_GNUTLS_GNUTLS_H
#endif      // PCMK__REMOTE_INTERNAL__H
