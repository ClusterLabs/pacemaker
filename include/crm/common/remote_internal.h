/*
 * Copyright 2008-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__REMOTE__H
#  define PCMK__REMOTE__H

// internal functions from remote.c

typedef struct crm_remote_s crm_remote_t;

int crm_remote_send(crm_remote_t *remote, xmlNode *msg);
int crm_remote_ready(crm_remote_t *remote, int total_timeout /*ms */ );
gboolean crm_remote_recv(crm_remote_t *remote, int total_timeout /*ms */,
                         int *disconnected);
xmlNode *crm_remote_parse_buffer(crm_remote_t *remote);
int crm_remote_tcp_connect(const char *host, int port);
int crm_remote_tcp_connect_async(const char *host, int port,
                                 int timeout /*ms */,
                                 int *timer_id, void *userdata,
                                 void (*callback) (void *userdata, int sock));
int crm_remote_accept(int ssock);
void crm_sockaddr2str(void *sa, char *s);

#  ifdef HAVE_GNUTLS_GNUTLS_H
#    include <gnutls/gnutls.h>

gnutls_session_t *pcmk__new_tls_session(int csock, unsigned int conn_type,
                                        gnutls_credentials_type_t cred_type,
                                        void *credentials);
/*!
 * \internal
 * \brief Initiate the client handshake after establishing the tcp socket
 *
 * \return 0 on success, negative number on failure
 * \note This function will block until the entire handshake is complete or
 *        until the timeout period is reached.
 */
int crm_initiate_client_tls_handshake(crm_remote_t *remote, int timeout_ms);

#  endif    // HAVE_GNUTLS_GNUTLS_H
#endif      // PCMK__REMOTE__H
