/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_TLS_INTERNAL__H
#define PCMK__CRM_COMMON_TLS_INTERNAL__H

#include <gnutls/gnutls.h>  // gnutls_session_t, gnutls_dh_params_t, etc.

#include <crm/common/ipc_internal.h>        // pcmk__client_t
#include <crm/common/remote_internal.h>     // pcmk__remote_t

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \internal
 * \brief Initialize Diffie-Hellman parameters for a TLS server
 *
 * \param[out] dh_params  Parameter object to initialize
 *
 * \return Standard Pacemaker return code
 * \todo The current best practice is to allow the client and server to
 *       negotiate the Diffie-Hellman parameters via a TLS extension (RFC 7919).
 *       However, we have to support both older versions of GnuTLS (<3.6) that
 *       don't support the extension on our side, and older Pacemaker versions
 *       that don't support the extension on the other side. The next best
 *       practice would be to use a known good prime (see RFC 5114 section 2.2),
 *       possibly stored in a file distributed with Pacemaker.
 */
int pcmk__init_tls_dh(gnutls_dh_params_t *dh_params);

/*!
 * \internal
 * \brief Initialize a new TLS session
 *
 * \param[in] csock       Connected socket for TLS session
 * \param[in] conn_type   GNUTLS_SERVER or GNUTLS_CLIENT
 * \param[in] cred_type   GNUTLS_CRD_ANON or GNUTLS_CRD_PSK
 * \param[in] credentials TLS session credentials
 *
 * \return Pointer to newly created session object, or NULL on error
 */
gnutls_session_t pcmk__new_tls_session(int csock, unsigned int conn_type,
                                       gnutls_credentials_type_t cred_type,
                                       void *credentials);

/*!
 * \internal
 * \brief Process handshake data from TLS client
 *
 * Read as much TLS handshake data as is available.
 *
 * \param[in] client  Client connection
 *
 * \return Standard Pacemaker return code (of particular interest, EAGAIN
 *         if some data was successfully read but more data is needed)
 */
int pcmk__read_handshake_data(const pcmk__client_t *client);

/*!
 * \internal
 * \brief Perform client TLS handshake after establishing TCP socket
 *
 * \param[in,out] remote       Newly established remote connection
 * \param[in]     timeout_sec  Abort handshake if not completed within this time
 * \param[out]    gnutls_rc    If this is non-NULL, it will be set to the GnuTLS
 *                             rc (for logging) if this function returns EPROTO,
 *                             otherwise GNUTLS_E_SUCCESS
 *
 * \return Standard Pacemaker return code
 */
int pcmk__tls_client_handshake(pcmk__remote_t *remote, int timeout_sec,
                               int *gnutls_rc);

/*!
 * \internal
 * \brief Make a single attempt to perform the client TLS handshake
 *
 * \param[in,out] remote       Newly established remote connection
 * \param[out]    gnutls_rc    If this is non-NULL, it will be set to the GnuTLS
 *                             rc (for logging) if this function returns EPROTO,
 *                             otherwise GNUTLS_E_SUCCESS
 *
 * \return Standard Pacemaker return code
 */
int pcmk__tls_client_try_handshake(pcmk__remote_t *remote, int *gnutls_rc);

/*!
 * \internal
 * \brief Is X509 authentication supported by the environment?
 *
 * \param[in] server Is this a server?
 *
 * \return true if the appropriate environment variables are set (see
 *         etc/sysconfig/pacemaker.in), otherwise false
 */
bool pcmk__x509_enabled(bool server);

#ifdef __cplusplus
}
#endif

#endif      // PCMK__CRM_COMMON_TLS_INTERNAL__H
