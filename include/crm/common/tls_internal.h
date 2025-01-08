/*
 * Copyright 2024-2025 the Pacemaker project contributors
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

typedef struct {
    bool server;
    gnutls_dh_params_t dh_params;
    gnutls_credentials_type_t cred_type;

    const char *ca_file;
    const char *cert_file;
    const char *crl_file;
    const char *key_file;

    union {
        gnutls_anon_server_credentials_t anon_s;
        gnutls_anon_client_credentials_t anon_c;
        gnutls_certificate_credentials_t cert;
        gnutls_psk_server_credentials_t psk_s;
        gnutls_psk_client_credentials_t psk_c;
    } credentials;
} pcmk__tls_t;

/*!
 * \internal
 * \brief Free a previously allocated \p pcmk__tls_t object
 *
 * \param[in,out] tls The object to free
 */
void pcmk__free_tls(pcmk__tls_t *tls);

/*!
 * \internal
 * \brief Initialize a new TLS object
 *
 * Unlike \p pcmk__new_tls_session, this function is used for creating the
 * global environment for TLS connections.
 *
 * \param[in,out] tls       The object to be allocated and initialized
 * \param[in]     server    Is this a server or not?
 * \param[in]     cred_type What type of gnutls credentials are in use?
 *                          (GNUTLS_CRD_* constants)
 *
 * \returns Standard Pacemaker return code
 */
int pcmk__init_tls(pcmk__tls_t **tls, bool server,
                   gnutls_credentials_type_t cred_type);

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
 * \param[in] tls    TLS environment object
 * \param[in] csock  Connected TCP socket for TLS session
 *
 * \return Pointer to newly created session object, or NULL on error
 */
gnutls_session_t pcmk__new_tls_session(pcmk__tls_t *tls, int csock);

int pcmk__tls_get_client_sock(const pcmk__remote_t *remote);

/*!
 * \internal
 * \brief Add the client PSK key to the TLS environment
 *
 * This function must be called for all TLS clients that are using PSK for
 * authentication.
 *
 * \param[in,out] tls The TLS environment
 * \param[in]     key The client's PSK key
 */
void pcmk__tls_add_psk_key(pcmk__tls_t *tls, gnutls_datum_t *key);

/*!
 * \internal
 * \brief Register the server's PSK credential fetching callback
 *
 * This function must be called for all TLS servers that are using PSK for
 * authentication.
 *
 * \param[in,out] tls The TLS environment
 * \param[in]     cb  The server's PSK credential fetching callback
 */
void pcmk__tls_add_psk_callback(pcmk__tls_t *tls,
                                gnutls_psk_server_credentials_function *cb);

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
 * \brief Log if a TLS certificate is near its expiration date
 *
 * \param[in] session The gnutls session object after handshaking is
 *                    complete
 */
void pcmk__tls_check_cert_expiration(gnutls_session_t session);

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
 * \return true if the appropriate environment variables are set (see
 *         etc/sysconfig/pacemaker.in), otherwise false
 */
bool pcmk__x509_enabled(void);

#ifdef __cplusplus
}
#endif

#endif      // PCMK__CRM_COMMON_TLS_INTERNAL__H
