/*
 * Copyright 2024-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <tls_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_TLS_INTERNAL__H
#define PCMK__CRM_COMMON_TLS_INTERNAL__H

#include <stdbool.h>

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
 * This function initializes \p tls as an environment for TLS connections. This
 * is in contrast to \c pcmk__new_tls_session(), which initializes a single
 * session within that environment.
 *
 * X.509 certificates are used if configured via environment variables.
 * Otherwise, we fall back to either pre-shared keys (PSK) or anonymous
 * authentication, depending on the value of \p have_psk.
 *
 * \param[out] tls       Where to store new TLS object
 * \param[in]  server    Current process is a server if \c true or a client if
 *                       \c false
 * \param[in]  have_psk  If X.509 certificates are not enabled, then use
 *                       \c GNUTLS_CRD_PSK (pre-shared keys) if this is \c true
 *                       or \c GNUTLS_CRD_ANON (anonymous authentication) if
 *                       this is \c false
 *
 * \return Standard Pacemaker return code
 *
 * \note CIB remote clients and the CIB manager's remote listener are the only
 *       things that use anonymous authentication when X.509 is disabled. Task
 *       T961 is open to implement PSK for those. The only other callers are
 *       executor clients and listeners, which already use PSK.
 */
int pcmk__init_tls(pcmk__tls_t **tls, bool server, bool have_psk);

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

/*!
 * \internal
 * \brief Get the socket file descriptor for a remote connection's TLS session
 *
 * \param[in] remote  Remote connection
 *
 * \return Socket file descriptor for \p remote
 *
 * \note The remote connection's \c tls_session must have already been
 *       initialized using \c pcmk__new_tls_session().
 */
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

/*!
 * \internal
 * \brief Copy an authentication key
 *
 * \param[out] dest    Where to copy the authentication key
 * \param[in]  source  The authentication key to copy
 */
void pcmk__copy_key(gnutls_datum_t *dest, const gnutls_datum_t *source);

/*!
 * \internal
 * \brief Attempt to load an authentication key from disk
 *
 * \param[in]  location  The file path to read from
 * \param[out] dest      Where to store the authentication key
 *
 * \return Standard Pacemaker return code
 */
int pcmk__load_key(const char *location, gnutls_datum_t *key);

#ifdef __cplusplus
}
#endif

#endif      // PCMK__CRM_COMMON_TLS_INTERNAL__H
