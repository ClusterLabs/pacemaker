/*
 * Copyright 2024-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                  // EAGAIN, ENODATA, EPROTO, EINVAL, ETIME
#include <signal.h>                 // signal, SIGPIPE, SIG_IGN
#include <stdbool.h>                // bool
#include <stdlib.h>                 // NULL, getenv, free
#include <string.h>                 // memcpy, strdup
#include <syslog.h>                 // LOG_WARNING
#include <time.h>                   // time, time_t

#include <glib.h>                   // g_clear_pointer, g_file_get_contents
#include <gnutls/gnutls.h>          // gnutls_*, GNUTLS_E_SUCCESS
#include <gnutls/x509.h>            // gnutls_x509_*
#include <qb/qblog.h>               // QB_XS

#include <crm/common/internal.h>
#include <crm/common/iso8601.h>     // crm_time_free, crm_time_log_date
#include <crm/common/logging.h>     // CRM_CHECK
#include <crm/common/results.h>     // pcmk_rc_*
#include <crm/lrmd.h>               // DEFAULT_REMOTE_USERNAME

static char *
get_gnutls_priorities(gnutls_credentials_type_t cred_type)
{
    const char *prio_base = pcmk__env_option(PCMK__ENV_TLS_PRIORITIES);

    if (prio_base == NULL) {
        prio_base = PCMK__GNUTLS_PRIORITIES;
    }

    if (cred_type == GNUTLS_CRD_ANON) {
        return pcmk__assert_asprintf("%s:+ANON-DH", prio_base);
    } else if (cred_type == GNUTLS_CRD_PSK) {
        return pcmk__assert_asprintf("%s:+DHE-PSK:+PSK", prio_base);
    } else {
        return strdup(prio_base);
    }
}

static const char *
tls_cred_str(gnutls_credentials_type_t cred_type)
{
    if (cred_type == GNUTLS_CRD_ANON) {
        return "unauthenticated";
    } else if (cred_type == GNUTLS_CRD_PSK) {
        return "shared-key-authenticated";
    } else if (cred_type == GNUTLS_CRD_CERTIFICATE) {
        return "certificate-authenticated";
    } else {
        return "unknown";
    }
}

static int
tls_load_x509_data(pcmk__tls_t *tls)
{
    int rc;

    CRM_CHECK(tls->cred_type == GNUTLS_CRD_CERTIFICATE, return EINVAL);

    /* Load a trusted CA to be used to verify client certificates.  Use
     * of this function instead of gnutls_certificate_set_x509_system_trust
     * means we do not look at the system-wide authorities installed in
     * /etc/pki somewhere.  This requires the cluster admin to set up their
     * own CA.
     */
    rc = gnutls_certificate_set_x509_trust_file(tls->credentials.cert,
                                                tls->ca_file,
                                                GNUTLS_X509_FMT_PEM);
    if (rc <= 0) {
        pcmk__err("Failed to set X509 CA file: %s", gnutls_strerror(rc));
        return ENODATA;
    }

    /* If a Certificate Revocation List (CRL) file was given in the environment,
     * load that now so we know which clients have been banned.
     */
    if (tls->crl_file != NULL) {
        rc = gnutls_certificate_set_x509_crl_file(tls->credentials.cert,
                                                  tls->crl_file,
                                                  GNUTLS_X509_FMT_PEM);
        if (rc < 0) {
            pcmk__err("Failed to set X509 CRL file: %s", gnutls_strerror(rc));
            return ENODATA;
        }
    }

    /* NULL = no password for the key, GNUTLS_PKCS_PLAIN = unencrypted key
     * file
     */
    rc = gnutls_certificate_set_x509_key_file2(tls->credentials.cert,
                                               tls->cert_file, tls->key_file,
                                               GNUTLS_X509_FMT_PEM, NULL,
                                               GNUTLS_PKCS_PLAIN);
    if (rc < 0) {
        pcmk__err("Failed to set X509 cert/key pair: %s", gnutls_strerror(rc));
        return ENODATA;
    }

    return pcmk_rc_ok;
}

static void
_gnutls_log_func(int level, const char *msg)
{
    pcmk__trace("%s", msg);
}

void
pcmk__free_tls(pcmk__tls_t *tls)
{
    if (tls == NULL) {
        return;
    }

    /* This is only set on the server side. */
    if (tls->server) {
        gnutls_dh_params_deinit(tls->dh_params);
    }

    if (tls->cred_type == GNUTLS_CRD_ANON) {
        if (tls->server) {
            gnutls_anon_free_server_credentials(tls->credentials.anon_s);
        } else {
            gnutls_anon_free_client_credentials(tls->credentials.anon_c);
        }
    } else if (tls->cred_type == GNUTLS_CRD_CERTIFICATE) {
        gnutls_certificate_free_credentials(tls->credentials.cert);
    } else if (tls->cred_type == GNUTLS_CRD_PSK) {
        if (tls->server) {
            gnutls_psk_free_server_credentials(tls->credentials.psk_s);
        } else {
            gnutls_psk_free_client_credentials(tls->credentials.psk_c);
        }
    }

    free(tls);
}

int
pcmk__init_tls(pcmk__tls_t **tls, bool server, bool have_psk)
{
    int rc = pcmk_rc_ok;

    if (*tls != NULL) {
        return rc;
    }

    *tls = pcmk__assert_alloc(1, sizeof(pcmk__tls_t));

    signal(SIGPIPE, SIG_IGN);

    gnutls_global_set_log_level(8);
    gnutls_global_set_log_function(_gnutls_log_func);

    if (server) {
        rc = pcmk__init_tls_dh(&(*tls)->dh_params);
        if (rc != pcmk_rc_ok) {
            g_clear_pointer(tls, pcmk__free_tls);
            return rc;
        }
    }

    if (pcmk__x509_enabled()) {
        (*tls)->cred_type = GNUTLS_CRD_CERTIFICATE;

    } else if (have_psk) {
        (*tls)->cred_type = GNUTLS_CRD_PSK;

    } else {
        (*tls)->cred_type = GNUTLS_CRD_ANON;
    }

    (*tls)->server = server;

    if ((*tls)->cred_type == GNUTLS_CRD_ANON) {
        if (server) {
            gnutls_anon_allocate_server_credentials(&(*tls)->credentials.anon_s);
            gnutls_anon_set_server_dh_params((*tls)->credentials.anon_s,
                                             (*tls)->dh_params);
        } else {
            gnutls_anon_allocate_client_credentials(&(*tls)->credentials.anon_c);
        }

    } else if ((*tls)->cred_type == GNUTLS_CRD_CERTIFICATE) {
        /* Try the PCMK_ version of each environment variable first, and if
         * it's not set then try the CIB_ version.
         */
        (*tls)->ca_file = pcmk__env_option(PCMK__ENV_CA_FILE);
        if (pcmk__str_empty((*tls)->ca_file)) {
            (*tls)->ca_file = getenv("CIB_ca_file");
        }

        (*tls)->cert_file = pcmk__env_option(PCMK__ENV_CERT_FILE);
        if (pcmk__str_empty((*tls)->cert_file)) {
            (*tls)->cert_file = getenv("CIB_cert_file");
        }

        (*tls)->crl_file = pcmk__env_option(PCMK__ENV_CRL_FILE);
        if (pcmk__str_empty((*tls)->crl_file)) {
            (*tls)->crl_file = getenv("CIB_crl_file");
        }

        (*tls)->key_file = pcmk__env_option(PCMK__ENV_KEY_FILE);
        if (pcmk__str_empty((*tls)->key_file)) {
            (*tls)->key_file = getenv("CIB_key_file");
        }

        gnutls_certificate_allocate_credentials(&(*tls)->credentials.cert);

        if (server) {
            gnutls_certificate_set_dh_params((*tls)->credentials.cert,
                                             (*tls)->dh_params);

        }

        rc = tls_load_x509_data(*tls);
        if (rc != pcmk_rc_ok) {
            g_clear_pointer(tls, pcmk__free_tls);
            return rc;
        }
    } else {    // GNUTLS_CRD_PSK
        if (server) {
            gnutls_psk_allocate_server_credentials(&(*tls)->credentials.psk_s);
            gnutls_psk_set_server_dh_params((*tls)->credentials.psk_s,
                                            (*tls)->dh_params);
        } else {
            gnutls_psk_allocate_client_credentials(&(*tls)->credentials.psk_c);
        }
    }

    return rc;
}

int
pcmk__init_tls_dh(gnutls_dh_params_t *dh_params)
{
    int rc = GNUTLS_E_SUCCESS;
    unsigned int dh_bits = 0;
    int dh_max_bits = 0;

    rc = gnutls_dh_params_init(dh_params);
    if (rc != GNUTLS_E_SUCCESS) {
        goto error;
    }

    dh_bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH,
                                          GNUTLS_SEC_PARAM_NORMAL);
    if (dh_bits == 0) {
        rc = GNUTLS_E_DH_PRIME_UNACCEPTABLE;
        goto error;
    }

    pcmk__scan_min_int(pcmk__env_option(PCMK__ENV_DH_MAX_BITS), &dh_max_bits, 0);
    if ((dh_max_bits > 0) && (dh_bits > dh_max_bits)) {
        dh_bits = dh_max_bits;
    }

    pcmk__info("Generating Diffie-Hellman parameters with %u-bit prime for TLS",
               dh_bits);
    rc = gnutls_dh_params_generate2(*dh_params, dh_bits);
    if (rc != GNUTLS_E_SUCCESS) {
        goto error;
    }

    return pcmk_rc_ok;

error:
    pcmk__err("Could not initialize Diffie-Hellman parameters for TLS: %s "
              QB_XS " rc=%d",
              gnutls_strerror(rc), rc);
    return EPROTO;
}

gnutls_session_t
pcmk__new_tls_session(pcmk__tls_t *tls, int csock)
{
    unsigned int conn_type = GNUTLS_CLIENT;
    int rc = GNUTLS_E_SUCCESS;
    char *prio = NULL;
    gnutls_session_t session = NULL;

    CRM_CHECK((tls != NULL) && (csock >= 0), return NULL);

    if (tls->server) {
        conn_type = GNUTLS_SERVER;
    }

    rc = gnutls_init(&session, conn_type);
    if (rc != GNUTLS_E_SUCCESS) {
        goto error;
    }

    /* Determine list of acceptable ciphers, etc. Pacemaker always adds the
     * values required for its functionality.
     *
     * For an example of anonymous authentication, see:
     * http://www.manpagez.com/info/gnutls/gnutls-2.10.4/gnutls_81.php#Echo-Server-with-anonymous-authentication
     */
    prio = get_gnutls_priorities(tls->cred_type);

    /* @TODO On the server side, it would be more efficient to cache the
     * priority with gnutls_priority_init2() and set it with
     * gnutls_priority_set() for all sessions.
     */
    rc = gnutls_priority_set_direct(session, prio, NULL);
    if (rc != GNUTLS_E_SUCCESS) {
        goto error;
    }

    gnutls_transport_set_int(session, csock);

    /* gnutls does not make this easy */
    if (tls->cred_type == GNUTLS_CRD_ANON && tls->server) {
        rc = gnutls_credentials_set(session, tls->cred_type, tls->credentials.anon_s);
    } else if (tls->cred_type == GNUTLS_CRD_ANON) {
        rc = gnutls_credentials_set(session, tls->cred_type, tls->credentials.anon_c);
    } else if (tls->cred_type == GNUTLS_CRD_CERTIFICATE) {
        rc = gnutls_credentials_set(session, tls->cred_type, tls->credentials.cert);
    } else if (tls->cred_type == GNUTLS_CRD_PSK && tls->server) {
        rc = gnutls_credentials_set(session, tls->cred_type, tls->credentials.psk_s);
    } else if (tls->cred_type == GNUTLS_CRD_PSK) {
        rc = gnutls_credentials_set(session, tls->cred_type, tls->credentials.psk_c);
    } else {
        pcmk__err("Unknown credential type: %d", tls->cred_type);
        rc = EINVAL;
        goto error;
    }

    if (rc != GNUTLS_E_SUCCESS) {
        goto error;
    }

    free(prio);

    if (tls->cred_type == GNUTLS_CRD_CERTIFICATE) {
        if (conn_type == GNUTLS_SERVER) {
            /* Require the client to send a certificate for the server to verify. */
            gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUIRE);
        }

        // Register a function to verify the peer's certificate
        gnutls_session_set_verify_cert(session, NULL, 0);
    }

    return session;

error:
    pcmk__err("Could not initialize %s TLS %s session: %s "
              QB_XS " rc=%d priority='%s'",
              tls_cred_str(tls->cred_type),
              ((conn_type == GNUTLS_SERVER)? "server" : "client"),
              gnutls_strerror(rc), rc, prio);
    free(prio);
    if (session != NULL) {
        gnutls_deinit(session);
    }
    return NULL;
}

int
pcmk__tls_get_client_sock(const pcmk__remote_t *remote)
{
    pcmk__assert((remote != NULL) && (remote->tls_session != NULL));

    return gnutls_transport_get_int(remote->tls_session);
}

int
pcmk__read_handshake_data(const pcmk__client_t *client)
{
    int rc = 0;

    pcmk__assert((client != NULL) && (client->remote != NULL)
                 && (client->remote->tls_session != NULL));

    do {
        rc = gnutls_handshake(client->remote->tls_session);
    } while (rc == GNUTLS_E_INTERRUPTED);

    if (rc == GNUTLS_E_AGAIN) {
        /* No more data is available at the moment. This function should be
         * invoked again once the client sends more.
         */
        return EAGAIN;
    } else if (rc == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR) {
        int type = gnutls_certificate_type_get(client->remote->tls_session);
        unsigned int status = gnutls_session_get_verify_cert_status(client->remote->tls_session);
        gnutls_datum_t out;

        gnutls_certificate_verification_status_print(status, type, &out, 0);
        pcmk__err("Certificate verification failed: %s", out.data);
        gnutls_free(out.data);
    } else if (rc != GNUTLS_E_SUCCESS) {
        pcmk__err("TLS handshake with remote client failed: %s " QB_XS " rc=%d",
                  gnutls_strerror(rc), rc);
        return EPROTO;
    }
    return pcmk_rc_ok;
}

void
pcmk__tls_add_psk_key(pcmk__tls_t *tls, gnutls_datum_t *key)
{
    gnutls_psk_set_client_credentials(tls->credentials.psk_c,
                                      DEFAULT_REMOTE_USERNAME, key,
                                      GNUTLS_PSK_KEY_RAW);
}

void
pcmk__tls_add_psk_callback(pcmk__tls_t *tls,
                           gnutls_psk_server_credentials_function *cb)
{
    gnutls_psk_set_server_credentials_function(tls->credentials.psk_s, cb);
}

void
pcmk__tls_check_cert_expiration(gnutls_session_t session)
{
    gnutls_x509_crt_t cert;
    const gnutls_datum_t *datum = NULL;
    time_t expiry;

    if (session == NULL) {
        return;
    }

    if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509) {
        return;
    }

    datum = gnutls_certificate_get_ours(session);
    if (datum == NULL) {
        return;
    }

    gnutls_x509_crt_init(&cert);
    gnutls_x509_crt_import(cert, datum, GNUTLS_X509_FMT_DER);

    expiry = gnutls_x509_crt_get_expiration_time(cert);

    if (expiry != -1) {
        time_t now = time(NULL);

        /* If the cert is going to expire within ~ one month (30 days), log it */
        if (expiry - now <= 60 * 60 * 24 * 30) {
            crm_time_t *expiry_t = pcmk__copy_timet(expiry);

            pcmk__time_log(LOG_WARNING, "TLS certificate will expire on",
                           expiry_t, crm_time_log_date|crm_time_log_timeofday);
            crm_time_free(expiry_t);
        }
    }

    gnutls_x509_crt_deinit(cert);
}

int
pcmk__tls_client_try_handshake(pcmk__remote_t *remote, int *gnutls_rc)
{
    int rc = pcmk_rc_ok;

    if (gnutls_rc != NULL) {
        *gnutls_rc = GNUTLS_E_SUCCESS;
    }

    rc = gnutls_handshake(remote->tls_session);

    switch (rc) {
        case GNUTLS_E_SUCCESS:
            rc = pcmk_rc_ok;
            break;

        case GNUTLS_E_INTERRUPTED:
        case GNUTLS_E_AGAIN:
            rc = EAGAIN;
            break;

        case GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR: {
            int type = gnutls_certificate_type_get(remote->tls_session);
            unsigned int status = gnutls_session_get_verify_cert_status(remote->tls_session);
            gnutls_datum_t out;

            gnutls_certificate_verification_status_print(status, type, &out, 0);
            pcmk__err("Certificate verification failed: %s", out.data);
            gnutls_free(out.data);
            break;
        }

        default:
            if (gnutls_rc != NULL) {
                *gnutls_rc = rc;
            }

            rc = EPROTO;
            break;
    }

    return rc;
}

int
pcmk__tls_client_handshake(pcmk__remote_t *remote, int timeout_sec,
                           int *gnutls_rc)
{
    const time_t time_limit = time(NULL) + timeout_sec;

    do {
        int rc = pcmk__tls_client_try_handshake(remote, gnutls_rc);

        if (rc != EAGAIN) {
            return rc;
        }
    } while (time(NULL) < time_limit);

    return ETIME;
}

bool
pcmk__x509_enabled(void)
{
    /* Environment variables for servers come through the sysconfig file, and
     * have names like PCMK_<whatever>.  Environment variables for clients come
     * from the environment and have names like CIB_<whatever>.  This function
     * is used for both, so we need to check both.
     */
    return (!pcmk__str_empty(pcmk__env_option(PCMK__ENV_CERT_FILE)) ||
            !pcmk__str_empty(getenv("CIB_cert_file"))) &&
           (!pcmk__str_empty(pcmk__env_option(PCMK__ENV_CA_FILE)) ||
            !pcmk__str_empty(getenv("CIB_ca_file"))) &&
           (!pcmk__str_empty(pcmk__env_option(PCMK__ENV_KEY_FILE)) ||
            !pcmk__str_empty(getenv("CIB_key_file")));
}

void
pcmk__copy_key(gnutls_datum_t *dest, const gnutls_datum_t *source)
{
    pcmk__assert((dest != NULL) && (source != NULL) && (source->data != NULL));

    dest->data = gnutls_malloc(source->size);
    pcmk__mem_assert(dest->data);

    memcpy(dest->data, source->data, source->size);
    dest->size = source->size;
}

int
pcmk__load_key(const char *location, gnutls_datum_t *key)
{
    gchar *contents = NULL;
    gsize len = 0;

    pcmk__assert((location != NULL) && (key != NULL));

    if (!g_file_get_contents(location, &contents, &len, NULL)) {
        return ENOKEY;
    }

    key->size = len;
    key->data = gnutls_malloc(key->size);
    pcmk__mem_assert(key->data);
    memcpy(key->data, contents, key->size);

    g_free(contents);
    return pcmk_rc_ok;
}
