/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>
#include <gnutls/gnutls.h>
#include <stdlib.h>

#include <crm/common/tls_internal.h>

static char *
get_gnutls_priorities(gnutls_credentials_type_t cred_type)
{
    const char *prio_base = pcmk__env_option(PCMK__ENV_TLS_PRIORITIES);

    if (prio_base == NULL) {
        prio_base = PCMK__GNUTLS_PRIORITIES;
    }

    return crm_strdup_printf("%s:%s", prio_base,
                             (cred_type == GNUTLS_CRD_ANON)? "+ANON-DH" : "+DHE-PSK:+PSK");
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

    crm_info("Generating Diffie-Hellman parameters with %u-bit prime for TLS",
             dh_bits);
    rc = gnutls_dh_params_generate2(*dh_params, dh_bits);
    if (rc != GNUTLS_E_SUCCESS) {
        goto error;
    }

    return pcmk_rc_ok;

error:
    crm_err("Could not initialize Diffie-Hellman parameters for TLS: %s "
            QB_XS " rc=%d", gnutls_strerror(rc), rc);
    return EPROTO;
}

gnutls_session_t *
pcmk__new_tls_session(int csock, unsigned int conn_type,
                      gnutls_credentials_type_t cred_type, void *credentials)
{
    int rc = GNUTLS_E_SUCCESS;
    char *prio = NULL;
    gnutls_session_t *session = NULL;

    session = gnutls_malloc(sizeof(gnutls_session_t));
    if (session == NULL) {
        rc = GNUTLS_E_MEMORY_ERROR;
        goto error;
    }

    rc = gnutls_init(session, conn_type);
    if (rc != GNUTLS_E_SUCCESS) {
        goto error;
    }

    /* Determine list of acceptable ciphers, etc. Pacemaker always adds the
     * values required for its functionality.
     *
     * For an example of anonymous authentication, see:
     * http://www.manpagez.com/info/gnutls/gnutls-2.10.4/gnutls_81.php#Echo-Server-with-anonymous-authentication
     */
    prio = get_gnutls_priorities(cred_type);

    /* @TODO On the server side, it would be more efficient to cache the
     * priority with gnutls_priority_init2() and set it with
     * gnutls_priority_set() for all sessions.
     */
    rc = gnutls_priority_set_direct(*session, prio, NULL);
    if (rc != GNUTLS_E_SUCCESS) {
        goto error;
    }

    gnutls_transport_set_ptr(*session,
                             (gnutls_transport_ptr_t) GINT_TO_POINTER(csock));

    rc = gnutls_credentials_set(*session, cred_type, credentials);
    if (rc != GNUTLS_E_SUCCESS) {
        goto error;
    }
    free(prio);
    return session;

error:
    crm_err("Could not initialize %s TLS %s session: %s "
            QB_XS " rc=%d priority='%s'",
            (cred_type == GNUTLS_CRD_ANON)? "anonymous" : "PSK",
            (conn_type == GNUTLS_SERVER)? "server" : "client",
            gnutls_strerror(rc), rc, prio);
    free(prio);
    if (session != NULL) {
        gnutls_free(session);
    }
    return NULL;
}

int
pcmk__read_handshake_data(const pcmk__client_t *client)
{
    int rc = 0;

    pcmk__assert((client != NULL) && (client->remote != NULL)
                 && (client->remote->tls_session != NULL));

    do {
        rc = gnutls_handshake(*client->remote->tls_session);
    } while (rc == GNUTLS_E_INTERRUPTED);

    if (rc == GNUTLS_E_AGAIN) {
        /* No more data is available at the moment. This function should be
         * invoked again once the client sends more.
         */
        return EAGAIN;
    } else if (rc != GNUTLS_E_SUCCESS) {
        crm_err("TLS handshake with remote client failed: %s "
                QB_XS " rc=%d", gnutls_strerror(rc), rc);
        return EPROTO;
    }
    return pcmk_rc_ok;
}

int
pcmk__tls_client_try_handshake(pcmk__remote_t *remote, int *gnutls_rc)
{
    int rc = pcmk_rc_ok;

    if (gnutls_rc != NULL) {
        *gnutls_rc = GNUTLS_E_SUCCESS;
    }

    rc = gnutls_handshake(*remote->tls_session);

    switch (rc) {
        case GNUTLS_E_SUCCESS:
            rc = pcmk_rc_ok;
            break;

        case GNUTLS_E_INTERRUPTED:
        case GNUTLS_E_AGAIN:
            rc = EAGAIN;
            break;

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
