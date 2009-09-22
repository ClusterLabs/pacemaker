/*
 * Copyright (c) 2008 Andrew Beekhof
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#include <crm_internal.h>
#include <crm/crm.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>

#include <netinet/ip.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>

#include <crm/common/ipc.h>
#include <crm/common/xml.h>

#ifdef HAVE_GNUTLS_GNUTLS_H
#  undef KEYFILE
#  include <gnutls/gnutls.h>
#endif

#ifdef HAVE_GNUTLS_GNUTLS_H
const int tls_kx_order[] = {
	  GNUTLS_KX_ANON_DH,
	  GNUTLS_KX_DHE_RSA,
	  GNUTLS_KX_DHE_DSS,
	  GNUTLS_KX_RSA,
	0
};
gnutls_anon_client_credentials anon_cred_c;
gnutls_anon_server_credentials anon_cred_s;
static char *cib_send_tls(gnutls_session *session, xmlNode *msg);
static char *cib_recv_tls(gnutls_session *session);
#endif

char *cib_recv_plaintext(int sock);
char *cib_send_plaintext(int sock, xmlNode *msg);

#ifdef HAVE_GNUTLS_GNUTLS_H
gnutls_session *create_tls_session(int csock, int type);

gnutls_session *
create_tls_session(int csock, int type /* GNUTLS_SERVER, GNUTLS_CLIENT */)
{
	int rc = 0;
	gnutls_session *session = gnutls_malloc(sizeof(gnutls_session));

	gnutls_init(session, type);
	gnutls_set_default_priority(*session);
 	gnutls_kx_set_priority (*session, tls_kx_order);
	gnutls_transport_set_ptr(*session,
				 (gnutls_transport_ptr) GINT_TO_POINTER(csock));
	switch(type) {
	    case GNUTLS_SERVER:
		gnutls_credentials_set(*session, GNUTLS_CRD_ANON, anon_cred_s);
		break;
	    case GNUTLS_CLIENT:
		gnutls_credentials_set(*session, GNUTLS_CRD_ANON, anon_cred_c);
		break;
	}

	do {
		rc = gnutls_handshake (*session);
	} while (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN);

	if (rc < 0) {
		crm_err("Handshake failed: %s", gnutls_strerror(rc));
		gnutls_deinit(*session);
 		gnutls_free(session);
		return NULL;
	}
	return session;
}

static char*
cib_send_tls(gnutls_session *session, xmlNode *msg)
{
	char *xml_text = NULL;
#if 0
	const char *name = crm_element_name(msg);
	if(safe_str_neq(name, "cib_command")) {
	    xmlNodeSetName(msg, "cib_result");
	}
#endif
	xml_text = dump_xml_unformatted(msg);
	if(xml_text != NULL) {
	    char *unsent = xml_text;
	    int len = strlen(xml_text);
	    int rc = 0;
	    
	    len++; /* null char */
	    crm_debug_3("Message size: %d", len);

	  retry:
		rc = gnutls_record_send (*session, unsent, len);
		crm_debug("Sent %d bytes", rc);
		if(rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN) {
		    crm_debug("Retry");
		    goto retry;

		} else if(rc < len) {
		    crm_debug("Only sent %d of %d bytes", rc, len);
		    len -= rc;
		    unsent += rc;
		    goto retry;
		}
		
	}
	crm_free(xml_text);
	return NULL;
	
}

static char*
cib_recv_tls(gnutls_session *session)
{
	int rc = 0;
	int last = 0;
	char* tls_buf = NULL;
	int chunk_size = 1024;
	int len = chunk_size;

	if (session == NULL) {
		return NULL;
	}

	crm_malloc0(tls_buf, chunk_size);
	
	while(1) {
		rc = gnutls_record_recv(*session, tls_buf+last, chunk_size);
		if (rc == 0) {
			if(len == 0) {
				goto bail;
			}
			return tls_buf;

		} else if(rc > 0 && rc < chunk_size) {
			return tls_buf;

		} else if(rc == chunk_size) {
			crm_debug("Creating more space: %d += %d: %.60s", len, chunk_size, tls_buf);
			last = len;
			len += chunk_size;
			crm_realloc(tls_buf, len);
			CRM_ASSERT(tls_buf != NULL);
			crm_debug("New size: %d: %.60s", len, tls_buf);
		}

		if(rc < 0
		   && rc != GNUTLS_E_INTERRUPTED
		   && rc != GNUTLS_E_AGAIN) {
			crm_perror(LOG_ERR,"Error receiving message: %d", rc);
			goto bail;
		}
	}
  bail:
	crm_free(tls_buf);
	return NULL;
	
}
#endif

char*
cib_send_plaintext(int sock, xmlNode *msg)
{
	char *xml_text = dump_xml_unformatted(msg);
	if(xml_text != NULL) {
		int rc = 0;
		int len = strlen(xml_text);
		len++; /* null char */
		crm_debug_3("Message on socket %d: size=%d", sock, len);
		rc = write (sock, xml_text, len);
		CRM_CHECK(len == rc,
			  crm_warn("Wrote %d of %d bytes", rc, len));
	}
	crm_free(xml_text);
	return NULL;
	
}

char*
cib_recv_plaintext(int sock)
{
	int last = 0;
	char* buf = NULL;
	int chunk_size = 512;
	int len = chunk_size;

	crm_malloc0(buf, chunk_size);
	
	while(1) {
		int rc = recv(sock, buf+last, chunk_size, 0);
		if (rc == 0) {
			if(len == 0) {
				goto bail;
			}
			return buf;

		} else if(rc > 0 && rc < chunk_size) {
			return buf;

		} else if(rc == chunk_size) {
			last = len;
			len += chunk_size;
			crm_realloc(buf, len);
			CRM_ASSERT(buf != NULL);
		}

		if(rc < 0 && errno != EINTR) {
			crm_perror(LOG_ERR,"Error receiving message: %d", rc);
			goto bail;
		}
	}
  bail:
	crm_free(buf);
	return NULL;
	
}

void
cib_send_remote_msg(void *session, xmlNode *msg, gboolean encrypted)
{
    if(encrypted) {
#ifdef HAVE_GNUTLS_GNUTLS_H
	cib_send_tls(session, msg);
#else
	CRM_ASSERT(encrypted == FALSE);
#endif
    } else {
	sleep(1); /* FIXME: For some reason comms doesn't work without this delay */
	cib_send_plaintext(GPOINTER_TO_INT(session), msg);
    }
}

xmlNode*
cib_recv_remote_msg(void *session, gboolean encrypted)
{
    char *reply = NULL;
    xmlNode *xml = NULL;
    if(encrypted) {
#ifdef HAVE_GNUTLS_GNUTLS_H
	reply = cib_recv_tls(session);
#else
	CRM_ASSERT(encrypted == FALSE);
#endif
    } else {
	reply = cib_recv_plaintext(GPOINTER_TO_INT(session));
    }
    if(reply == NULL || strlen(reply) == 0) {
	crm_err("Empty reply");

    } else {
	xml = string2xml(reply);
	if(xml == NULL) {
	    crm_err("Couldn't parse: '%.120s'", reply);
	}
    }
    
    crm_free(reply);
    return xml;
}

