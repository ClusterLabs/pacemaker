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

	    while(TRUE) {
		rc = gnutls_record_send (*session, unsent, len);
		crm_debug("Sent %d bytes", rc);

		if(rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN) {
		    crm_debug("Retry");

		} else if(rc < 0) {
		    crm_debug("Connection terminated");
		    break;
		    
		} else if(rc < len) {
		    crm_debug("Only sent %d of %d bytes", rc, len);
		    len -= rc;
		    unsent += rc;
		} else {
		    break;
		}
	    }
		
	}
	crm_free(xml_text);
	return NULL;
	
}

static char*
cib_recv_tls(gnutls_session *session)
{
	char* buf = NULL;

	int rc = 0;
	int len = 0;
	int chunk_size = 1024;

	if (session == NULL) {
		return NULL;
	}

	crm_malloc0(buf, chunk_size);
	
	while(TRUE) {
	    errno = 0;
	    rc = gnutls_record_recv(*session, buf+len, chunk_size);
	    crm_debug_2("Got %d more bytes. errno=%d", rc, errno);

	    if(rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN) {
		crm_debug_2("Retry");

	    } else if(rc < 0) {
		crm_perror(LOG_ERR,"Error receiving message: %d", (int)rc);
		goto bail;
		
	    } else if(rc == chunk_size) {
		len += rc;
		chunk_size *= 2;
		crm_realloc(buf, len + chunk_size);
		crm_debug_2("Retry with %d more bytes", (int)chunk_size);
		CRM_ASSERT(buf != NULL);
		
	    } else if(buf[len+rc-1] != 0) {
		crm_debug_2("Last char is %d '%c'", buf[len+rc-1], buf[len+rc-1]);
		crm_debug_2("Retry with %d more bytes", (int)chunk_size);
		len += rc;
		crm_realloc(buf, len + chunk_size);
		CRM_ASSERT(buf != NULL);

	    } else {
		crm_debug_2("Got %d more bytes", (int)rc);
		return buf;
	    }
	}
  bail:
	crm_free(buf);
	return NULL;
	
}
#endif

char*
cib_send_plaintext(int sock, xmlNode *msg)
{
	char *xml_text = dump_xml_unformatted(msg);
	if(xml_text != NULL) {
		int rc = 0;
		char *unsent = xml_text;
		int len = strlen(xml_text);
		len++; /* null char */
		crm_debug_3("Message on socket %d: size=%d", sock, len);
	  retry:
		rc = write (sock, unsent, len);
		if(rc < 0) {
		    switch(errno) {
			case EINTR:
			case EAGAIN:
			    crm_debug_2("Retry");
			    goto retry;
			default:
			    crm_perror(LOG_ERR, "Could only write %d of the remaining %d bytes", rc, len);
			    break;
		    }

		} else if(rc < len) {
		    crm_debug_2("Only sent %d of %d remaining bytes", rc, len);
		    len -= rc;
		    unsent += rc;
		    goto retry;

		} else {
		    crm_debug_2("Sent %d bytes: %.100s", rc, xml_text);
		}
	}
	crm_free(xml_text);
	return NULL;
	
}

char*
cib_recv_plaintext(int sock)
{
	char* buf = NULL;

	ssize_t rc = 0;
	ssize_t len = 0;
	ssize_t chunk_size = 512;

	crm_malloc0(buf, chunk_size);
	
	while(1) {
	    errno = 0;
	    rc = read(sock, buf+len, chunk_size);
	    crm_debug_2("Got %d more bytes. errno=%d", (int)rc, errno);

	    if(errno == EINTR || errno == EAGAIN) {
		crm_debug_2("Retry: %d", (int)rc);
		if(rc > 0) {
		    len += rc;
		    crm_realloc(buf, len + chunk_size);
		    CRM_ASSERT(buf != NULL);
		}

	    } else if(rc < 0) {
		crm_perror(LOG_ERR,"Error receiving message: %d", (int)rc);
		goto bail;

	    } else if(rc == chunk_size) {
		len += rc;
		chunk_size *= 2;
		crm_realloc(buf, len + chunk_size);
		crm_debug_2("Retry with %d more bytes", (int)chunk_size);
		CRM_ASSERT(buf != NULL);

	    } else if(buf[len+rc-1] != 0) {
		crm_debug_2("Last char is %d '%c'", buf[len+rc-1], buf[len+rc-1]);
		crm_debug_2("Retry with %d more bytes", (int)chunk_size);
		len += rc;
		crm_realloc(buf, len + chunk_size);
		CRM_ASSERT(buf != NULL);

	    } else {
		return buf;
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

