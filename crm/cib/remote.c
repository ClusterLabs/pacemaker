#include <lha_internal.h>
#include <crm/crm.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>

#include <libnet.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>

#include <crm/common/ipc.h>
#include <crm/common/xml.h>
#include "callbacks.h"
/* #undef HAVE_PAM_PAM_APPL_H */
/* #undef HAVE_GNUTLS_GNUTLS_H */

#ifdef HAVE_GNUTLS_GNUTLS_H
#  undef KEYFILE
#  include <gnutls/gnutls.h>
#endif

#include <pwd.h>
#include <grp.h>
#if HAVE_SECURITY_PAM_APPL_H
#  include <security/pam_appl.h>
#  define HAVE_PAM 1
#else
#  if HAVE_PAM_PAM_APPL_H
#    include <pam/pam_appl.h>
#    define HAVE_PAM 1
#  endif
#endif

int init_remote_listener(int port);
char *cib_recv_remote_msg(void *session);
void cib_send_remote_msg(void *session, HA_Message *msg);


#ifdef HAVE_GNUTLS_GNUTLS_H
#  define DH_BITS 1024
const int tls_kx_order[] = {
	  GNUTLS_KX_ANON_DH,
	  GNUTLS_KX_DHE_RSA,
	  GNUTLS_KX_DHE_DSS,
	  GNUTLS_KX_RSA,
	0
};
gnutls_dh_params dh_params;
gnutls_anon_server_credentials anon_cred;
char *cib_send_tls(gnutls_session *session, HA_Message *msg);
char *cib_recv_tls(gnutls_session *session);
#endif

extern int num_clients;
int authenticate_user(const char* user, const char* passwd);
gboolean cib_remote_listen(int ssock, gpointer data);
gboolean cib_remote_msg(int csock, gpointer data);
char *cib_send_plaintext(int sock, HA_Message *msg);
char *cib_recv_plaintext(int sock);

extern void cib_process_request(
	HA_Message *request, gboolean privileged, gboolean force_synchronous,
	gboolean from_peer, cib_client_t *cib_client);

#ifdef HAVE_GNUTLS_GNUTLS_H
static void debug_log(int level, const char *str)
{
	fputs (str, stderr);
}

static gnutls_session *
create_tls_session(int csock)
{
	int rc = 0;
	gnutls_session                 *session;
	session = (gnutls_session*)gnutls_malloc(sizeof(gnutls_session));

	gnutls_init(session, GNUTLS_SERVER);
	gnutls_set_default_priority(*session);
 	gnutls_kx_set_priority (*session, tls_kx_order);
	gnutls_credentials_set(*session, GNUTLS_CRD_ANON, anon_cred);
	gnutls_transport_set_ptr(*session,
				 (gnutls_transport_ptr) GINT_TO_POINTER(csock));
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

char*
cib_send_tls(gnutls_session *session, HA_Message *msg)
{
	char *xml_text = NULL;
	ha_msg_mod(msg, F_XML_TAGNAME, "cib_result");
	crm_log_xml(LOG_DEBUG_2, "Result: ", msg);
	xml_text = dump_xml_unformatted(msg);
	if(xml_text != NULL) {
		int len = strlen(xml_text);
		len++; /* null char */
		crm_debug_3("Message size: %d", len);
		gnutls_record_send (*session, xml_text, len);
	}
	crm_free(xml_text);
	return NULL;
	
}

char*
cib_recv_tls(gnutls_session *session)
{
	int len = 0;
	char* buf = NULL;
	int chunk_size = 512;

	if (session == NULL) {
		return NULL;
	}

	crm_malloc0(buf, chunk_size);
	
	while(1) {
		int rc = gnutls_record_recv(*session, buf+len, chunk_size);
		if (rc == 0) {
			if(len == 0) {
				goto bail;
			}
			return buf;

		} else if(rc > 0 && rc < chunk_size) {
			return buf;

		} else if(rc == chunk_size) {
			len += chunk_size;
			crm_realloc(buf, len);
			CRM_ASSERT(buf != NULL);
		}

		if(rc < 0
		   && rc != GNUTLS_E_INTERRUPTED
		   && rc != GNUTLS_E_AGAIN) {
			cl_perror("Error receiving message: %d", rc);
			goto bail;
		}
	}
  bail:
	crm_free(buf);
	return NULL;
	
}
#endif

#define ERROR_SUFFIX "  Shutting down remote listener"
int
init_remote_listener(int port) 
{
	int 			ssock;
	struct sockaddr_in 	saddr;
	int			optval;

	if(port <= 0) {
		/* dont start it */
		return 0;
	}
	
#ifdef HAVE_GNUTLS_GNUTLS_H
	crm_notice("Starting a tls listener on port %d.", port);	
	gnutls_global_init();
/* 	gnutls_global_set_log_level (10); */
	gnutls_global_set_log_function (debug_log);
	gnutls_dh_params_init(&dh_params);
	gnutls_dh_params_generate2(dh_params, DH_BITS);
	gnutls_anon_allocate_server_credentials (&anon_cred);
	gnutls_anon_set_server_dh_params (anon_cred, dh_params);
#else
	crm_warn("Starting a _plain_text_ listener on port %d.", port);	
#endif
#ifndef HAVE_PAM
	crm_warn("PAM is _not_ enabled!");	
#endif
	
	/* create server socket */
	ssock = socket(AF_INET, SOCK_STREAM, 0);
	if (ssock == -1) {
		cl_perror("Can not create server socket."ERROR_SUFFIX);
		return -1;
	}
	
	/* reuse address */
	optval = 1;
	setsockopt(ssock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));	
	
	/* bind server socket*/
	memset(&saddr, '\0', sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(port);
	if (bind(ssock, (struct sockaddr*)&saddr, sizeof(saddr)) == -1) {
		cl_perror("Can not bind server socket."ERROR_SUFFIX);
		return -2;
	}
	if (listen(ssock, 10) == -1) {
		cl_perror("Can not start listen."ERROR_SUFFIX);
		return -3;
	}
	
	G_main_add_fd(G_PRIORITY_HIGH, ssock, FALSE,
		      cib_remote_listen, NULL,
		      default_ipc_connection_destroy);
	
	return 0;
}

static int
check_group_membership(const char* usr, const char* grp)
{
	int index = 0;
	struct group *group = NULL;
	
	CRM_CHECK(usr != NULL, return FALSE);
	CRM_CHECK(grp != NULL, return FALSE);
	
	group = getgrnam(grp);
	if (group == NULL) {
		crm_err("No group named '%s' exists!", grp);
		return FALSE;
	}

	while (TRUE) {
		char* member = group->gr_mem[index++];
		if(member == NULL) {
			break;

		} else if (crm_str_eq(usr, member, TRUE)) {
			return TRUE;
		}
	};

	return FALSE;
}

#define WELCOME "<cib_result cib_op=\"welecome\"/>"

gboolean
cib_remote_listen(int ssock, gpointer data)
{
	int lpc = 0;
	int csock;
	unsigned laddr;
	char *msg = NULL;
	struct sockaddr_in addr;
#ifdef HAVE_GNUTLS_GNUTLS_H
	gnutls_session *session = NULL;
#endif
	cib_client_t *new_client = NULL;

	crm_data_t *login = NULL;
	const char *user = NULL;
	const char *pass = NULL;
	const char *tmp = NULL;

	cl_uuid_t client_id;
	char uuid_str[UU_UNPARSE_SIZEOF];
	
	
	crm_debug("New connection");
	
	/* accept the connection */
	laddr = sizeof(addr);
	csock = accept(ssock, (struct sockaddr*)&addr, &laddr);
	if (csock == -1) {
		crm_err("accept socket failed");
		return TRUE;
	}

#ifdef HAVE_GNUTLS_GNUTLS_H
	/* create gnutls session for the server socket */
	session = create_tls_session(csock);
	if (session == NULL) {
		crm_err("TLS session creation failed");
		close(csock);
		return TRUE;
	}
	
#endif
	do {
		crm_debug_2("Iter: %d", lpc++);
#ifdef HAVE_GNUTLS_GNUTLS_H
		msg = cib_recv_remote_msg(session);
#else
		msg = cib_recv_remote_msg(GINT_TO_POINTER(csock));
#endif
		sleep(1);
		
	} while(msg == NULL && lpc < 10);
	
	/* convert to xml */
	login = string2xml(msg);

	crm_log_xml_info(login, "Login: ");
	if(login == NULL) {
		goto bail;
	}
	
	tmp = crm_element_name(login);
	if(safe_str_neq(tmp, "cib_command")) {
		crm_err("Wrong tag: %s", tmp);
		goto bail;
	}

	tmp = crm_element_value(login, "op");
	if(safe_str_neq(tmp, "authenticate")) {
		crm_err("Wrong operation: %s", tmp);
		goto bail;
	}
	
	user = crm_element_value(login, "user");
	pass = crm_element_value(login, "password");

	if(check_group_membership(user, HA_APIGROUP) == FALSE) {
		crm_err("User is not a member of the required group");
		goto bail;

	} else if (authenticate_user(user, pass) == FALSE) {
		crm_err("PAM auth failed");
		goto bail;
	}

	/* send ACK */
	crm_malloc0(new_client, sizeof(cib_client_t));
	num_clients++;
	new_client->channel_name = "remote";

	cl_uuid_generate(&client_id);
	cl_uuid_unparse(&client_id, uuid_str);

	CRM_CHECK(new_client->id == NULL, crm_free(new_client->id));
	new_client->id = crm_strdup(uuid_str);
	
	new_client->callback_id = NULL;
#ifdef HAVE_GNUTLS_GNUTLS_H
	new_client->channel = (void*)session;
	gnutls_record_send (*session, WELCOME, sizeof (WELCOME));
#else
	new_client->channel = GINT_TO_POINTER(csock);
	write(csock, WELCOME, sizeof (WELCOME));
#endif
	new_client->source = (void*)G_main_add_fd(
		G_PRIORITY_HIGH, csock, FALSE, cib_remote_msg, new_client,
		default_ipc_connection_destroy);

	g_hash_table_insert(client_list, new_client->id, new_client);
	return TRUE;

  bail:
#ifdef HAVE_GNUTLS_GNUTLS_H
	gnutls_bye(*session, GNUTLS_SHUT_RDWR);
	gnutls_deinit(*session);
	gnutls_free(session);
#endif
	close(csock);
	return TRUE;
}

gboolean
cib_remote_msg(int csock, gpointer data)
{
	cl_uuid_t call_id;
	char call_uuid[UU_UNPARSE_SIZEOF];
	const char *value = NULL;
	crm_data_t *command = NULL;
	cib_client_t *client = data;
	char* msg = cib_recv_remote_msg(client->channel);
	if(msg == NULL) {
		return FALSE;
	}

	command = string2xml(msg);
	if(command == NULL) {
		crm_info("Could not parse command: %s", msg);
		goto bail;
	}
	
	crm_log_xml(LOG_MSG+1, "Command: ", command);

	value = crm_element_name(command);
	if(safe_str_neq(value, "cib_command")) {
		goto bail;
	}

	cl_uuid_generate(&call_id);
	cl_uuid_unparse(&call_id, call_uuid);

	crm_xml_add(command, F_TYPE, T_CIB);
	crm_xml_add(command, F_CIB_CLIENTID, client->id);
	crm_xml_add(command, F_CIB_CLIENTNAME, client->name);
	crm_xml_add(command, F_CIB_CALLID, call_uuid);
	if(crm_element_value(command, F_CIB_CALLOPTS) == NULL) {
		crm_xml_add_int(command, F_CIB_CALLOPTS, 0);
	}
	
	crm_log_xml(LOG_MSG, "Fixed Command: ", command);

	/* unset dangerous options */
	xml_remove_prop(command, F_ORIG);
	xml_remove_prop(command, F_CIB_HOST);
	xml_remove_prop(command, F_CIB_GLOBAL_UPDATE);
	
	value = cl_get_string(command, F_CIB_OPERATION);
	if(safe_str_eq(value, T_CIB_NOTIFY) ) {
	    /* Update the notify filters for this client */
	    int on_off = 0;
	    ha_msg_value_int(command, F_CIB_NOTIFY_ACTIVATE, &on_off);
	    value = cl_get_string(command, F_CIB_NOTIFY_TYPE);
	    
	    crm_info("Setting %s callbacks for %s: %s",
		     value, client->name, on_off?"on":"off");
	    
	    if(safe_str_eq(value, T_CIB_POST_NOTIFY)) {
		client->post_notify = on_off;
		
	    } else if(safe_str_eq(value, T_CIB_PRE_NOTIFY)) {
		client->pre_notify = on_off;
		
	    } else if(safe_str_eq(value, T_CIB_UPDATE_CONFIRM)) {
		client->confirmations = on_off;
		
	    } else if(safe_str_eq(value, T_CIB_DIFF_NOTIFY)) {
		client->diffs = on_off;
		
	    } else if(safe_str_eq(value, T_CIB_REPLACE_NOTIFY)) {
		client->replace = on_off;
		
	    }
	    goto bail;
	}
	
 	cib_process_request(command, TRUE, TRUE, FALSE, client);
	
  bail:
	free_xml(command);
	crm_free(msg);
	return TRUE;
}

#ifdef HAVE_PAM
/* 
 * Useful Examples:
 *    http://www.kernel.org/pub/linux/libs/pam/Linux-PAM-html
 *    http://developer.apple.com/samplecode/CryptNoMore/index.html
 */
static int
construct_pam_passwd(int n, const struct pam_message **msg,
		     struct pam_response **resp, void *data)
{
	int i;
	char* passwd = (char*)data;
	struct pam_response *reply = NULL;

	crm_malloc0(reply, n * sizeof(*reply));
	CRM_ASSERT(reply != NULL);

	/* Construct a PAM password message */
	for (i = 0; i < n; ++i) {
		switch (msg[i]->msg_style) {
			case PAM_PROMPT_ECHO_OFF:
			case PAM_PROMPT_ECHO_ON:
				reply[i].resp = passwd;
				break;
			default:
/* 			case PAM_ERROR_MSG: */
/* 			case PAM_TEXT_INFO: */
				crm_err("Unhandled message type: %d",
					msg[i]->msg_style);
				goto bail;
				break;
		}
	}
	*resp = reply;
	return PAM_SUCCESS;
  bail:
	crm_free(reply);
	return PAM_CONV_ERR;
}
#endif

int 
authenticate_user(const char* user, const char* passwd)
{
#ifndef HAVE_PAM
	gboolean pass = TRUE;
#else
	gboolean pass = FALSE;
	int rc = 0;
	struct pam_handle *handle = NULL;
	struct pam_conv passwd_data;
	
	passwd_data.conv = construct_pam_passwd;
	passwd_data.appdata_ptr = strdup(passwd);

	rc = pam_start ("cib", user, &passwd_data, &handle);
	if (rc != PAM_SUCCESS) {
		goto bail;
	}
	
	rc = pam_authenticate (handle, 0);
	if(rc != PAM_SUCCESS) {
		crm_err("pam_authenticate: %s (%d)",
			pam_strerror(handle, rc), rc);
		goto bail;
	}
        rc = pam_acct_mgmt(handle, 0);       /* permitted access? */
	if(rc != PAM_SUCCESS) {
		crm_err("pam_acct: %s (%d)", pam_strerror(handle, rc), rc);
		goto bail;
	}
	pass = TRUE;
	
  bail:
	rc = pam_end (handle, rc);
#endif
	return pass;
}

char*
cib_send_plaintext(int sock, HA_Message *msg)
{
	char *xml_text = NULL;
	ha_msg_mod(msg, F_XML_TAGNAME, "cib_result");
	crm_log_xml(LOG_DEBUG_2, "Result: ", msg);
	xml_text = dump_xml_unformatted(msg);
	if(xml_text != NULL) {
		int rc = 0;
		int len = strlen(xml_text);
		len++; /* null char */
		crm_debug_3("Message size: %d", len);
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
	int len = 0;
	char* buf = NULL;
	int chunk_size = 512;

	crm_malloc0(buf, chunk_size);
	
	while(1) {
		int rc = recv(sock, buf+len, chunk_size, 0);
		if (rc == 0) {
			if(len == 0) {
				goto bail;
			}
			return buf;

		} else if(rc > 0 && rc < chunk_size) {
			return buf;

		} else if(rc == chunk_size) {
			len += chunk_size;
			crm_realloc(buf, len);
			CRM_ASSERT(buf != NULL);
		}

		if(rc < 0 && errno != EINTR) {
			cl_perror("Error receiving message: %d", rc);
			goto bail;
		}
	}
  bail:
	crm_free(buf);
	return NULL;
	
}

void
cib_send_remote_msg(void *session, HA_Message *msg)
{
#ifdef HAVE_GNUTLS_GNUTLS_H
	cib_send_tls(session, msg);
#else
	cib_send_plaintext(GPOINTER_TO_INT(session), msg);
#endif
}

char *
cib_recv_remote_msg(void *session)
{
#ifdef HAVE_GNUTLS_GNUTLS_H
	return cib_recv_tls(session);
#else
	return cib_recv_plaintext(GPOINTER_TO_INT(session));
#endif
}

