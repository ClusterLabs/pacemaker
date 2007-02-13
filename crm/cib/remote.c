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

#include <crm/common/xml.h>

#undef KEYFILE
#include <gnutls/gnutls.h>

#include <pwd.h>
#include <grp.h>
#    include <pam/pam_appl.h>
#if HAVE_SECURITY_PAM_APPL_H
#  include <security/pam_appl.h>
#else
#  if HAVE_PAM_PAM_APPL_H
#    include <pam/pam_appl.h>
#  endif
#endif

#define DH_BITS 1024
gnutls_dh_params dh_params;
gnutls_anon_server_credentials anon_cred;

int init_remote_listener(int port);
char *cib_recv_tls_string(gnutls_session_t *session);
int authenticate_user(const char* user, const char* passwd);
gboolean on_listen(GIOChannel *source, GIOCondition condition, gpointer data);
gboolean on_msg_arrived(GIOChannel *source, GIOCondition condition, gpointer data);

static void debug_log (int level, const char *str)
{
	fputs (str, stderr);
}

int
init_remote_listener(int port) 
{
	int 			ssock;
	struct sockaddr_in 	saddr;
	GIOChannel* 		sch;
	int			optval;

	if(port < 0) {
		/* dont start it */
		return 0;
	}
	
	/* init pam & gnutls lib */
	gnutls_global_init();
/* 	gnutls_global_set_log_level (10); */
	gnutls_global_set_log_function (debug_log);
	gnutls_dh_params_init(&dh_params);
	gnutls_dh_params_generate2(dh_params, DH_BITS);
	gnutls_anon_allocate_server_credentials (&anon_cred);
	gnutls_anon_set_server_dh_params (anon_cred, dh_params);
	
	/* create server socket */
	ssock = socket(AF_INET, SOCK_STREAM, 0);
	if (ssock == -1) {
		crm_err("Can not create server socket.  Shutting down.");
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
		crm_err("Can not bind server socket.  Shutting down.");
		return -2;
	}
	if (listen(ssock, 10) == -1) {
		crm_err("Can not start listen.  Shutting down.");
		return -3;
	}	

	sch = g_io_channel_unix_new(ssock);
	g_io_add_watch(sch, G_IO_IN|G_IO_ERR|G_IO_HUP, on_listen, NULL);
	
	return 0;
}

const int tls_kx_order[] = {
	  GNUTLS_KX_ANON_DH,
	  GNUTLS_KX_DHE_RSA,
	  GNUTLS_KX_DHE_DSS,
	  GNUTLS_KX_RSA,
	0
};

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

#define WELCOME "hello there from gnutls\r\n"
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

gboolean
on_listen(GIOChannel *source, GIOCondition condition, gpointer data)
{
	char *msg = NULL;
	GIOChannel *chan;
	int lpc = 0;
	int ssock, csock;
	unsigned laddr;
	struct sockaddr_in addr;
	gnutls_session *session = NULL;

	crm_data_t *login = NULL;
	const char *user = NULL;
	const char *pass = NULL;
	const char *tmp = NULL;
	
	if ((condition & G_IO_IN) == 0) {
		return TRUE;
	}

	crm_debug("New connection");
	
	/* accept the connection */
	ssock = g_io_channel_unix_get_fd(source);
	laddr = sizeof(addr);
	csock = accept(ssock, (struct sockaddr*)&addr, &laddr);
	if (csock == -1) {
		crm_err("accept socket failed");
		return TRUE;
	}

	/* create gnutls session for the server socket */
	session = create_tls_session(csock);
	if (session == NULL) {
		crm_err("TLS session creation failed");
		close(csock);
		return TRUE;
	}

	crm_err("Sending '%s' size=%d", WELCOME, (int)sizeof (WELCOME));
	gnutls_record_send (*session, WELCOME, sizeof (WELCOME));
	crm_free(msg);
	msg = NULL;
	
	do {
		crm_err("Iter: %d", lpc++);
		msg = cib_recv_tls_string(session);
		sleep(1);
		
	} while(msg == NULL && lpc < 10);
	
	/* convert to xml */
	login = string2xml(msg);
	crm_log_xml_err(login, "Login: ");

	tmp = crm_element_name(login);
	if(safe_str_neq(tmp, "cib_command")) {
		goto bail;
	}

	tmp = crm_element_value(login, "op");
	if(safe_str_neq(tmp, "authenticate")) {
		goto bail;
	}
	
	user = crm_element_value(login, "user");
	pass = crm_element_value(login, "password");

	if(check_group_membership(user, "admin") == FALSE) {
		crm_err("User is not a member of the required group");
		goto bail;

	} else if (authenticate_user(user, pass) == FALSE) {
		crm_err("PAM auth failed");
		goto bail;
	}

	/* send ACK */

/* 	client_t* client = cl_malloc(sizeof(client_t)); */
	chan = g_io_channel_unix_new(csock);
	g_io_channel_set_close_on_unref(chan, TRUE);
	g_io_add_watch(chan, G_IO_IN|G_IO_ERR|G_IO_HUP, on_msg_arrived,
		       session/* userdata */);
/* 	client->ch = chan */
/* 	client->session = session; */
/* 	g_hash_table_insert(clients, (gpointer)&client->id, client); */
	return TRUE;

  bail:
	gnutls_bye(*session, GNUTLS_SHUT_RDWR);
	gnutls_deinit(*session);
	gnutls_free(session);
	close(csock);
	return TRUE;
}

gboolean
on_msg_arrived(GIOChannel *source, GIOCondition condition, gpointer data)
{
	char* msg;
	if ((condition & G_IO_IN) == 0) {
		return TRUE;
	}

	msg = cib_recv_tls_string(data);

	crm_err("Got: %s", msg);
	if(msg == NULL) {
		return FALSE;
	}

	crm_free(msg);
	return TRUE;
}

/* 
 * Useful Examples:
 *    http://www.kernel.org/pub/linux/libs/pam/Linux-PAM-html
 *    http://developer.apple.com/samplecode/CryptNoMore/index.html
 */
static int
construct_pam_passwd(int n, const struct pam_message **msg,
		     struct pam_response **resp, void *data)
{
	struct pam_response *reply;
	int i;
	char* passwd = (char*)data;

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
				crm_err("Unhandled message type: %d", msg[i]->msg_style);
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

int 
authenticate_user(const char* user, const char* passwd)
{
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
		crm_err("pam_authenticate: %s (%d)", pam_strerror(handle, rc), rc);
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
	return pass;
}


char*
cib_recv_tls_string(gnutls_session_t *session)
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
