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

#ifdef HAVE_GNUTLS_GNUTLS_H
#  define DH_BITS 1024
gnutls_dh_params dh_params;
extern gnutls_anon_server_credentials anon_cred_s;
static void debug_log(int level, const char *str)
{
	fputs (str, stderr);
}
extern gnutls_session *create_tls_session(int csock, int type);

#endif

extern int num_clients;
int authenticate_user(const char* user, const char* passwd);
gboolean cib_remote_listen(int ssock, gpointer data);
gboolean cib_remote_msg(int csock, gpointer data);

extern void cib_process_request(
	xmlNode *request, gboolean privileged, gboolean force_synchronous,
	gboolean from_peer, cib_client_t *cib_client);


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
	gnutls_anon_allocate_server_credentials (&anon_cred_s);
	gnutls_anon_set_server_dh_params (anon_cred_s, dh_params);
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
	struct sockaddr_in addr;
#ifdef HAVE_GNUTLS_GNUTLS_H
	gnutls_session *session = NULL;
#endif
	cib_client_t *new_client = NULL;

	xmlNode *login = NULL;
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
	session = create_tls_session(csock, GNUTLS_SERVER);
	if (session == NULL) {
		crm_err("TLS session creation failed");
		close(csock);
		return TRUE;
	}
	
#endif
	do {
		crm_debug_2("Iter: %d", lpc++);
#ifdef HAVE_GNUTLS_GNUTLS_H
		login = cib_recv_remote_msg(session);
#else
		login = cib_recv_remote_msg(GINT_TO_POINTER(csock));
#endif
		sleep(1);
		
	} while(login == NULL && lpc < 10);
	
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
	xmlNode *command = NULL;
	cib_client_t *client = data;
	command = cib_recv_remote_msg(client->channel);
	if(command == NULL) {
	    crm_info("Could not parse command");
	    return FALSE;
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
	
	value = crm_element_value(command, F_CIB_OPERATION);
	if(safe_str_eq(value, T_CIB_NOTIFY) ) {
	    /* Update the notify filters for this client */
	    int on_off = 0;
	    const char *on_off_s = crm_element_value(command, F_CIB_NOTIFY_ACTIVATE);
	    value = crm_element_value(command, F_CIB_NOTIFY_TYPE);
	    on_off = crm_parse_int(on_off_s, "0");
	    
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
 			case PAM_ERROR_MSG:
			    crm_err("PAM error: %s", msg[i]->msg);
			    break;
 			case PAM_TEXT_INFO:
			    crm_info("PAM info: %s", msg[i]->msg);
			    break;
		    default:
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

