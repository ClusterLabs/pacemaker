/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * File: raexecocf.c
 * Author: Sun Jiang Dong <sunjd@cn.ibm.com>
 * Copyright (c) 2004 International Business Machines
 *
 * This code implements the Resource Agent Plugin Module for LSB style.
 * It's a part of Local Resource Manager. Currently it's used by lrmd only.
 */

#include <portability.h>
#include <stdio.h>		
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <glib.h>
#include <clplumbing/cl_log.h>
#include <pils/plugin.h>
#include <lrm/raexec.h>

#define PIL_PLUGINTYPE		RA_EXEC_TYPE
#define PIL_PLUGIN		ocf
#define PIL_PLUGINTYPE_S	"RAExec"
#define PIL_PLUGIN_S		"ocf"
#define PIL_PLUGINLICENSE	LICENSE_PUBDOM
#define PIL_PLUGINLICENSEURL	URL_PUBDOM


/* The begin of exported function list */
static int execra(const char * ra_name,  
		  const char * op,
	 	  GHashTable * cmd_params,
		  GHashTable * env_params,
		  gboolean need_metadata,
		  int * call_key);

static int post_query_result(int exec_key, int * result, char ** meta_data);
/* The end of exported function list */
 
/* The begin of internal used function & data list */
static int raexec_setenv(GHashTable * env_params);
static int fork_and_execra(const char * ra_name, const char * op, 
			const char * cmd_params, GHashTable * env_params, 
			gboolean need_metadata);
static int read_pipe(int fd, char ** meta_data);
static int * g_intdup(gint value); 
static void set_env(gpointer key, gpointer value, gpointer user_data);

static GHashTable * post_query_ops = NULL;
/* The end of internal function & data list */

/* Rource agent execution plugin operations */
static struct RAExecOps raops =
{	execra,
	post_query_result
};

/*
 * The following two functions are only exported to the plugin infrastructure.
 */

/*
 * raexec_closepi is called as part of shutting down the plugin.
 * If there was any global data allocated, or file descriptors opened, etc.
 * which is associated with the plugin, and not a single interface
 * in particular, here's our chance to clean it up.
 */
static void raexec_closepi(PILPlugin *pi)
{
	if ( post_query_ops != NULL ) { 
		g_hash_table_destroy(post_query_ops);
	}
}

/*
 * raexec_close_intf called as part of shutting down the md5 HBauth interface.
 * If there was any global data allocated, or file descriptors opened, etc.
 * which is associated with the md5 implementation, here's our chance
 * to clean it up.
 */
static PIL_rc raexec_closeintf(PILInterface *pi, void *pd)
{
	return PIL_OK;
}

PIL_PLUGIN_BOILERPLATE("1.0", Debug, raexec_closepi);

static const PILPluginImports*  PluginImports;
static PILPlugin*               OurPlugin;
static PILInterface*		OurInterface;
static void*			OurImports;
static void*			interfprivate;

/*
 * Our plugin initialization and registration function
 * It gets called when the plugin gets loaded.
 */
PIL_rc
PIL_PLUGIN_INIT(PILPlugin * us, const PILPluginImports* imports);

PIL_rc
PIL_PLUGIN_INIT(PILPlugin * us, const PILPluginImports* imports)
{
	/* Force the compiler to do a little type checking */
	(void)(PILPluginInitFun)PIL_PLUGIN_INIT;

	PluginImports = imports;
	OurPlugin = us;

	/* Register ourself as a plugin */
	imports->register_plugin(us, &OurPIExports);  

	post_query_ops = g_hash_table_new(g_int_hash, g_int_equal);

	/*  Register our interfaces */
 	return imports->register_interface(us, PIL_PLUGINTYPE_S,  PIL_PLUGIN_S,	
		&raops, raexec_closeintf, &OurInterface, &OurImports,
		interfprivate); 
}

/*
 *	Real work starts here ;-)
 */

static int 
execra( const char * ra_name, const char * op, GHashTable * cmd_params,
	GHashTable * env_params, gboolean need_metadata, int * call_key)
{
	cl_log(LOG_DEBUG, "To execute a RA %s", ra_name);
	/* Prepare the call parameter */
	if (!cmd_params) {
		cl_log(LOG_ERR, "OCF RA should have no command-line \
			 parameters.");
	}

	/* Fork a child and execute the RA */
	*call_key = fork_and_execra(ra_name, op, NULL,
				env_params, need_metadata);

	if (*call_key <= 0) { 
		return -1;
	}
	else {
		return 0;  /* return ok */
	}
}

static int
post_query_result(int exec_key, int * result, char ** meta_data)
{
	int ret;
	gpointer org_key, org_value;
	gboolean found = FALSE;

	if ( post_query_ops == NULL ) {
		 return -1;
	}

	found = g_hash_table_lookup_extended(post_query_ops, 
			&exec_key, &org_key, &org_value); 		
	if ( !found ) { 
		cl_log(LOG_ERR,"No this child %d need post query.", exec_key);
		return -1;
	}
	ret = waitpid(exec_key, result, WNOHANG);
	if ( ret == 0 ) {
		cl_log(LOG_DEBUG, "process %d don't exit yet.", exec_key);
                /* return at once to avoid remove item in 'post_query_ops' */
		return 0;  
	}

	if ( ret == -1 ) {
		cl_log(LOG_ERR, "error when fetching %d  exit status.",
			exec_key);
	}

	if ((ret > 0) && (*(int*)org_value > 0) && ( meta_data != NULL )) {
		read_pipe(*(int*)org_value, meta_data);
	}

	g_free(org_key);
	g_free(org_value);
	g_hash_table_remove(post_query_ops, &exec_key);
	
	return ret;
}

/* Possible bug for pipe using such as exceeding the buffer length ? */
static int 
fork_and_execra(const char * ra_name, const char * op, const char * cmd_params,
		GHashTable * env_params, gboolean need_metadata)
{
	int cpid;
	int fd[2];	

	cl_log(LOG_DEBUG, "Will to execute RA %s.", ra_name);
	if (need_metadata == TRUE) {
		if ( pipe(fd) < 0 ) {
			cl_log(LOG_ERR,"pipe create error when to execute %s.",
				 ra_name);
			exit(-1);
		}
	}

	if ( (cpid=fork()) < 0 ) {
		cl_log(LOG_ERR, "Fork failed when to execute %s.", ra_name);
		exit(-1);
	} 

	if ( cpid > 0 ) {
		/* In parent process */
		/* close write fd */
		if ( need_metadata == TRUE ) {
			close(fd[1]);
			g_hash_table_insert(post_query_ops, 
				g_intdup(cpid), g_intdup(fd[0]));
		}
		else {
			g_hash_table_insert(post_query_ops, 
				g_intdup(cpid), g_intdup(0));
		}
		return cpid;
	} else {
		/* in child process */
		/* close read fd */
		cl_log(LOG_DEBUG, "In forked child %d.", getpid());

		if ( need_metadata == TRUE ) {
			close(fd[0]);
			if ( fd[1] != STDOUT_FILENO ) {
				if (dup2(fd[1], STDOUT_FILENO)!=STDOUT_FILENO) {
					cl_log(LOG_ERR,"dup2 error when to "\
						"execute RA.");
					exit(-1);
				}
			}
			close(fd[1]);
		}

		raexec_setenv(env_params);
		if ( execl(ra_name, ra_name, op, NULL) < 0 ) {
			cl_log(LOG_ERR, "execl error when to execute RA %s.", 
				ra_name);
		}
		exit(-1);
     	} 
}

static int
read_pipe(int fd, char ** meta_data)
{
	const int BUFFLEN = 81;
	char buffer[BUFFLEN];
	int readlen;
	GString * gstr_tmp;

	*meta_data = NULL;
	gstr_tmp = g_string_new("");
	do {
		memset(buffer, 0, BUFFLEN);
		readlen = read(fd, buffer, BUFFLEN - 1);
		if ( readlen > 0 ) {
			g_string_append(gstr_tmp, buffer);
		}
	} while (readlen == BUFFLEN - 1); 
	close(fd);

	if (readlen < 0) {
		cl_log(LOG_ERR, "read pipe error when execute RA."); 
		return -1;
	}
	if ( gstr_tmp->len == 0 ) {
		cl_log(LOG_INFO, "read 0 byte from this pipe when execute RA."); 
		return 0;
	}

	*meta_data = malloc(gstr_tmp->len + 1);
	if ( *meta_data == NULL ) {
		cl_log(LOG_ERR, "malloc error in read_pipe.");
		return -1;
	} 

	(*meta_data)[0] = '\0'; 
	(*meta_data)[gstr_tmp->len] = '\0'; 
	strncpy(*meta_data, gstr_tmp->str, gstr_tmp->len);
	g_string_free(gstr_tmp, TRUE);	
	return 0;
}

static int 
raexec_setenv(GHashTable * env_params)
{
	if (!env_params) {
		return -1;
	}

	g_hash_table_foreach(env_params, set_env, NULL);
	/* Need to free the env_params ? */
	return 0;
}

static int * 
g_intdup(gint value)
{
	gint * tmp;
	tmp = g_new(gint,1);
	*tmp = value;
	return tmp;
}

static void 
set_env(gpointer key, gpointer value, gpointer user_data)
{
	setenv((const char *)key, (const char *)value, 1);	
	/*Need to free the memory to which key and value point?*/
}
