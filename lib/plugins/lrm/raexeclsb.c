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
 * File: raexeclsb.c
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
#include <errno.h>
#include <dirent.h>
#include <libgen.h>  /* Add it for compiling on OSX */
#include <glib.h>
#include <clplumbing/cl_log.h>
#include <pils/plugin.h>
#include <lrm/raexec.h>
#include <libgen.h>

#define PIL_PLUGINTYPE		RA_EXEC_TYPE
#define PIL_PLUGIN		lsb
#define PIL_PLUGINTYPE_S	"RAExec"
#define PIL_PLUGIN_S		"lsb"
#define PIL_PLUGINLICENSE	LICENSE_PUBDOM
#define PIL_PLUGINLICENSEURL	URL_PUBDOM

/*
 * Are there multiple paths? Now according to LSB init scripts, the answer 
 * is 'no', but should be 'yes' for lsb none-init scripts?
 */
static const char * RA_PATH = "/usr/lib/lsb/";
static const int status_op_exitcode_map[] = { 0, 11, 12, 13, 14 };

/* The begin of exported function list */
static int execra(const char * ra_name,  
		  const char * op,
	 	  GHashTable * cmd_params,
		  GHashTable * env_params);

static uniform_ret_execra_t map_ra_retvalue(int ret_execra, const char * op);
static int get_resource_list(GList ** rsc_info);
/* The end of exported function list */

/* The begin of internal used function & data list */
#define MAX_PARAMETER_NUM 40 
typedef char * RA_ARGV[MAX_PARAMETER_NUM];

static int prepare_cmd_parameters(const char * raname, const char * op, 
	GHashTable * params, RA_ARGV params_argv);  
static void params_hash_to_argv(gpointer key, gpointer value, 
				gpointer user_data);
static int raexec_setenv(GHashTable * env_params);
static void set_env(gpointer key, gpointer value, gpointer user_data);
/* The end of internal function & data list */

/* Rource agent execution plugin operations */
static struct RAExecOps raops =
{	execra,
	map_ra_retvalue,
	get_resource_list
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

	/*  Register our interfaces */
 	return imports->register_interface(us, PIL_PLUGINTYPE_S,  PIL_PLUGIN_S,	
		&raops, raexec_closeintf, &OurInterface, &OurImports,
		interfprivate); 
}

/*
 *	Real work starts here ;-)
 */

static int 
execra( const char * ra_name, const char * op, 
	GHashTable * cmd_params, GHashTable * env_params )
{
	uniform_ret_execra_t exit_value;
	RA_ARGV params_argv;
	char *ra_name_dup, *base_name;
	GString * ra_dirname;

	cl_log(LOG_DEBUG, "To execute a RA %s.", ra_name);
	/* Prepare the call parameter */
	if (0 > prepare_cmd_parameters(ra_name, op, cmd_params, params_argv)) {
		cl_log(LOG_ERR, "lsb RA: Error of preparing parameters");
		return -1;
	}
	
	ra_dirname = g_string_new(ra_name);
	ra_name_dup = strndup(ra_name, RA_MAX_DIRNAME_LENGTH);
	base_name = basename(ra_name_dup);
	/*
	 * If ra_name only contains basename, then append RA_PATH.
	 * If ra_name is a pathname, then don't deal with it.
	 */
	if ( strncmp(ra_name, base_name, RA_MAX_BASENAME_LENGTH) == 0 ) {
		g_string_insert(ra_dirname, 0, RA_PATH);
	}
	free(ra_name_dup);
	
	raexec_setenv(env_params);
	execv(ra_dirname->str, params_argv);

        switch (errno) {
                case ENOENT:   /* No such file or directory */
                case EISDIR:   /* Is a directory */
                        exit_value = EXECRA_NO_RA;
                        break;

                default:
                        exit_value = EXECRA_EXEC_UNKNOWN_ERROR;
        }

        cl_log(LOG_ERR, "execl error when to execute RA %s.", ra_name);
        exit(exit_value);
}

static uniform_ret_execra_t 
map_ra_retvalue(int ret_execra, const char * op)
{
	/* Except op equals 'status', the UNIFORM_RET_EXECRA is compatible 
	   with LSB standard. 
	*/
	if ( strncmp(op, "status", 6) == 0 ) {
		if (ret_execra < 0 || ret_execra > 4 ) {
			ret_execra = 4;
		}
		return status_op_exitcode_map[ret_execra];	
	} else
	{
		return ret_execra;
	}
}

static int 
get_resource_list(GList ** rsc_info)
{
	struct dirent **namelist;
	int file_num;

	if ( rsc_info == NULL ) {
		cl_log(LOG_ERR, "Parameter error: get_resource_list");
		return -2;
	}

	if ( *rsc_info != NULL ) {
		cl_log(LOG_ERR, "Parameter error: get_resource_list."\
			"will cause memory leak.");
		*rsc_info = NULL;
	}
 
	file_num = scandir(RA_PATH, &namelist, 0, alphasort);
	if (file_num < 0) {
		cl_log(LOG_ERR, "scandir failed in OCF RA plugin");
		return -2;
	} else 
	{
		while (file_num--) {
			rsc_info_t * rsc_info_tmp;
			if (*(namelist[file_num]->d_name) != '.') {
				rsc_info_tmp = g_new(rsc_info_t, 1);	
				rsc_info_tmp->rsc_type = 
					g_strdup(namelist[file_num]->d_name);
			/* 
			 * Since the version definition isn't cleat yet,
			 * the version is setted 1.0.
			 */
				rsc_info_tmp->version = g_strdup("1.0");
				*rsc_info = g_list_append(*rsc_info, 
						(gpointer)rsc_info_tmp);
			}
			free(namelist[file_num]);
		}
		free(namelist);
	}
	return g_list_length(*rsc_info);			
}

static int 
prepare_cmd_parameters(const char * raname, const char * op, 
			GHashTable * params_ht, RA_ARGV params_argv)
{
	/* For lsb init scripts, no corresponding definite specification
	 * But for lsb none-init scripts, maybe need it.
	 */ 

	int tmp_len;
	int ht_size = 0;
	if (params_ht) {
		ht_size = g_hash_table_size(params_ht);
	}

	if ( ht_size+3 > MAX_PARAMETER_NUM ) {
		cl_log(LOG_ERR, "Too many parameters");
		return -1;
	}
	
	tmp_len = strnlen(raname, 160) + 1;
	params_argv[0] = g_new(gchar, tmp_len); 
	strncpy(params_argv[0], raname, tmp_len);

	tmp_len = strnlen(op, 160) + 1;
	params_argv[1] = g_new(gchar, tmp_len); 
	strncpy(params_argv[1], op, tmp_len);
	params_argv[ht_size+2] = NULL; 
	
	if (params_ht) {
		g_hash_table_foreach(params_ht, 
				params_hash_to_argv, params_argv);
	}

	return 0;
}

static void
params_hash_to_argv(gpointer key, gpointer value, gpointer user_data)
{
        RA_ARGV * ra_argv  = user_data;
	int param_index;

	if (user_data == NULL) {
		return;
	}
        if (*ra_argv == NULL ) {
                return;
        }

	/* the parameter index start from 1 */
	/* and start from 2 in argv array */
	param_index = atoi((char *)key);
	(*ra_argv)[param_index + 1] = g_new(gchar, 21);
	*((*ra_argv)[param_index + 1] + 20) = '\0';
        strncpy((*ra_argv)[param_index +1], (char*)value,
                strnlen((char*)value, 20));
}

static int 
raexec_setenv(GHashTable * env_params)
{
	/* For lsb init scripts, no corresponding definite specification
	 * But for lsb none-init scripts, maybe need it.
	 */ 
        if (env_params) {
        	g_hash_table_foreach(env_params, set_env, NULL);
        }
        return 0;
}

static void
set_env(gpointer key, gpointer value, gpointer user_data)
{
        setenv((const char *)key, (const char *)value, 1);
        /*Need to free the memory to which key and value point?*/
}
