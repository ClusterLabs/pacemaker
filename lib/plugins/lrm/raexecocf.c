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
#include <libgen.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <glib.h>
#include <clplumbing/cl_log.h>
#include <pils/plugin.h>
#include <dirent.h>
#include <libgen.h>  /* Add it for compiling on OSX */

#include <lrm/raexec.h>

# define PIL_PLUGINTYPE		RA_EXEC_TYPE
# define PIL_PLUGINTYPE_S	"RAExec"
# define PIL_PLUGINLICENSE	LICENSE_PUBDOM
# define PIL_PLUGINLICENSEURL	URL_PUBDOM

#ifndef COMPILE_AS_STONITH
# define PIL_PLUGIN		ocf
# define PIL_PLUGIN_S		"ocf"
/* 
 * Are there multiple paths? Now according to OCF spec, the answer is 'no'.
 * But actually or for future?
 */
static const char * RA_PATH = OCF_RA_DIR;

#else
# define PIL_PLUGIN		stonith
# define PIL_PLUGIN_S		"stonith"
/* 
 * Are there multiple paths? Now according to OCF spec, the answer is 'no'.
 * But actually or for future?
 */
static const char * RA_PATH = STONITH_RA_DIR;

#endif

/* The begin of exported function list */
static int execra(const char * rsc_type,
		  const char * provider,
		  const char * op_type,
	 	  GHashTable * params);
static uniform_ret_execra_t map_ra_retvalue(int ret_execra, const char * op_type);
static int get_resource_list(GList ** rsc_info);
static char* get_resource_meta(const char* rsc_type,  const char* provider);
static int get_provider_list(const char* op_type, GList ** providers);

/* The end of exported function list */

/* The begin of internal used function & data list */
static void add_OCF_prefix( GHashTable * params, GHashTable * new_params);
static void add_prefix_foreach(gpointer key, gpointer value,
				   gpointer user_data);
static gboolean let_remove_eachitem(gpointer key, gpointer value,
				    gpointer user_data);
/* The end of internal function & data list */

/* Rource agent execution plugin operations */
static struct RAExecOps raops =
{	execra,
	map_ra_retvalue,
	get_resource_list,
	get_provider_list,
	get_resource_meta
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
execra( const char * rsc_type, const char * provider, const char * op_type,
	GHashTable * params)
{
	uniform_ret_execra_t exit_value;
	char ra_pathname[RA_MAX_NAME_LENGTH];
	GHashTable * tmp_for_setenv;

	get_ra_pathname(RA_PATH, rsc_type, provider, ra_pathname);

	/* execute the RA */
	cl_log(LOG_DEBUG, "Will execute OCF RA : %s %s", ra_pathname, op_type);
	tmp_for_setenv = g_hash_table_new(g_str_hash, g_str_equal);
	add_OCF_prefix( params, tmp_for_setenv);
	raexec_setenv(tmp_for_setenv);
	g_hash_table_foreach_remove(tmp_for_setenv, let_remove_eachitem, NULL);
	g_hash_table_destroy(tmp_for_setenv);
	execl(ra_pathname, ra_pathname, op_type, NULL);

	switch (errno) {
		case ENOENT:   /* No such file or directory */
		case EISDIR:   /* Is a directory */
			exit_value = EXECRA_NO_RA;
			break;

		default:
			exit_value = EXECRA_EXEC_UNKNOWN_ERROR;
	}

	cl_log(LOG_ERR, "execl error when to execute RA %s.", rsc_type);
	exit(exit_value);
}

static uniform_ret_execra_t
map_ra_retvalue(int ret_execra, const char * op_type)
{
	/* Because the UNIFORM_RET_EXECRA is compatible with OCF standard */
	return ret_execra;
}

static int
get_resource_list(GList ** rsc_info)
{
	return get_ra_list(RA_PATH, rsc_info);
}


static int
get_provider_list(const char* op_type, GList ** providers)
{
	int ret;
	ret = get_providers(RA_PATH, op_type, providers);
	if (0>ret) {
		cl_log(LOG_ERR, "scandir failed in OCF RA plugin");
	}
	return ret;
}

static char*
get_resource_meta(const char* rsc_type, const char* provider)
{
	const int BUFF_LEN=4096;
	int read_len = 0;
	char buff[BUFF_LEN];
	char* data = NULL;
	GString* g_str_tmp = NULL;
	char ra_pathname[RA_MAX_NAME_LENGTH];
	FILE* file = NULL;

	get_ra_pathname(RA_PATH, rsc_type, provider, ra_pathname);

	strncat(ra_pathname, " meta-data",RA_MAX_NAME_LENGTH);

	file = popen(ra_pathname, "r");
	if (NULL==file) {
		return NULL;
	}

	g_str_tmp = g_string_new("");
	while(!feof(file)) {
		memset(buff, 0, BUFF_LEN);
		read_len = fread(buff, 1, BUFF_LEN, file);
		if (0<read_len) {
			g_string_append(g_str_tmp, buff);
		}
		else {
			sleep(1);
		}
	}
	data = (char*)g_new(char, g_str_tmp->len+1);
	data[0] = data[g_str_tmp->len] = 0;
	strncpy(data, g_str_tmp->str, g_str_tmp->len);

	g_string_free(g_str_tmp, TRUE);
	
	pclose(file);
	return data;
	
}

static void 
add_OCF_prefix( GHashTable * env_params, GHashTable * new_env_params)
{
	if (env_params) {
		g_hash_table_foreach(env_params, add_prefix_foreach,
				     new_env_params);
	}
}

static void
add_prefix_foreach(gpointer key, gpointer value, gpointer user_data)
{
	const int MAX_LENGTH_OF_ENV = 50;
	GHashTable * new_hashtable = (GHashTable *) user_data;
	char * newkey;

	newkey = g_new(gchar, strnlen((char*)key, MAX_LENGTH_OF_ENV-1) + 1);
	memset(newkey, '\0', strnlen((char*)key, MAX_LENGTH_OF_ENV-1) + 1); 
	strncat(newkey, "OCF_RESKEY_", 12);
	strncat(newkey, key, strnlen((char*)key, MAX_LENGTH_OF_ENV-12));
	g_hash_table_insert(new_hashtable, (gpointer)newkey, value);
}

static gboolean
let_remove_eachitem(gpointer key, gpointer value, gpointer user_data)
{
	return TRUE;
}
