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
#include <dirent.h>
#include <libgen.h>  /* Add it for compiling on OSX */
#include <glib.h>
#include <clplumbing/cl_log.h>
#include <pils/plugin.h>
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
		  const char * op_type,
	 	  GHashTable * cmd_params,
		  GHashTable * env_params);

static uniform_ret_execra_t map_ra_retvalue(int ret_execra, const char * op_type);

static int get_resource_list(GList ** rsc_info);

static char* get_resource_meta(const char* rsc_type);

/* The end of exported function list */

/* The begin of internal used function & data list */
static int raexec_setenv(GHashTable * env_params);
static void set_env(gpointer key, gpointer value, gpointer user_data);
static gboolean filtered(char * file_name);
/* The end of internal function & data list */

/* Rource agent execution plugin operations */
static struct RAExecOps raops =
{	execra,
	map_ra_retvalue,
	get_resource_list,
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
execra( const char * rsc_type, const char * op_type,
	GHashTable * cmd_params, GHashTable * env_params )
{
	char *ra_name_dup, *base_name;
	GString * ra_dirname;

	uniform_ret_execra_t exit_value;

	cl_log(LOG_DEBUG, "To execute a RA %s", rsc_type);
	/* Prepare the call parameter */
	if (!cmd_params) {
		if (g_hash_table_size(cmd_params) > 0) {
			cl_log(LOG_ERR, "OCF RA should have no "\
				"command-line parameters.");
		}
	}

	ra_dirname = g_string_new(rsc_type);
	ra_name_dup = strndup(rsc_type, RA_MAX_DIRNAME_LENGTH);
	base_name = basename(ra_name_dup);
	/*
	 * If rsc_type only contains basename, then append RA_PATH.
	 * If rsc_type is a pathname, then don't deal with it.
	 */
	if ( strncmp(rsc_type, base_name, RA_MAX_BASENAME_LENGTH) == 0 ) {
		g_string_insert(ra_dirname, 0, RA_PATH);
	}
	free(ra_name_dup);

	/* execute the RA */
	cl_log(LOG_INFO, "Will execute OCF RA : %s %s", ra_dirname->str, op_type);
	cl_log(LOG_INFO, "Its environment parameters is as below.");
	raexec_setenv(env_params);
	execl(ra_dirname->str, ra_dirname->str, op_type, NULL);

	switch (errno) {
		case ENOENT:   /* No such file or directory */
		case EISDIR:   /* Is a directory */
			exit_value = EXECRA_NO_RA;
			break;

		default:
			exit_value = EXECRA_EXEC_UNKNOWN_ERROR;
	}

	cl_log(LOG_ERR, "execl error when to execute RA %s.", rsc_type);
	g_string_free(ra_dirname, TRUE);
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
			char tmp_buffer[FILENAME_MAX+1];

			tmp_buffer[0] = '\0';
			tmp_buffer[FILENAME_MAX] = '\0';
			strncpy(tmp_buffer, RA_PATH, FILENAME_MAX);
			strncat(tmp_buffer, namelist[file_num]->d_name, FILENAME_MAX);
			if ( filtered(tmp_buffer) == TRUE ) {
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
raexec_setenv(GHashTable * env_params)
{
	if (!env_params) {
		return -1;
	}

	g_hash_table_foreach(env_params, set_env, NULL);
	/* Need to free the env_params ? */
	return 0;
}

static void
set_env(gpointer key, gpointer value, gpointer user_data)
{
	cl_log(LOG_INFO, "%s = %s.", (char *)key, (char *)value);
	setenv((const char *)key, (const char *)value, 1);
	/*Need to free the memory to which key and value point?*/
}
static char*
get_resource_meta(const char* rsc_type)
{
	const int BUFF_LEN=4096;
	int read_len = 0;
	char buff[BUFF_LEN];
	char* data = NULL;
	GString* g_str_tmp = NULL;
	char *ra_type_dup, *base_name;
	GString * ra_dirname;
	FILE* file = NULL;

	ra_dirname = g_string_new(rsc_type);
	ra_type_dup = strndup(rsc_type, RA_MAX_DIRNAME_LENGTH);
	base_name = basename(ra_type_dup);

	if ( strncmp(rsc_type, base_name, RA_MAX_BASENAME_LENGTH) == 0 ) {
		g_string_insert(ra_dirname, 0, RA_PATH);
	}
	free(ra_type_dup);
	g_string_append(ra_dirname, " meta-data");

	file = popen(ra_dirname->str, "r");
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
	g_string_free(ra_dirname, TRUE);
	
	pclose(file);
	return data;
	
}

/* 
 *    Description:   Filter a file. 
 *    Return Value:   
 *		     TRUE:  the file is qualified.
 *		     FALSE: the file is unqualified.
 *    Notes: A qalifed file is a regular file with execute bits.
 */
static gboolean 
filtered(char * file_name)
{
	struct stat buf;

	if ( stat(file_name, &buf) != 0 ) {
		return FALSE;
	}

	if (   S_ISREG(buf.st_mode) 
            && (   ( buf.st_mode & S_IXUSR ) || ( buf.st_mode & S_IXGRP ) 
		|| ( buf.st_mode & S_IXOTH ) ) ) {
		return TRUE;
	}
	return FALSE;
}
