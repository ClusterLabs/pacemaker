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
#include <sys/stat.h>
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
static const char * RA_PATH = LSB_RA_DIR;
/* Map to the return code of the 'monitor' operation defined in the OCF RA 
 * specification.
 */
static const int status_op_exitcode_map[] = { 
	EXECRA_OK,
	EXECRA_UNKNOWN_ERROR,
	EXECRA_UNKNOWN_ERROR,
	EXECRA_NOT_RUNNING,
	EXECRA_UNKNOWN_ERROR
};

/* The begin of exported function list */
static int execra(const char * rsc_id,
		  const char * rsc_type,
		  const char * provider,
		  const char * op_type,
		  const int    timeout,
	 	  GHashTable * params);

static uniform_ret_execra_t map_ra_retvalue(int ret_execra, const char * op_type);
static char* get_resource_meta(const char* rsc_type, const char* provider);
static int get_resource_list(GList ** rsc_info);
static int get_provider_list(const char* ra_type, GList ** providers);

/* The end of exported function list */

/* The begin of internal used function & data list */
#define MAX_PARAMETER_NUM 40
#define LSB_INITSCRIPT_BEGIN_TAG "### BEGIN INIT INFO"
#define LSB_INITSCRIPT_END_TAG "### END INIT INFO"

const int MAX_LENGTH_OF_RSCNAME = 40,
	  MAX_LENGTH_OF_OPNAME = 40;

typedef char * RA_ARGV[MAX_PARAMETER_NUM];

static int prepare_cmd_parameters(const char * rsc_type, const char * op_type,
	GHashTable * params, RA_ARGV params_argv);
/* The end of internal function & data list */

/* Rource agent execution plugin operations */
static struct RAExecOps raops =
{	execra,
	map_ra_retvalue,
	get_resource_list,
	get_provider_list,
	get_resource_meta
};

PIL_PLUGIN_BOILERPLATE2("1.0", Debug)

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
		&raops, NULL, &OurInterface, &OurImports,
		interfprivate);
}

/*
 *	Real work starts here ;-)
 */

static int
execra( const char * rsc_id, const char * rsc_type, const char * provider,
	const char * op_type, const int timeout, GHashTable * params)
{
	uniform_ret_execra_t exit_value;
	RA_ARGV params_argv;
	char ra_pathname[RA_MAX_NAME_LENGTH];
	char * optype_tmp = NULL;
	GString * debug_info;
	int index_tmp = 0;

	/* To simulate the 'monitor' operation with 'status'.
	 * Now suppose there is no 'monitor' operation for LSB scripts.
	 */
	if (0 == strncmp(op_type, "monitor", strlen("monitor"))) {
		optype_tmp = g_strdup("status");
	} else {
		optype_tmp = g_strdup(op_type);
	}

	/* Prepare the call parameter */
	if ( prepare_cmd_parameters(rsc_type, optype_tmp, params, params_argv)
		 != 0) {
		cl_log(LOG_ERR, "lsb RA: Error of preparing parameters");
		g_free(optype_tmp);
		return -1;
	}
	g_free(optype_tmp);
	get_ra_pathname(RA_PATH, rsc_type, NULL, ra_pathname);

	debug_info = g_string_new("");
	do {
		g_string_append(debug_info, params_argv[index_tmp]);
		g_string_append(debug_info, " ");
	} while (params_argv[++index_tmp] != NULL);

	debug_info->str[debug_info->len-1] = '\0';
	cl_log(LOG_DEBUG, "Will execute a lsb RA: %s", debug_info->str);
	g_string_free(debug_info, TRUE);

	execv(ra_pathname, params_argv);
        cl_log(LOG_ERR, "execv error when to execute a LSB RA %s.", rsc_type);

        switch (errno) {
                case ENOENT:   /* No such file or directory */
			/* Fall down */
                case EISDIR:   /* Is a directory */
                        exit_value = EXECRA_NO_RA;
        		cl_log(LOG_ERR, "Cause: No such file or directory.");
                        break;

                default:
                        exit_value = EXECRA_EXEC_UNKNOWN_ERROR;
        		cl_log(LOG_ERR, "Cause: execv unknow error.");
        }

        exit(exit_value);
}

static uniform_ret_execra_t
map_ra_retvalue(int ret_execra, const char * op_type)
{
	/* Except op_type equals 'status', the UNIFORM_RET_EXECRA is compatible
	   with LSB standard.
	*/
	if ( strncmp(op_type, "status", strlen("status")) == 0 ) {
		if (ret_execra < 0 || ret_execra > 4 ) {
			ret_execra = EXECRA_UNKNOWN_ERROR;
		}
		return status_op_exitcode_map[ret_execra];
	}
	/* For none-status operation return code */
	if ( ret_execra < 0 || ret_execra > 7 ) {
		ret_execra = EXECRA_UNKNOWN_ERROR;
	} 
	return ret_execra;
}

static int
get_resource_list(GList ** rsc_info)
{
	char ra_pathname[RA_MAX_NAME_LENGTH];
	FILE * fp;
	gboolean next_continue, found_begin_tag, is_lsb_script;
	int rc = 0;
	GList  *cur, *tmp;
	const int BUFLEN = 80;
	char buffer[BUFLEN];

	if ((rc = get_runnable_list(RA_PATH, rsc_info))  <= 0) {
		return rc;
	}

	/* Use the following comment line as the filter patterns to choose
	 * the real LSB-compliant scripts.
	 *  "### BEGIN INIT INFO" and "### END INIT INFO"
	 */
	cur = g_list_first(*rsc_info);
	while ( cur != NULL ) {
		get_ra_pathname(RA_PATH, cur->data, NULL, ra_pathname);
		if ( (fp = fopen(ra_pathname, "r")) == NULL ) {
			tmp = g_list_next(cur);
			*rsc_info = g_list_remove(*rsc_info, cur->data);
			g_free(cur->data);
			cur = tmp;
			continue;
		}
		is_lsb_script = FALSE;
		next_continue = FALSE;
		found_begin_tag = FALSE;
		while (NULL != fgets(buffer, BUFLEN, fp)) {
			/* Handle the lines over BUFLEN(80) columns, only
			 * the first part is compared.
			 */
			if ( next_continue == TRUE ) {
				continue;
			}
			if (strlen(buffer) == BUFLEN ) {
				next_continue = TRUE;
			} else {
				next_continue = FALSE;
			}
			/* Shorte the search time */
			if (buffer[0] != '#' && buffer[0] != ' '
				&& buffer[0] != '\n') {
				break; /* donnot find */
			}
	
			if (found_begin_tag == TRUE && 0 == strncmp(buffer
		    		, LSB_INITSCRIPT_END_TAG
				, strlen(LSB_INITSCRIPT_END_TAG)) ) {
				is_lsb_script = TRUE;
				break;
			}
			if (found_begin_tag == FALSE && 0 == strncmp(buffer
				, LSB_INITSCRIPT_BEGIN_TAG
				, strlen(LSB_INITSCRIPT_BEGIN_TAG)) ) {
				found_begin_tag = TRUE;	
			}
		}
		fclose(fp);
		tmp = g_list_next(cur);
		if ( is_lsb_script != TRUE ) {
			*rsc_info = g_list_remove(*rsc_info, cur->data);
			g_free(cur->data);
		}
		cur = tmp;
	}

	return g_list_length(*rsc_info);
}

static int
prepare_cmd_parameters(const char * rsc_type, const char * op_type,
			GHashTable * params_ht, RA_ARGV params_argv)
{
	int tmp_len;
	int ht_size = 0;
#if 0
	/* Reserve it for possible furture use */
	int index;
	void * value_tmp = NULL;
	char buf_tmp[20];
#endif

	if (params_ht) {
		ht_size = g_hash_table_size(params_ht);
	}
	
	/* Need 3 additonal spaces for accomodating: 
	 * argv[0] = RA_file_name(RA_TYPE)
	 * argv[1] = operation
	 * a terminal NULL
	 */
	if ( ht_size+3 > MAX_PARAMETER_NUM ) {
		cl_log(LOG_ERR, "Too many parameters");
		return -1;
	}

	tmp_len = strnlen(rsc_type, MAX_LENGTH_OF_RSCNAME);
	params_argv[0] = g_strndup(rsc_type, tmp_len);
	/* Add operation code as the first argument */
	tmp_len = strnlen(op_type, MAX_LENGTH_OF_OPNAME);
	params_argv[1] = g_strndup(op_type, tmp_len);
	/* Add the teminating NULL pointer */
	params_argv[ht_size+2] = NULL;

	/* No actual arguments except op_type */
	if (ht_size != 0) {
		/* Too strict? maybe */
		cl_log(LOG_ERR, "For LSB init script, no parameter needed.");
		return -1;
	}

/* Actually comment the following code, but I still think it may be used
 * in the future for LSB none-initial scripts, so reserver it.
 */
#if 0
	/* Now suppose the parameter formate stored in Hashtabe is like
	 * key="1", value="-Wl,soname=test"
	 * Moreover, the key is supposed as a string transfered from an integer.
	 * It may be changed in the future.
	 */
	for (index = 1; index <= ht_size; index++ ) {
		snprintf(buf_tmp, sizeof(buf_tmp), "%d", index);
		value_tmp = g_hash_table_lookup(params_ht, buf_tmp);
		/* suppose the key is consecutive */
		if ( value_tmp == NULL ) {
			cl_log(LOG_ERR, "Parameter ordering error in"\
				"prepare_cmd_parameters, raexeclsb.c");
			return -1;
		}
		params_argv[index+1] = g_strdup((char *)value_tmp);
	}
#endif

	return 0;
}

static char*
get_resource_meta(const char* rsc_type,  const char* provider)
{
	return g_strndup(rsc_type, strnlen(rsc_type, MAX_LENGTH_OF_RSCNAME));
}

static int
get_provider_list(const char* ra_type, GList ** providers)
{
	*providers = NULL;
	return 0;
}
