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
 * File: raexechb.c
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
#include <libgen.h>
#include <glib.h>
#include <clplumbing/cl_log.h>
#include <pils/plugin.h>
#include <lrm/raexec.h>

#define PIL_PLUGINTYPE		RA_EXEC_TYPE
#define PIL_PLUGIN		heartbeat
#define PIL_PLUGINTYPE_S	"RAExec"
#define PIL_PLUGIN_S		"heartbeat"
#define PIL_PLUGINLICENSE	LICENSE_PUBDOM
#define PIL_PLUGINLICENSEURL	URL_PUBDOM

static const char * RA_PATH = HB_RA_DIR;

#define meta_data_template  "\n"\
"<?xml version=\"1.0\"?>\n"\
"<!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n"\
"<resource-agent name=%s"\
"\" version=\"0.1\">\n"\
"  <version>1.0</version>\n"\
"  <longdesc lang=\"en\">\n"\
"    %s"\
"  </longdesc>\n"\
"  <shortdesc lang=\"en\">%s</shortdesc>\n"\
"  <parameters>\n"\
"  </parameters>\n"\
"  <actions>\n"\
"    <action name=\"start\"   timeout=\"15\" />\n"\
"    <action name=\"stop\"    timeout=\"15\" />\n"\
"    <action name=\"status\"  timeout=\"15\" />\n"\
"    <action name=\"monitor\" timeout=\"15\" interval=\"15\" start-delay=\"15\" />\n"\
"    <action name=\"meta-data\"  timeout=\"5\" />\n"\
"  </actions>\n"\
"  <special tag=\"heartbeart\">\n"\
"  </special>\n"\
"</resource-agent>\n"

/* The begin of exported function list */
static int execra(const char * rsc_id,
		  const char * rsc_type,
		  const char * provider,
		  const char * op_type,
		  const int    timeout,
	 	  GHashTable * params);

static uniform_ret_execra_t map_ra_retvalue(int ret_execra
	, const char * op_type, const char * std_output);
static int get_resource_list(GList ** rsc_info);
static char* get_resource_meta(const char* rsc_type,  const char* provider);
static int get_provider_list(const char* ra_type, GList ** providers);

/* The end of exported function list */
 
/* The begin of internal used function & data list */
#define HADEBUGVAL      "HA_DEBUG"
#define MAX_PARAMETER_NUM 40
typedef char * RA_ARGV[MAX_PARAMETER_NUM];

const int MAX_LENGTH_OF_RSCNAME = 40,
	  MAX_LENGTH_OF_OPNAME = 40;

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
	RA_ARGV params_argv;
	char ra_pathname[RA_MAX_NAME_LENGTH];
	uniform_ret_execra_t exit_value;
	GString * debug_info;
	char * inherit_debuglevel = NULL;
	char * optype_tmp = NULL;
	int index_tmp = 0;

	/* How to generate the meta-data? There is nearly no value
	 * information in meta-data build up in current way. 
	 * Should directly add meta-data to the script itself?
	 */
	if ( 0 == STRNCMP_CONST(op_type, "meta-data") ) {
		printf("%s", get_resource_meta(rsc_type, provider));
		exit(0);
	}

	/* To simulate the 'monitor' operation with 'status'.
	 * Now suppose there is no 'monitor' operation for heartbeat scripts.
	 */
	if ( 0 == STRNCMP_CONST(op_type, "monitor") ) {
		optype_tmp = g_strdup("status");
	} else {
		optype_tmp = g_strdup(op_type);
	}

	/* Prepare the call parameter */
	if (0 > prepare_cmd_parameters(rsc_type, optype_tmp, params, params_argv)) {
		cl_log(LOG_ERR, "HB RA: Error of preparing parameters");
		g_free(optype_tmp);
		return -1;
	}
	g_free(optype_tmp);

	get_ra_pathname(RA_PATH, rsc_type, NULL, ra_pathname);

	/* let this log show only high loglevel. */
	inherit_debuglevel = getenv(HADEBUGVAL);
	if ((inherit_debuglevel != NULL) && (atoi(inherit_debuglevel) > 1)) {
		debug_info = g_string_new("");
		do {
			g_string_append(debug_info, params_argv[index_tmp]);
			g_string_append(debug_info, " ");
		} while (params_argv[++index_tmp] != NULL);
		debug_info->str[debug_info->len-1] = '\0';

		cl_log(LOG_DEBUG, "RA instance %s executing: heartbeat::%s"
			, rsc_id, debug_info->str);

		g_string_free(debug_info, TRUE);
	} 
	
	execv(ra_pathname, params_argv);
	cl_perror("(%s:%s:%d) execv failed for %s"
		  , __FILE__, __FUNCTION__, __LINE__, ra_pathname);

	switch (errno) {
		case ENOENT:   /* No such file or directory */
		case EISDIR:   /* Is a directory */
			exit_value = EXECRA_NO_RA;
			break;
		default:
			exit_value = EXECRA_EXEC_UNKNOWN_ERROR;
        }
        exit(exit_value);
}

static int 
prepare_cmd_parameters(const char * rsc_type, const char * op_type,
	GHashTable * params_ht, RA_ARGV params_argv)
{
	int tmp_len, index;
	int ht_size = 0;
	int param_num = 0;
	char buf_tmp[20];
	void * value_tmp;

	if (params_ht) {
		ht_size = g_hash_table_size(params_ht);
	}
	if ( ht_size+3 > MAX_PARAMETER_NUM ) {
		cl_log(LOG_ERR, "Too many parameters");
		return -1;
	}
                                                                                        
	/* Now suppose the parameter format stored in Hashtabe is as like as
	 * key="1", value="-Wl,soname=test"
	 * Moreover, the key is supposed as a string transfered from an integer.
	 * It may be changed in the future.
	 */
	/* Notice: if ht_size==0, no actual arguments except op_type */
	for (index = 1; index <= ht_size; index++ ) {
		snprintf(buf_tmp, sizeof(buf_tmp), "%d", index);
		value_tmp = g_hash_table_lookup(params_ht, buf_tmp);
		/* suppose the key is consecutive */
		if ( value_tmp == NULL ) {
/*			cl_log(LOG_WARNING, "Parameter ordering error in"\
				"prepare_cmd_parameters, raexeclsb.c");
			cl_log(LOG_WARNING, "search key=%s.", buf_tmp);
*/			continue;
                }
		param_num ++;
		params_argv[param_num] = g_strdup((char *)value_tmp);
	}

	tmp_len = strnlen(rsc_type, MAX_LENGTH_OF_RSCNAME);
	params_argv[0] = g_strndup(rsc_type, tmp_len);
	/* Add operation code as the last argument */
	tmp_len = strnlen(op_type, MAX_LENGTH_OF_OPNAME);
	params_argv[param_num+1] = g_strndup(op_type, tmp_len);
	/* Add the teminating NULL pointer */
	params_argv[param_num+2] = NULL;
	return 0;
}

static uniform_ret_execra_t 
map_ra_retvalue(int ret_execra, const char * op_type, const char * std_output)
{
	
	/* Now there is no formal related specification for Heartbeat RA 
	 * scripts. Temporarily deal as LSB init script.
	 */
	/* Except op_type equals 'status', the UNIFORM_RET_EXECRA is compatible
	   with LSB standard.
	*/
	const char * stop_pattern1 = "*stopped*",
		   * stop_pattern2 = "*not*running*",
		   * running_pattern1 = "*running*",
		   * running_pattern2 = "*OK*";
	const char * lower_std_output = NULL;
	
	if ( 0 == STRNCMP_CONST(op_type, "status") ) {
		if (std_output == NULL ) {
			cl_log(LOG_WARNING, "The heartbeat RA did output"
			" anything for status output to stdout.");
			return EXECRA_NOT_RUNNING;
		}
	 	lower_std_output = g_ascii_strdown(std_output, -1);

		if ( TRUE == g_pattern_match_simple(stop_pattern1
			, lower_std_output) || TRUE ==
			g_pattern_match_simple(stop_pattern2
			, lower_std_output) ) {
			return EXECRA_NOT_RUNNING; /* stopped */
		}
		if ( TRUE == g_pattern_match_simple(running_pattern1
			, lower_std_output) || TRUE ==
			g_pattern_match_simple(running_pattern2
			, std_output) ) {
			return EXECRA_OK; /* running */
		}
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
	return get_runnable_list(RA_PATH, rsc_info);			
}

static char*
get_resource_meta(const char* rsc_type,  const char* provider)
{
	GString * meta_data;

	meta_data = g_string_new("");
	g_string_sprintf( meta_data, meta_data_template, rsc_type
			, rsc_type, rsc_type);
	return meta_data->str;
}	
static int
get_provider_list(const char* ra_type, GList ** providers)
{
	*providers = NULL;
	return 0;
}
