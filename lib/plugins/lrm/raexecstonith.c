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

#include <crm_internal.h>
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
#include <clplumbing/uids.h>
#include <pils/plugin.h>
#include <dirent.h>
#include <libgen.h>  /* Add it for compiling on OSX */
#include <libxml/entities.h>

#include <lrm/raexec.h>
#include <fencing/stonithd_api.h>
#include <stonith/stonith.h>

# define PIL_PLUGINTYPE		RA_EXEC_TYPE
# define PIL_PLUGINTYPE_S	"RAExec"
# define PIL_PLUGINLICENSE	LICENSE_PUBDOM
# define PIL_PLUGINLICENSEURL	URL_PUBDOM

# define PIL_PLUGIN		stonith
# define PIL_PLUGIN_S		"stonith"

static PIL_rc close_stonithRA(PILInterface*, void* ud_interface);

/* static const char * RA_PATH = STONITH_RA_DIR; */
/* Temporarily use it */
static const char * RA_PATH = HA_LIBHBDIR "/stonith/plugins/stonith/";

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
static int get_provider_list(const char* op_type, GList ** providers);

/* The end of exported function list */

/* The begin of internal used function & data list */
static int get_providers(const char* class_path, const char* op_type,
			 GList ** providers);
static void stonithRA_ops_callback(stonithRA_ops_t * op, void * private_data);
static int exit_value;
/* The end of internal function & data list */

/* Rource agent execution plugin operations */
static struct RAExecOps raops =
{	execra,
	map_ra_retvalue,
	get_resource_list,
	get_provider_list,
	get_resource_meta
};

static const char META_TEMPLATE[] =
"<?xml version=\"1.0\"?>\n"
"<!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n"
"<resource-agent name=\"%s\">\n"
"<version>1.0</version>\n"
"<longdesc lang=\"en\">\n"
"%s\n"
"</longdesc>\n"	
"<shortdesc lang=\"en\">%s</shortdesc>\n"
"%s\n"
"<actions>\n"
"<action name=\"start\"   timeout=\"15\" />\n"
"<action name=\"stop\"    timeout=\"15\" />\n"
"<action name=\"status\"  timeout=\"15\" />\n"
"<action name=\"monitor\" timeout=\"15\" interval=\"15\" start-delay=\"15\" />\n"
"<action name=\"meta-data\"  timeout=\"15\" />\n"
"</actions>\n"
"<special tag=\"heartbeat\">\n"
"<version>2.0</version>\n"
"</special>\n"
"</resource-agent>\n";

static const char * no_parameter_info = "<!-- No parameter segment -->";

#define CHECKMETANULL(ret, which) \
	if (ret == NULL) { \
		cl_log(LOG_WARNING, "stonithRA plugin: cannot get %s " \
			"segment of %s's metadata.", which, rsc_type); \
		ret = no_parameter_info; \
	}
#define xmlize(p) \
	( p ? (char *)xmlEncodeEntitiesReentrant(NULL, \
				(const unsigned char *)p) \
	 	: NULL )
#define zapxml(p) do { \
	if( p ) { \
		xmlFree(p); \
	} \
} while(0)

PIL_PLUGIN_BOILERPLATE2("1.0", Debug);

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
		&raops, close_stonithRA, &OurInterface, &OurImports,
		interfprivate);
}

static PIL_rc
close_stonithRA(PILInterface* pif, void* ud_interface)
{
	return PIL_OK;
}

/*
 * Most of the oprations will be sent to sotnithd directly, such as 'start',
 * 'stop', 'monitor'. And others like 'meta-data' will be handled by itself
 * locally.
 * Some of important parameters' name:
 * config_file
 * config_string
 */
static int
execra(const char * rsc_id, const char * rsc_type, const char * provider,
       const char * op_type,const int timeout, GHashTable * params)
{
	stonithRA_ops_t * op;
	int call_id = -1;
	char buffer_tmp[32];

	/* Handling "meta-data" operation in a special way.
	 * Now handle "meta-data" operation locally. 
	 * Should be changed in the future?
	 */
	if ( 0 == STRNCMP_CONST(op_type, "meta-data")) {
		char * tmp;
		tmp = get_resource_meta(rsc_type, provider);
		printf("%s", tmp);
		g_free(tmp);
		exit(0);
	}

	g_snprintf(buffer_tmp, sizeof(buffer_tmp), "%s_%d"
		, 	"STONITH_RA_EXEC", getpid());
	if (ST_OK != stonithd_signon(buffer_tmp)) {
		cl_log(LOG_ERR, "%s:%d: Cannot sign on the stonithd."
			, __FUNCTION__, __LINE__);
		exit(EXECRA_UNKNOWN_ERROR);
	}

	stonithd_set_stonithRA_ops_callback(stonithRA_ops_callback, &call_id);

	/* Temporarily donnot use it, but how to deal with the global OCF 
	 * variables. This is a important thing to think about and do.
	 */
	/* send the RA operation to stonithd to simulate a RA's actions */
	if ( 0==STRNCMP_CONST(op_type, "start") 
		|| 0==STRNCMP_CONST(op_type, "stop") ) {
		cl_log(LOG_INFO
			, "Try to %s STONITH resource <rsc_id=%s> : Device=%s"
			, op_type, rsc_id, rsc_type);
	}

	op = g_new(stonithRA_ops_t, 1);
	op->ra_name = g_strdup(rsc_type);
	op->op_type = g_strdup(op_type);
	op->params = params;
	op->rsc_id = g_strdup(rsc_id);
	if (ST_OK != stonithd_virtual_stonithRA_ops(op, &call_id)) {
		cl_log(LOG_ERR, "sending stonithRA op to stonithd failed.");
		/* Need to improve the granularity for error return code */
		stonithd_signoff();
		exit(EXECRA_EXEC_UNKNOWN_ERROR);
	}

	/* May be redundant */
	/*
	while (stonithd_op_result_ready() != TRUE) {
		;
	}
	*/
	/* cl_log(LOG_DEBUG, "Will call stonithd_receive_ops_result."); */
	if (ST_OK != stonithd_receive_ops_result(TRUE)) {
		cl_log(LOG_ERR, "stonithd_receive_ops_result failed.");
		/* Need to improve the granularity for error return code */
		stonithd_signoff();
		exit(EXECRA_EXEC_UNKNOWN_ERROR);
	}

	/* exit_value will be setted by the callback function */
	g_free(op->ra_name);
	g_free(op->op_type);
	g_free(op->rsc_id);
	g_free(op);

	stonithd_signoff();
	/* cl_log(LOG_DEBUG, "stonithRA orignal exit code=%d", exit_value); */
	exit(map_ra_retvalue(exit_value, op_type, NULL));
}

static void
stonithRA_ops_callback(stonithRA_ops_t * op, void * private_data)
{
	/* cl_log(LOG_DEBUG, "setting exit code=%d", exit_value); */
	exit_value = op->op_result;
}

static uniform_ret_execra_t
map_ra_retvalue(int ret_execra, const char * op_type, const char * std_output)
{
	/* Because the UNIFORM_RET_EXECRA is compatible with OCF standard, no
	 * actual mapping except validating, which ensure the return code
	 * will be in the range 0 to 7. Too strict?
	 */
	if (ret_execra < 0 ||
		ret_execra > EXECRA_STATUS_UNKNOWN) {
		cl_log(LOG_WARNING, "mapped the invalid return code %d."
			, ret_execra);
		ret_execra = EXECRA_UNKNOWN_ERROR;
	}
	return ret_execra;
}

static int
get_resource_list(GList ** rsc_info)
{
	int rc;
	int     needprivs = !cl_have_full_privs();

	if ( rsc_info == NULL ) {
		cl_log(LOG_ERR, "Parameter error: get_resource_list");
		return -2;
	}

	if ( *rsc_info != NULL ) {
		cl_log(LOG_ERR, "Parameter error: get_resource_list."\
			"will cause memory leak.");
		*rsc_info = NULL;
	}

	if (needprivs) {
		return_to_orig_privs();
	}
	if (ST_OK != stonithd_signon("STONITH_RA")) {
		cl_log(LOG_ERR, "%s:%d: Can not signon to the stonithd."
			, __FUNCTION__, __LINE__);
		rc = -1;
	} else {
		rc = stonithd_list_stonith_types(rsc_info);
		stonithd_signoff();
	}

	if (needprivs) {
		return_to_dropped_privs();
	}
	return rc;
}

static int
get_provider_list(const char* op_type, GList ** providers)
{
	int ret;
	ret = get_providers(RA_PATH, op_type, providers);
	if (0>ret) {
		cl_log(LOG_ERR, "scandir failed in stonith RA plugin");
	}
	return ret;
}

static char *
get_resource_meta(const char* rsc_type, const char* provider)
{
	char * buffer;
	int bufferlen = 0;
	const char * meta_param = NULL;
	const char * meta_longdesc = NULL;
	const char * meta_shortdesc = NULL;
	char *xml_meta_longdesc = NULL;
	char *xml_meta_shortdesc = NULL;
	Stonith * stonith_obj = NULL;	

	if ( provider != NULL ) {
		cl_log(LOG_DEBUG, "stonithRA plugin: provider attribute "
			"is not needed and will be ignored.");
	}

	stonith_obj = stonith_new(rsc_type);
	meta_longdesc = stonith_get_info(stonith_obj, ST_DEVICEDESCR);
	CHECKMETANULL(meta_longdesc, "longdesc")
	xml_meta_longdesc = xmlize(meta_longdesc);
	meta_shortdesc = stonith_get_info(stonith_obj, ST_DEVICENAME);
	CHECKMETANULL(meta_shortdesc, "shortdesc") 
	xml_meta_shortdesc = xmlize(meta_shortdesc);
	meta_param = stonith_get_info(stonith_obj, ST_CONF_XML);
	CHECKMETANULL(meta_param, "parameters") 

	
	bufferlen = STRLEN_CONST(META_TEMPLATE) + strlen(rsc_type)
			+ strlen(xml_meta_longdesc) + strlen(xml_meta_shortdesc)
			+ strlen(meta_param) + 1;
	buffer = g_new(char, bufferlen);
	buffer[bufferlen-1] = '\0';
	snprintf(buffer, bufferlen-1, META_TEMPLATE, rsc_type
		, xml_meta_longdesc, xml_meta_shortdesc, meta_param);
	stonith_delete(stonith_obj);
	zapxml(xml_meta_longdesc);
	zapxml(xml_meta_shortdesc);

	return buffer;
}

/* 
 * Currently should return *providers = NULL, but remain the old code for
 * possible unsing in the future
 */
static int
get_providers(const char* class_path, const char* op_type, GList ** providers)
{
	if ( providers == NULL ) {
		cl_log(LOG_ERR, "%s:%d: Parameter error: providers==NULL"
			, __FUNCTION__, __LINE__);
		return -2;
	}

	if ( *providers != NULL ) {
		cl_log(LOG_ERR, "%s:%d: Parameter error: *providers==NULL."
			"This will cause memory leak."
			, __FUNCTION__, __LINE__);
	}

	/* Now temporarily make it fixed */
	*providers = g_list_append(*providers, g_strdup("heartbeat"));

	return g_list_length(*providers);
}
