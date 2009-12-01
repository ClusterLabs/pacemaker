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

#if HAVE_HB_CONFIG_H
#include <heartbeat/hb_config.h>
#endif

#if HAVE_GLUE_CONFIG_H
#include <glue_config.h>
#endif

#include <clplumbing/cl_log.h>
#include <clplumbing/uids.h>
#include <pils/plugin.h>
#include <dirent.h>
#include <libgen.h>  /* Add it for compiling on OSX */
#include <libxml/entities.h>

#include <lrm/raexec.h>
#include <crm/stonith-ng.h>

# define PIL_PLUGINTYPE		RA_EXEC_TYPE
# define PIL_PLUGINTYPE_S	"RAExec"
# define PIL_PLUGINLICENSE	LICENSE_PUBDOM
# define PIL_PLUGINLICENSEURL	URL_PUBDOM

# define PIL_PLUGIN		stonith
# define PIL_PLUGIN_S		"stonith"

static PIL_rc close_stonithRA(PILInterface*, void* ud_interface);

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

static int
execra(const char *rsc_id, const char *rsc_type, const char *provider,
       const char *op_type, const int timeout, GHashTable *params)
{
    int rc = 0;
    stonith_t *stonith_api = NULL;
    
    if ( 0 == STRNCMP_CONST(op_type, "meta-data")) {
	char *meta = get_resource_meta(rsc_type, provider);
	printf("%s", meta);
	free(meta);
	exit(0);
    }

    stonith_api = stonith_api_new();
    rc = stonith_api->cmds->connect(stonith_api, "lrmd", NULL, NULL);
    if ( 0 == STRNCMP_CONST(op_type, "monitor") ) {
	rc = stonith_api->cmds->call(
	    stonith_api, stonith_sync_call, rsc_id, "monitor", NULL, timeout);
	
    } else if ( 0 == STRNCMP_CONST(op_type, "start") ) {
	const char *agent = rsc_type;
	if(provider == NULL || 0 != STRNCMP_CONST(provider, "redhat")) {
	    agent = "fence_legacy";
	    g_hash_table_replace(params, strdup("plugin"), strdup(rsc_type));
	}
	
	rc = stonith_api->cmds->register_device(
	    stonith_api, stonith_sync_call, rsc_id, provider, agent, params);

    } else if ( 0 == STRNCMP_CONST(op_type, "stop") ) {
	rc = stonith_api->cmds->remove_device(
	    stonith_api, stonith_sync_call, rsc_id);	    
    }

    stonith_api->cmds->disconnect(stonith_api);
    stonith_api_delete(stonith_api);
    
    /* cl_log(LOG_DEBUG, "stonithRA orignal exit code=%d", exit_value); */
    exit(map_ra_retvalue(rc, op_type, NULL));
}

static uniform_ret_execra_t
map_ra_retvalue(int ret_execra, const char * op_type, const char * std_output)
{
    if (ret_execra < 0 ||
	ret_execra > EXECRA_STATUS_UNKNOWN) {
	cl_log(LOG_WARNING, "%s:%d: mapped the invalid return code %d."
	       , __FUNCTION__, __LINE__, ret_execra);
	ret_execra = EXECRA_UNKNOWN_ERROR;
    }
    return ret_execra;
}

static int
get_resource_list(GList ** rsc_info)
{
    int file_num;
    char **entry = NULL;
    char **type_list = NULL;
    struct dirent **namelist;

    if ( rsc_info == NULL ) {
	cl_log(LOG_ERR, "Parameter error: get_resource_list");
	return -2;
    }

    /* Include Heartbeat agents */
    type_list = stonith_types();
    for(entry = type_list; *entry; ++entry) {
	cl_log(LOG_INFO, "Added: %s", *entry);
	*rsc_info = g_list_append(*rsc_info, *entry);
    }

    /* Include Red Hat agents, basically: ls -1 @sbin_dir@/fence_* */
    file_num = scandir(RH_STONITH_DIR, &namelist, 0, alphasort);
    if (file_num > 0) {
	struct stat prop;
	char buffer[FILENAME_MAX+1];

	while (file_num--) {
	    if ('.' == namelist[file_num]->d_name[0]) {
		free(namelist[file_num]);
		continue;

	    } else if(0 != strncmp(RH_STONITH_PREFIX,
				   namelist[file_num]->d_name,
				   strlen(RH_STONITH_PREFIX))) {
		free(namelist[file_num]);
		continue;
	    }
	    
	    snprintf(buffer,FILENAME_MAX,"%s/%s",
		     RH_STONITH_DIR, namelist[file_num]->d_name);
	    stat(buffer, &prop);
	    if (S_ISREG(prop.st_mode)) {
		*rsc_info = g_list_append(*rsc_info, g_strdup(namelist[file_num]->d_name));
	    }

	    free(namelist[file_num]);
	}
	free(namelist);
    }

    return 0;
}

static int
get_provider_list(const char* op_type, GList ** providers)
{
    int rc = 0;
    struct stat prop;
    char buffer[FILENAME_MAX+1];
    
    if(providers == NULL) {
	return -1;

    } else if(op_type == NULL) {
	return -2;
    }

    snprintf(buffer,FILENAME_MAX,"%s/%s", RH_STONITH_DIR, op_type);
    rc = stat(buffer, &prop);
    if (rc >= 0 && S_ISREG(prop.st_mode)) {
	*providers = g_list_append(*providers, g_strdup("redhat"));

    } else {
	*providers = g_list_append(*providers, g_strdup("heartbeat"));
    }
	
    return 1;
}

static char *
get_resource_meta(const char* rsc_type, const char* provider)
{
	int bufferlen = 0;
	char *buffer = NULL;
	const char * meta_param = NULL;
	const char * meta_longdesc = NULL;
	const char * meta_shortdesc = NULL;
	char *xml_meta_longdesc = NULL;
	char *xml_meta_shortdesc = NULL;
	Stonith * stonith_obj = NULL;	
	static const char * no_parameter_info = "<!-- no value -->";

	cl_log(LOG_INFO, "stonithRA plugin: looking up %s/%s metadata.", rsc_type, provider);
	if(provider && 0 == STRNCMP_CONST(provider, "redhat")) {
	    stonith_t *stonith_api = stonith_api_new();
	    stonith_api->cmds->connect(stonith_api, "lrmd", NULL, NULL);
	    stonith_api->cmds->metadata(
		stonith_api, stonith_sync_call, rsc_type, provider, &buffer, 0);
	    stonith_api->cmds->disconnect(stonith_api);
	    stonith_api_delete(stonith_api);
	    cl_log(LOG_INFO, "stonithRA plugin: got metadata: %s", buffer);
	    return buffer;
	}
	
	if( provider != NULL ) {
		cl_log(LOG_DEBUG, "stonithRA plugin: provider attribute "
		       "is not needed and will be ignored.");
	}

	stonith_obj = stonith_new(rsc_type);

	meta_longdesc = stonith_get_info(stonith_obj, ST_DEVICEDESCR);
	if (meta_longdesc == NULL) {
	    cl_log(LOG_WARNING, "stonithRA plugin: no long description in %s's metadata.", rsc_type);
	    meta_longdesc = no_parameter_info;
	}
	xml_meta_longdesc = (char *)xmlEncodeEntitiesReentrant(NULL, (const unsigned char *)meta_longdesc);

	meta_shortdesc = stonith_get_info(stonith_obj, ST_DEVICENAME);
	if (meta_shortdesc == NULL) {
	    cl_log(LOG_WARNING, "stonithRA plugin: no short description in %s's metadata.", rsc_type);
	    meta_shortdesc = no_parameter_info;
	}
	xml_meta_shortdesc = (char *)xmlEncodeEntitiesReentrant(NULL, (const unsigned char *)meta_shortdesc);
	
	meta_param = stonith_get_info(stonith_obj, ST_CONF_XML);
	if (meta_param == NULL) {
	    cl_log(LOG_WARNING, "stonithRA plugin: no list of parameters in %s's metadata.", rsc_type);
	    meta_param = no_parameter_info;
	}
	
	bufferlen = STRLEN_CONST(META_TEMPLATE) + strlen(rsc_type)
			+ strlen(xml_meta_longdesc) + strlen(xml_meta_shortdesc)
			+ strlen(meta_param) + 1;

	buffer = malloc(sizeof(char) * bufferlen);
	memset(buffer, 0, bufferlen);
	snprintf(buffer, bufferlen-1, META_TEMPLATE,
		 rsc_type, xml_meta_longdesc, xml_meta_shortdesc, meta_param);

	stonith_delete(stonith_obj);
	xmlFree(xml_meta_longdesc);
	xmlFree(xml_meta_shortdesc);

	return buffer;
}
