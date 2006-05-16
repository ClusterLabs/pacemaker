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
/*
 * Todo
 * 1) Use flex&bison to make the analysis functions for lsb compliant comment?
 * 2) Support multiple paths which contain lsb compliant RAs.
 * 3) Optional and additional actions analysis?
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


/* meta-data template for lsb scripts */
/* Note: As for optional actions -- extracted from lsb standard.
 * The reload and the try-restart options are optional. Other init script
 * actions may be defined by the init script.
 */
#define meta_data_template  \
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
"    <action name=\"restart\"  timeout=\"15\" />\n"\
"    <action name=\"force-reload\"  timeout=\"15\" />\n"\
"    <action name=\"monitor\" timeout=\"15\" interval=\"15\" start-delay=\"15\" />\n"\
"    <action name=\"meta-data\"  timeout=\"5\" />\n"\
"  </actions>\n"\
"  <special tag=\"LSB\">\n"\
"    <Provides>%s</Provides>\n"\
"    <Required-Start>%s</Required-Start>\n"\
"    <Required-Stop>%s</Required-Stop>\n"\
"    <Should-Start>%s</Should-Start>\n"\
"    <Should-Stop>%s</Should-Stop>\n"\
"    <Default-Start>%s</Default-Start>\n"\
"    <Default-Stop>%s</Default-Stop>\n"\
"  </special>\n"\
"</resource-agent>\n"

/* The keywords for lsb-compliant comment */
#define LSB_INITSCRIPT_BEGIN_TAG "### BEGIN INIT INFO"
#define LSB_INITSCRIPT_END_TAG "### END INIT INFO"
#define PROVIDES    "# Provides:" 
#define REQ_START   "# Required-Start:"
#define REQ_STOP    "# Required-Stop:"
#define SHLD_START  "# Should-Start:"
#define SHLD_STOP   "# Should-Stop:"
#define DFLT_START  "# Default-Start:"
#define DFLT_STOP   "# Default-Stop:"
#define SHORT_DSCR  "# Short-Description:"
#define DESCRIPTION "# Description:"

#define ZAPGDOBJ(m)				\
		if ( (m) != NULL ) {		\
			g_free(m);		\
			(m) = NULL;		\
		}

#define RALSB_GET_VALUE(ptr, keyword)	\
	if ( (ptr == NULL) & (0 == strncasecmp(buffer, keyword, strlen(keyword))) ) { \
		(ptr) = g_strdup(buffer+strlen(keyword)); \
		if (*(ptr+strlen(ptr)-1) == '\n') { \
			*(ptr+strlen(ptr)-1) = ' '; \
		} \
		continue; \
	}
/*
 * Are there multiple paths? Now according to LSB init scripts, the answer 
 * is 'no', but should be 'yes' for lsb none-init scripts?
 */
static const char * RA_PATH = LSB_RA_DIR;
/* Map to the return code of the 'monitor' operation defined in the OCF RA 
 * specification.
 */
static const int status_op_exitcode_map[] = { 
	EXECRA_OK,		/* LSB_STATUS_OK */
	EXECRA_NOT_RUNNING,	/* LSB_STATUS_VAR_PID */
	EXECRA_NOT_RUNNING,	/* LSB_STATUS_VAR_LOCK */
	EXECRA_NOT_RUNNING,	/* LSB_STATUS_STOPPED */
	EXECRA_UNKNOWN_ERROR	/* LSB_STATUS_UNKNOWN */
};

/* The begin of exported function list */
static int execra(const char * rsc_id,
		  const char * rsc_type,
		  const char * provider,
		  const char * op_type,
		  const int    timeout,
	 	  GHashTable * params);

static uniform_ret_execra_t map_ra_retvalue(int ret_execra
	, const char * op_type, const char * std_output);
static char* get_resource_meta(const char* rsc_type, const char* provider);
static int get_resource_list(GList ** rsc_info);
static int get_provider_list(const char* ra_type, GList ** providers);

/* The end of exported function list */

/* The begin of internal used function & data list */
#define HADEBUGVAL      "HA_DEBUG"
#define MAX_PARAMETER_NUM 40

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
	GString * debug_info;
	char * inherit_debuglevel = NULL;
	char * optype_tmp = NULL;
	int index_tmp = 0;

	/* Specially handle the operation "metameta-data". To build up its
	 * output from templet, dummy data and its comment head.
	 */
	if ( 0 == STRNCMP_CONST(op_type, "meta-data")) {
		printf("%s", get_resource_meta(rsc_type, provider));
		exit(0);
	}

	/* To simulate the 'monitor' operation with 'status'.
	 * Now suppose there is no 'monitor' operation for LSB scripts.
	 */
	if (0 == STRNCMP_CONST(op_type, "monitor")) {
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

	/* let this log show only high loglevel. */
	inherit_debuglevel = getenv(HADEBUGVAL);
	if ((inherit_debuglevel != NULL) && (atoi(inherit_debuglevel) > 1)) {
		debug_info = g_string_new("");
		do {
			g_string_append(debug_info, params_argv[index_tmp]);
			g_string_append(debug_info, " ");
		} while (params_argv[++index_tmp] != NULL);
		debug_info->str[debug_info->len-1] = '\0';

		cl_log(LOG_DEBUG, "RA instance %s executing: lsb::%s"
			, rsc_id, debug_info->str);

		g_string_free(debug_info, TRUE);
	} 

	execv(ra_pathname, params_argv);
	cl_perror("(%s:%s:%d) execv failed for %s"
		  , __FILE__, __FUNCTION__, __LINE__, ra_pathname);

        switch (errno) {
                case ENOENT:   /* No such file or directory */
			/* Fall down */
                case EISDIR:   /* Is a directory */
                        exit_value = EXECRA_NO_RA;
                        break;

                default:
                        exit_value = EXECRA_EXEC_UNKNOWN_ERROR;
        }

        exit(exit_value);
}

static uniform_ret_execra_t
map_ra_retvalue(int ret_execra, const char * op_type, const char * std_output)
{
	/* Except op_type equals 'status', the UNIFORM_RET_EXECRA is compatible
	 * with the LSB standard.
	 */
	if (ret_execra < 0) {
		return EXECRA_UNKNOWN_ERROR;
	}
	if (	0 == STRNCMP_CONST(op_type, "status")
	|| 	0 == STRNCMP_CONST(op_type, "monitor")) {
		if (ret_execra < DIMOF(status_op_exitcode_map)) {
			ret_execra =  status_op_exitcode_map[ret_execra];
		}
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
	const size_t BUFLEN = 80;
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
	
			if (found_begin_tag == TRUE && 0 == strncasecmp(buffer
		    		, LSB_INITSCRIPT_END_TAG
				, strlen(LSB_INITSCRIPT_END_TAG)) ) {
				is_lsb_script = TRUE;
				break;
			}
			if (found_begin_tag == FALSE && 0 == strncasecmp(buffer
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

	/* 
	 * No actual arguments needed except op_type.
	 * Add the teminating NULL pointer. 
	 */
	params_argv[2] = NULL;
	if ( (ht_size != 0) && (0 != STRNCMP_CONST(op_type, "status")) ) {
		cl_log(LOG_WARNING, "For LSB init script, no additional "
			"parameters are needed.");
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
	char ra_pathname[RA_MAX_NAME_LENGTH];
	FILE * fp;
	gboolean next_continue;
	GString * meta_data;
	const size_t BUFLEN = 132;
	char buffer[BUFLEN];
	char * provides  = NULL,
	     * req_start = NULL,
	     * req_stop  = NULL,
	     * shld_start = NULL,
	     * shld_stop  = NULL,
	     * dflt_start = NULL,
	     * dflt_stop  = NULL,
	     * s_dscrpt  = NULL;
	 GString * l_dscrpt = NULL;
	
	/* 
	 * Use the following tags to find the LSb-compliant comment block.
	 *  "### BEGIN INIT INFO" and "### END INIT INFO"
	 */
	get_ra_pathname(RA_PATH, rsc_type, NULL, ra_pathname);
	if ( (fp = fopen(ra_pathname, "r")) == NULL ) {
		cl_log(LOG_ERR, "Failed to open lsb RA %s. No meta-data gotten."
			, rsc_type);
		return NULL;
	}
	meta_data = g_string_new("");

	next_continue = FALSE;
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

		if ( 0 == strncasecmp(buffer , LSB_INITSCRIPT_BEGIN_TAG
			, strlen(LSB_INITSCRIPT_BEGIN_TAG)) ) {
			break;
		}
	}

	/* Enter into the lsb-compliant comment block */
	while ( NULL != fgets(buffer, BUFLEN, fp) ) {
		/* Now suppose each of the following eight arguments contain
		 * only one line 
		 */
		RALSB_GET_VALUE(provides,   PROVIDES)
		RALSB_GET_VALUE(req_start,  REQ_START)
		RALSB_GET_VALUE(req_stop,   REQ_STOP)
		RALSB_GET_VALUE(shld_start, SHLD_START)
		RALSB_GET_VALUE(shld_stop,  SHLD_STOP)
		RALSB_GET_VALUE(dflt_start, DFLT_START)
		RALSB_GET_VALUE(dflt_stop,  DFLT_STOP)
		RALSB_GET_VALUE(s_dscrpt,  SHORT_DSCR)
		
		/* Long description may cross multiple lines */
		if ( (l_dscrpt == NULL) & (0 == strncasecmp(buffer, DESCRIPTION
			, strlen(DESCRIPTION))) ) {
			l_dscrpt = g_string_new(buffer+strlen(DESCRIPTION));
			/* Between # and keyword, more than one space, or a tab
			 * character, indicates the continuation line.
			 * 	Extracted from LSB init script standatd
			 */
			while ( NULL != fgets(buffer, BUFLEN, fp) ) {
				if ( (0 == strncmp(buffer, "#  ", 3))
				  || (0 == strncmp(buffer, "#\t", 2)) ) {
					buffer[0] = ' ';
					l_dscrpt = g_string_append(l_dscrpt
								   , buffer);
				} else {
					fputs(buffer, fp);
					break; /* Long description ends */
				}
			}
			continue;
		}

		if ( 0 == strncasecmp(buffer, LSB_INITSCRIPT_END_TAG
			, strlen(LSB_INITSCRIPT_END_TAG)) ) {
			/* Get to the out border of LSB comment block */
			break;
		}
	}
	fclose(fp);
	
	g_string_sprintf( meta_data, meta_data_template, rsc_type
			, (l_dscrpt==NULL)? rsc_type : l_dscrpt->str
			, (s_dscrpt==NULL)? rsc_type : s_dscrpt
			, (provides==NULL)? "" : provides
			, (req_start==NULL)? "" : req_start
			, (req_stop==NULL)? "" : req_stop
			, (shld_start==NULL)? "" : shld_start
			, (shld_stop==NULL)? "" : shld_stop
			, (dflt_start==NULL)? "" : dflt_start
			, (dflt_stop==NULL)? "" : dflt_stop );

	if ( l_dscrpt != NULL) {
		g_string_free(l_dscrpt, TRUE);
		l_dscrpt = NULL;
	}
	ZAPGDOBJ(s_dscrpt);	
	ZAPGDOBJ(provides);	
	ZAPGDOBJ(req_start);	
	ZAPGDOBJ(req_stop);	
	ZAPGDOBJ(shld_start);	
	ZAPGDOBJ(shld_stop);	
	ZAPGDOBJ(dflt_start);	
	ZAPGDOBJ(dflt_stop);	

	return meta_data->str;
}

static int
get_provider_list(const char* ra_type, GList ** providers)
{
	*providers = NULL;
	return 0;
}
