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
#include <config.h>

#include <lrm/raexec.h>

# define PIL_PLUGINTYPE		RA_EXEC_TYPE
# define PIL_PLUGINTYPE_S	"RAExec"
# define PIL_PLUGINLICENSE	LICENSE_PUBDOM
# define PIL_PLUGINLICENSEURL	URL_PUBDOM

# define PIL_PLUGIN		ocf
# define PIL_PLUGIN_S		"ocf"
/* 
 * Are there multiple paths? Now according to OCF spec, the answer is 'no'.
 * But actually or for future?
 */
static const char * RA_PATH = OCF_RA_DIR;

/* The begin of exported function list */
static int execra(const char * rsc_id,
		  const char * rsc_type,
		  const char * provider,
		  const char * op_type,
		  const int    timeout,
	 	  GHashTable * params);
static uniform_ret_execra_t map_ra_retvalue(int ret_execra, 
	   const char * op_type, const char * std_output);
static int get_resource_list(GList ** rsc_info);
static char* get_resource_meta(const char* rsc_type,  const char* provider);
static int get_provider_list(const char* ra_type, GList ** providers);

/* The end of exported function list */

/* The begin of internal used function & data list */
static void add_OCF_prefix(GHashTable * params, GHashTable * new_params);
static void add_OCF_env_vars(GHashTable * env, const char * rsc_id,
			     const char * rsc_type, const char * provider);
static void add_prefix_foreach(gpointer key, gpointer value,
				   gpointer user_data);

static void hash_to_str(GHashTable * , GString *);
static void hash_to_str_foreach(gpointer key, gpointer value,
				   gpointer user_data);

static int raexec_setenv(GHashTable * env_params);
static void set_env(gpointer key, gpointer value, gpointer user_data);
				   
static gboolean let_remove_eachitem(gpointer key, gpointer value,
				    gpointer user_data);
static int get_providers(const char* class_path, const char* op_type,
			 GList ** providers);
static void merge_string_list(GList** old, GList* new);
static gint compare_str(gconstpointer a, gconstpointer b);

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
 * The function to execute a RA.
 */
static int
execra(const char * rsc_id, const char * rsc_type, const char * provider,
       const char * op_type, const int timeout, GHashTable * params)
{
	uniform_ret_execra_t exit_value;
	char ra_pathname[RA_MAX_NAME_LENGTH];
	GHashTable * tmp_for_setenv;
	GString * params_gstring;

	get_ra_pathname(RA_PATH, rsc_type, provider, ra_pathname);

	/* Setup environment correctly */
	tmp_for_setenv = g_hash_table_new(g_str_hash, g_str_equal);
	add_OCF_prefix(params, tmp_for_setenv);
	add_OCF_env_vars(tmp_for_setenv, rsc_id, rsc_type, provider);
	raexec_setenv(tmp_for_setenv);
	g_hash_table_foreach_remove(tmp_for_setenv, let_remove_eachitem, NULL);
	g_hash_table_destroy(tmp_for_setenv);
	
	/* execute the RA */
	params_gstring = g_string_new("");
	hash_to_str(params, params_gstring);
	cl_log(LOG_DEBUG, "Will execute OCF RA: %s %s . Enironment vars: {%s}", 
		ra_pathname, op_type, params_gstring->str);
	g_string_free(params_gstring, TRUE);

	if ( 0 == strncmp(op_type, "status", strlen("status")) ) {
		execl(ra_pathname, ra_pathname, "monitor", NULL);
	} else {
		execl(ra_pathname, ra_pathname, op_type, NULL);
	}

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
map_ra_retvalue(int ret_execra, const char * op_type, const char * std_output)
{
	/* Because the UNIFORM_RET_EXECRA is compatible with OCF standard,
         * no actual mapping except validating, which ensure the return code
         * will be in the range 0 to 7. Too strict?
         */
        if (ret_execra < 0 || ret_execra > 7) {
                cl_log(LOG_WARNING, "mapped the invalid return code %d."
                        , ret_execra);
                ret_execra = EXECRA_UNKNOWN_ERROR;
        }
	return ret_execra;
}

static gint
compare_str(gconstpointer a, gconstpointer b)
{
	return strncmp(a,b,RA_MAX_NAME_LENGTH);
}

static int
get_resource_list(GList ** rsc_info)
{
	struct dirent **namelist;
	GList* item;
	int file_num;
	char subdir[FILENAME_MAX+1];

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
		return -2;
	}
	while (file_num--) {
		GList* ra_subdir = NULL;
		if ((DT_DIR != namelist[file_num]->d_type) || 
		    ('.' == namelist[file_num]->d_name[0])) {
			free(namelist[file_num]);
			continue;
		}

		snprintf(subdir,FILENAME_MAX,"%s/%s",
			 RA_PATH, namelist[file_num]->d_name);
			 
		get_runnable_list(subdir,&ra_subdir);

		merge_string_list(rsc_info,ra_subdir);

		while (NULL != (item = g_list_first(ra_subdir))) {
			ra_subdir = g_list_remove_link(ra_subdir, item);
			g_free(item->data);
			g_list_free_1(item);
		}

		free(namelist[file_num]);
	}
	free(namelist);
			
	return 0;
}

static void
merge_string_list(GList** old, GList* new)
{
	GList* item = NULL;
	char* newitem;
	for( item=g_list_first(new); NULL!=item; item=g_list_next(item)){
		if (!g_list_find_custom(*old, item->data,compare_str)){
			newitem = g_strndup(item->data,RA_MAX_NAME_LENGTH);
			*old = g_list_append(*old, newitem);
		}
	}
}

static int
get_provider_list(const char* ra_type, GList ** providers)
{
	int ret;
	ret = get_providers(RA_PATH, ra_type, providers);
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
	GHashTable * tmp_for_setenv;

	get_ra_pathname(RA_PATH, rsc_type, provider, ra_pathname);

	strncat(ra_pathname, " meta-data",RA_MAX_NAME_LENGTH);
	tmp_for_setenv = g_hash_table_new(g_str_hash, g_str_equal);
	add_OCF_env_vars(tmp_for_setenv, "DUMMY_INSTANCE", rsc_type, provider);
	raexec_setenv(tmp_for_setenv);
	g_hash_table_foreach_remove(tmp_for_setenv, let_remove_eachitem, NULL);
	g_hash_table_destroy(tmp_for_setenv);

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
	if (0 == g_str_tmp->len) {
		pclose(file);
		return NULL;
	}
	data = (char*)g_new(char, g_str_tmp->len+1);
	data[0] = data[g_str_tmp->len] = 0;
	strncpy(data, g_str_tmp->str, g_str_tmp->len);

	g_string_free(g_str_tmp, TRUE);
	
	pclose(file);
	return data;
}

static void 
add_OCF_prefix(GHashTable * env_params, GHashTable * new_env_params)
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
	int prefix = strlen("OCF_RESKEY_");
	GHashTable * new_hashtable = (GHashTable *) user_data;
	char * newkey;
	int keylen = strnlen((char*)key, MAX_LENGTH_OF_ENV-prefix)+prefix+1;
	
	newkey = g_new(gchar, keylen);
	strncpy(newkey, "OCF_RESKEY_", keylen);
	strncat(newkey, key, keylen);
	g_hash_table_insert(new_hashtable, (gpointer)newkey, g_strdup(value));
}

static void 
hash_to_str(GHashTable * params , GString * str)
{
	if (params) {
		g_hash_table_foreach(params, hash_to_str_foreach, str);
	}
}

static void
hash_to_str_foreach(gpointer key, gpointer value, gpointer user_data)
{
	char buffer_tmp[60];
	GString * str = (GString *)user_data;

	snprintf(buffer_tmp, 60, "%s=%s ", (char *)key, (char *)value);
	str = g_string_append(str, buffer_tmp);
}

static gboolean
let_remove_eachitem(gpointer key, gpointer value, gpointer user_data)
{
	g_free(key);
	g_free(value);
	return TRUE;
}

static int
raexec_setenv(GHashTable * env_params)
{
        if (env_params) {
        	g_hash_table_foreach(env_params, set_env, NULL);
        }
        return 0;
}

static void
set_env(gpointer key, gpointer value, gpointer user_data)
{
       if (setenv(key, value, 1) != 0) {
		cl_log(LOG_ERR, "setenv failed in raexecocf.");
	}
}

static int
get_providers(const char* class_path, const char* ra_type, GList ** providers)
{
	struct dirent **namelist;
	int file_num;

	if ( providers == NULL ) {
		cl_log(LOG_ERR, "Parameter error: get_providers");
		return -2;
	}

	if ( *providers != NULL ) {
		cl_log(LOG_ERR, "Parameter error: get_providers."\
			"will cause memory leak.");
		*providers = NULL;
	}

	file_num = scandir(class_path, &namelist, 0, alphasort);
	if (file_num < 0) {
		return -2;
	}else{
		char tmp_buffer[FILENAME_MAX+1];
		while (file_num--) {
			if ((DT_DIR != namelist[file_num]->d_type) ||
			    ('.' == namelist[file_num]->d_name[0])) {
				free(namelist[file_num]);
				continue;
			}

			snprintf(tmp_buffer,FILENAME_MAX,"%s/%s/%s",
				 class_path, namelist[file_num]->d_name, ra_type);

			if ( filtered(tmp_buffer) == TRUE ) {
				*providers = g_list_append(*providers,
					g_strdup(namelist[file_num]->d_name));
			}
			free(namelist[file_num]);
		}
		free(namelist);
	}
	return g_list_length(*providers);
}

static void
add_OCF_env_vars(GHashTable * env, const char * rsc_id,
	         const char * rsc_type, const char * provider)
{
	if ( env == NULL ) {
		cl_log(LOG_WARNING, "env should not be a NULL pointer.");
		return;
	}
	
	g_hash_table_insert(env, g_strdup("OCF_RA_VERSION_MAJOR"), 
			    g_strdup("1"));
	g_hash_table_insert(env, g_strdup("OCF_RA_VERSION_MINOR"), 
			    g_strdup("0"));
	g_hash_table_insert(env, g_strdup("OCF_ROOT"), 
			    g_strdup(OCF_ROOT_DIR));

	if ( rsc_id != NULL ) {
		g_hash_table_insert(env, g_strdup("OCF_RESOURCE_INSTANCE"),
				    g_strdup(rsc_id));
	}

	/* Currently the rsc_type=="the filename of the RA script/executable",
	 * It seems always correct even in the furture. ;-)
	 */
	if ( rsc_type != NULL ) {
		g_hash_table_insert(env, g_strdup("OCF_RESOURCE_TYPE"), 
				    g_strdup(rsc_type));
	}

	/* Notes: this is not added to specification yet. Sept 10,2004 */
	if ( provider != NULL ) {
		g_hash_table_insert(env, g_strdup("OCF_RESOURCE_PROVIDER"),
			    	    g_strdup(provider));
	}
}

