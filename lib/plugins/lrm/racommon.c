#include <portability.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <libgen.h>  /* Add it for compiling on OSX */
#include <glib.h>
#include <sys/stat.h>
#include <clplumbing/cl_log.h>

#include <lrm/racommon.h>

static void set_env(gpointer key, gpointer value, gpointer user_data);

void
get_ra_pathname(const char* class_path, const char* type, const char* provider,
		char pathname[])
{
	char* type_dup;
	char* base_name;
	type_dup = strndup(type, RA_MAX_NAME_LENGTH);
	base_name = basename(type_dup);

	if ( strncmp(type, base_name, RA_MAX_NAME_LENGTH) == 0 ) {
		/*the type does not include path*/
		if (provider) {
			snprintf(pathname, RA_MAX_NAME_LENGTH, "%s%s/%s",
				class_path, provider, type);
		}else{
			snprintf(pathname, RA_MAX_NAME_LENGTH, "%s%s",
				class_path,type);
		}			
	}else{
		/*the type includes path, just copy it to pathname*/
		strncpy(pathname, type, RA_MAX_NAME_LENGTH);
	}

	free(type_dup);
}
	
/*
 *    Description:   Filter a file.
 *    Return Value:
 *		     TRUE:  the file is qualified.
 *		     FALSE: the file is unqualified.
 *    Notes: A qalifed file is a regular file with execute bits.
 */
gboolean
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
int
get_providers(const char* class_path, const char* op_type, GList ** providers)
{
	struct dirent **namelist;
	int file_num;

	if ( providers == NULL ) {
		return -2;
	}

	if ( *providers != NULL ) {
		*providers = NULL;
	}

	file_num = scandir(class_path, &namelist, 0, alphasort);
	if (file_num < 0) {
		return -2;
	}else{
		char tmp_buffer[FILENAME_MAX+1];
		while (file_num--) {
			if (DT_DIR != namelist[file_num]->d_type) {
				free(namelist[file_num]);
				continue;
			}
			if ('.' == namelist[file_num]->d_name[0]) {
				free(namelist[file_num]);
				continue;
			}

			snprintf(tmp_buffer,FILENAME_MAX,"%s%s/%s",
				 class_path, namelist[file_num]->d_name, op_type);

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
int
get_ra_list(const char* class_path, GList ** rsc_info)
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

	file_num = scandir(class_path, &namelist, 0, alphasort);
	if (file_num < 0) {
		cl_log(LOG_ERR, "scandir failed in OCF RA plugin");
		return -2;
	} else{
		while (file_num--) {
			rsc_info_t * rsc_info_tmp = NULL;
			char tmp_buffer[FILENAME_MAX+1];

			tmp_buffer[0] = '\0';
			tmp_buffer[FILENAME_MAX] = '\0';
			strncpy(tmp_buffer, class_path, FILENAME_MAX);
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
int
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

