/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
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
 */
#ifndef CIB_UTIL__H
#define CIB_UTIL__H

/* Utility functions */
extern const char *get_object_path(const char *object_type);
extern const char *get_object_parent(const char *object_type);
extern xmlNode *get_object_root(const char *object_type,xmlNode *the_root);
extern xmlNode *create_cib_fragment_adv(
			xmlNode *update, const char *section, const char *source);
extern char *cib_pluralSection(const char *a_section);
extern const char *get_crm_option(
	xmlNode *cib, const char *name, gboolean do_warn);

/* Error Interpretation*/
extern const char *cib_error2string(enum cib_errors);

extern xmlNode *createEmptyCib(void);
extern gboolean verifyCibXml(xmlNode *cib);
extern int cib_section2enum(const char *a_section);

#define create_cib_fragment(update,cib_section) create_cib_fragment_adv(update, cib_section, __FUNCTION__)

extern gboolean cib_config_changed(xmlNode *old_cib, xmlNode *new_cib, xmlNode **result);

extern xmlNode *diff_cib_object(
	xmlNode *old, xmlNode *new,gboolean suppress);

extern gboolean apply_cib_diff(
	xmlNode *old, xmlNode *diff, xmlNode **new);

extern void log_cib_diff(int log_level, xmlNode *diff, const char *function);

extern gboolean cib_diff_version_details(
	xmlNode *diff, int *admin_epoch, int *epoch, int *updates, 
	int *_admin_epoch, int *_epoch, int *_updates);

extern gboolean cib_version_details(
	xmlNode *cib, int *admin_epoch, int *epoch, int *updates);

extern enum cib_errors update_attr(
	cib_t *the_cib, int call_options,
	const char *section, const char *node_uuid, const char *set_name,
	const char *attr_id, const char *attr_name, const char *attr_value, gboolean to_console);

extern enum cib_errors find_attr_details(
	xmlNode *xml_search, const char *node_uuid,
	const char *set_name, const char *attr_id, const char *attr_name,
	xmlNode **xml_obj, gboolean to_console);

extern enum cib_errors read_attr(
	cib_t *the_cib,
	const char *section, const char *node_uuid, const char *set_name,
	const char *attr_id, const char *attr_name, char **attr_value, gboolean to_console);

extern enum cib_errors delete_attr(
	cib_t *the_cib, int options, 
	const char *section, const char *node_uuid, const char *set_name,
	const char *attr_id, const char *attr_name, const char *attr_value, gboolean to_console);

extern enum cib_errors query_node_uuid(
	cib_t *the_cib, const char *uname, char **uuid);

extern enum cib_errors query_node_uname(
	cib_t *the_cib, const char *uuid, char **uname);

extern enum cib_errors query_standby(cib_t *the_cib, const char *uuid,
				     char **scope, char **standby_value);

extern enum cib_errors set_standby(
	cib_t *the_cib,
	const char *uuid, const char *scope, const char *standby_value);

enum cib_errors delete_standby(
	cib_t *the_cib,
	const char *uuid, const char *scope, const char *standby_value);

extern const char *feature_set(xmlNode *xml_obj);

extern gboolean   startCib(const char *filename);
extern xmlNode *get_cib_copy(cib_t *cib);
extern xmlNode *cib_get_generation(cib_t *cib);
extern int cib_compare_generation(xmlNode *left, xmlNode *right);

#endif
