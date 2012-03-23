/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef CIB_UTIL__H
#  define CIB_UTIL__H

/* Utility functions */
extern const char *get_object_path(const char *object_type);
extern const char *get_object_parent(const char *object_type);
extern xmlNode *get_object_root(const char *object_type, xmlNode * the_root);
extern xmlNode *create_cib_fragment_adv(xmlNode * update, const char *section, const char *source);

/* Error Interpretation*/
extern const char *cib_error2string(enum cib_errors);

extern xmlNode *createEmptyCib(void);
extern gboolean verifyCibXml(xmlNode * cib);
extern int cib_section2enum(const char *a_section);

#  define create_cib_fragment(update,cib_section) create_cib_fragment_adv(update, cib_section, __FUNCTION__)

extern void fix_cib_diff(xmlNode * last, xmlNode * next, xmlNode * local_diff, gboolean changed);

extern xmlNode *diff_cib_object(xmlNode * old, xmlNode * new, gboolean suppress);

extern gboolean apply_cib_diff(xmlNode * old, xmlNode * diff, xmlNode ** new);

extern void log_cib_diff(int log_level, xmlNode * diff, const char *function);

extern gboolean cib_diff_version_details(xmlNode * diff, int *admin_epoch, int *epoch, int *updates,
                                         int *_admin_epoch, int *_epoch, int *_updates);

extern gboolean cib_version_details(xmlNode * cib, int *admin_epoch, int *epoch, int *updates);

extern enum cib_errors update_attr_delegate(cib_t * the_cib, int call_options,
                                            const char *section, const char *node_uuid,
                                            const char *set_type, const char *set_name,
                                            const char *attr_id, const char *attr_name,
                                            const char *attr_value, gboolean to_console,
                                            const char *user_name);

static inline enum cib_errors
update_attr(cib_t * the_cib, int call_options,
            const char *section, const char *node_uuid, const char *set_type, const char *set_name,
            const char *attr_id, const char *attr_name, const char *attr_value, gboolean to_console)
{
    return update_attr_delegate(the_cib, call_options, section, node_uuid, set_type, set_name,
                                attr_id, attr_name, attr_value, to_console, NULL);
}

extern enum cib_errors find_nvpair_attr_delegate(cib_t * the_cib, const char *attr,
                                                 const char *section, const char *node_uuid,
                                                 const char *set_type, const char *set_name,
                                                 const char *attr_id, const char *attr_name,
                                                 gboolean to_console, char **value,
                                                 const char *user_name);

static inline enum cib_errors
find_nvpair_attr(cib_t * the_cib, const char *attr, const char *section, const char *node_uuid,
                 const char *set_type, const char *set_name, const char *attr_id,
                 const char *attr_name, gboolean to_console, char **value)
{
    return find_nvpair_attr_delegate(the_cib, attr, section, node_uuid, set_type,
                                     set_name, attr_id, attr_name, to_console, value, NULL);
}

extern enum cib_errors read_attr_delegate(cib_t * the_cib,
                                          const char *section, const char *node_uuid,
                                          const char *set_type, const char *set_name,
                                          const char *attr_id, const char *attr_name,
                                          char **attr_value, gboolean to_console,
                                          const char *user_name);

static inline enum
    cib_errors
read_attr(cib_t * the_cib,
          const char *section, const char *node_uuid, const char *set_type, const char *set_name,
          const char *attr_id, const char *attr_name, char **attr_value, gboolean to_console)
{
    return read_attr_delegate(the_cib, section, node_uuid, set_type, set_name,
                              attr_id, attr_name, attr_value, to_console, NULL);
}

extern enum cib_errors delete_attr_delegate(cib_t * the_cib, int options,
                                            const char *section, const char *node_uuid,
                                            const char *set_type, const char *set_name,
                                            const char *attr_id, const char *attr_name,
                                            const char *attr_value, gboolean to_console,
                                            const char *user_name);

static inline enum
    cib_errors
delete_attr(cib_t * the_cib, int options,
            const char *section, const char *node_uuid, const char *set_type, const char *set_name,
            const char *attr_id, const char *attr_name, const char *attr_value, gboolean to_console)
{
    return delete_attr_delegate(the_cib, options, section, node_uuid, set_type, set_name,
                                attr_id, attr_name, attr_value, to_console, NULL);
}

extern enum cib_errors query_node_uuid(cib_t * the_cib, const char *uname, char **uuid);

extern enum cib_errors query_node_uname(cib_t * the_cib, const char *uuid, char **uname);

extern enum cib_errors set_standby(cib_t * the_cib,
                                   const char *uuid, const char *scope, const char *standby_value);

extern const char *feature_set(xmlNode * xml_obj);

extern gboolean startCib(const char *filename);
extern xmlNode *get_cib_copy(cib_t * cib);
extern xmlNode *cib_get_generation(cib_t * cib);
extern int cib_compare_generation(xmlNode * left, xmlNode * right);
extern gboolean determine_host(cib_t * cib_conn, char **node_uname, char **node_uuid);

extern void cib_metadata(void);
extern void verify_cib_options(GHashTable * options);
extern const char *cib_pref(GHashTable * options, const char *name);
extern gboolean cib_read_config(GHashTable * options, xmlNode * current_cib);
extern gboolean cib_internal_config_changed(xmlNode * diff);

#endif
