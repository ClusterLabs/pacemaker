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
const char *get_object_path(const char *object_type);
const char *get_object_parent(const char *object_type);
xmlNode *get_object_root(const char *object_type, xmlNode * the_root);
xmlNode *create_cib_fragment_adv(xmlNode * update, const char *section, const char *source);

/* Error Interpretation*/
const char *cib_error2string(int);

xmlNode *createEmptyCib(void);
gboolean verifyCibXml(xmlNode * cib);
int cib_section2enum(const char *a_section);

#  define create_cib_fragment(update,cib_section) create_cib_fragment_adv(update, cib_section, __FUNCTION__)

void fix_cib_diff(xmlNode * last, xmlNode * next, xmlNode * local_diff, gboolean changed);

xmlNode *diff_cib_object(xmlNode * old, xmlNode * new, gboolean suppress);

gboolean apply_cib_diff(xmlNode * old, xmlNode * diff, xmlNode ** new);

void log_cib_diff(int log_level, xmlNode * diff, const char *function);

gboolean cib_diff_version_details(xmlNode * diff, int *admin_epoch, int *epoch, int *updates,
                                         int *_admin_epoch, int *_epoch, int *_updates);

gboolean cib_version_details(xmlNode * cib, int *admin_epoch, int *epoch, int *updates);

int update_attr_delegate(cib_t * the_cib, int call_options,
                                            const char *section, const char *node_uuid,
                                            const char *set_type, const char *set_name,
                                            const char *attr_id, const char *attr_name,
                                            const char *attr_value, gboolean to_console,
                                            const char *user_name);

static inline int
update_attr(cib_t * the_cib, int call_options,
            const char *section, const char *node_uuid, const char *set_type, const char *set_name,
            const char *attr_id, const char *attr_name, const char *attr_value, gboolean to_console)
{
    return update_attr_delegate(the_cib, call_options, section, node_uuid, set_type, set_name,
                                attr_id, attr_name, attr_value, to_console, NULL);
}

int find_nvpair_attr_delegate(cib_t * the_cib, const char *attr,
                                                 const char *section, const char *node_uuid,
                                                 const char *set_type, const char *set_name,
                                                 const char *attr_id, const char *attr_name,
                                                 gboolean to_console, char **value,
                                                 const char *user_name);

static inline int
find_nvpair_attr(cib_t * the_cib, const char *attr, const char *section, const char *node_uuid,
                 const char *set_type, const char *set_name, const char *attr_id,
                 const char *attr_name, gboolean to_console, char **value)
{
    return find_nvpair_attr_delegate(the_cib, attr, section, node_uuid, set_type,
                                     set_name, attr_id, attr_name, to_console, value, NULL);
}

int read_attr_delegate(cib_t * the_cib,
                                          const char *section, const char *node_uuid,
                                          const char *set_type, const char *set_name,
                                          const char *attr_id, const char *attr_name,
                                          char **attr_value, gboolean to_console,
                                          const char *user_name);

static inline int
read_attr(cib_t * the_cib,
          const char *section, const char *node_uuid, const char *set_type, const char *set_name,
          const char *attr_id, const char *attr_name, char **attr_value, gboolean to_console)
{
    return read_attr_delegate(the_cib, section, node_uuid, set_type, set_name,
                              attr_id, attr_name, attr_value, to_console, NULL);
}

int delete_attr_delegate(cib_t * the_cib, int options,
                                            const char *section, const char *node_uuid,
                                            const char *set_type, const char *set_name,
                                            const char *attr_id, const char *attr_name,
                                            const char *attr_value, gboolean to_console,
                                            const char *user_name);

static inline int
delete_attr(cib_t * the_cib, int options,
            const char *section, const char *node_uuid, const char *set_type, const char *set_name,
            const char *attr_id, const char *attr_name, const char *attr_value, gboolean to_console)
{
    return delete_attr_delegate(the_cib, options, section, node_uuid, set_type, set_name,
                                attr_id, attr_name, attr_value, to_console, NULL);
}

int query_node_uuid(cib_t * the_cib, const char *uname, char **uuid);

int query_node_uname(cib_t * the_cib, const char *uuid, char **uname);

int set_standby(cib_t * the_cib,
                                   const char *uuid, const char *scope, const char *standby_value);

const char *feature_set(xmlNode * xml_obj);

gboolean startCib(const char *filename);
xmlNode *get_cib_copy(cib_t * cib);
xmlNode *cib_get_generation(cib_t * cib);
int cib_compare_generation(xmlNode * left, xmlNode * right);
gboolean determine_host(cib_t * cib_conn, char **node_uname, char **node_uuid);

void cib_metadata(void);
void verify_cib_options(GHashTable * options);
const char *cib_pref(GHashTable * options, const char *name);
gboolean cib_read_config(GHashTable * options, xmlNode * current_cib);
gboolean cib_internal_config_changed(xmlNode * diff);

#endif
