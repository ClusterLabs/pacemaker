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

xmlNode *createEmptyCib(void);
gboolean verifyCibXml(xmlNode * cib);

#  define create_cib_fragment(update,cib_section) create_cib_fragment_adv(update, cib_section, __FUNCTION__)

xmlNode *diff_cib_object(xmlNode * old, xmlNode * new, gboolean suppress);
gboolean apply_cib_diff(xmlNode * old, xmlNode * diff, xmlNode ** new);
void log_cib_diff(int log_level, xmlNode * diff, const char *function);

gboolean cib_version_details(xmlNode * cib, int *admin_epoch, int *epoch, int *updates);

int update_attr_delegate(cib_t * the_cib, int call_options,
                         const char *section, const char *node_uuid,
                         const char *set_type, const char *set_name,
                         const char *attr_id, const char *attr_name,
                         const char *attr_value, gboolean to_console, const char *user_name);

int find_nvpair_attr_delegate(cib_t * the_cib, const char *attr,
                              const char *section, const char *node_uuid,
                              const char *set_type, const char *set_name,
                              const char *attr_id, const char *attr_name,
                              gboolean to_console, char **value, const char *user_name);

int read_attr_delegate(cib_t * the_cib,
                       const char *section, const char *node_uuid,
                       const char *set_type, const char *set_name,
                       const char *attr_id, const char *attr_name,
                       char **attr_value, gboolean to_console, const char *user_name);

int delete_attr_delegate(cib_t * the_cib, int options,
                         const char *section, const char *node_uuid,
                         const char *set_type, const char *set_name,
                         const char *attr_id, const char *attr_name,
                         const char *attr_value, gboolean to_console, const char *user_name);

int query_node_uuid(cib_t * the_cib, const char *uname, char **uuid);

int query_node_uname(cib_t * the_cib, const char *uuid, char **uname);

int set_standby(cib_t * the_cib, const char *uuid, const char *scope, const char *standby_value);

xmlNode *get_cib_copy(cib_t * cib);
xmlNode *cib_get_generation(cib_t * cib);

void cib_metadata(void);
const char *cib_pref(GHashTable * options, const char *name);
int cib_apply_patch_event(xmlNode * event, xmlNode * input, xmlNode ** output, int level);

#endif
