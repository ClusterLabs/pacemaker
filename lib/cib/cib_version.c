
/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/cib.h>




const char * feature_sets[] = {
    "1.1",
    "1.2",
    "1.3",
    "2.0",
};


typedef struct tag_set_s 
{
	int length;
	const char **tags;
} tag_set_t;


const char *feature_tags_12[] = { "master_slave", };
const char *feature_tags_20[] = {
    "cluster_property_set",
    "meta_attributes",
    "transient_attributes",
};

tag_set_t feature_tags[] = {
    { 0, NULL },
    { 1, feature_tags_12 },
    { 0, NULL },
    { 3, feature_tags_20 },
};

const char *feature_attrs_12[] = { "master_node_max", };
const char *feature_attrs_20[] = {
    "start_delay",
    "disabled",
    "on_fail",
    "prereq",
    "collocated",
    "globally_unique",
    "from_role",
    "to_role",
    "node_attribute",
    "score_attribute",
    "hours",
    "transition_key",
    "op_digest",
    "op_restart_digest",
    "op_force_restart",
};

tag_set_t feature_attrs[] = {
    { 0, NULL },
    { 1, feature_attrs_12 },
    { 0, NULL },
    { 15, feature_attrs_20 },
};

static int
internal_update_feature_set(xmlNode *xml_obj, int current)
{
    int lpc = current;
    int lpc_nested = 0;
    const char *value = NULL;
    xmlNode *xml_child = NULL;
    int num_sets = DIMOF(feature_sets);

    CRM_CHECK(compare_version(
		  CIB_FEATURE_SET, feature_sets[num_sets-1]) == 0,
	      return num_sets-1);

    for(;lpc < num_sets; lpc++) {
	const char *tag = crm_element_name(xml_obj);
	crm_debug_3("Checking set %d with %d tags", lpc,
		    feature_tags[lpc].length);
		
	lpc_nested = 0;
	for(; lpc_nested < feature_tags[lpc].length; lpc_nested++) {
	    const char *name = feature_tags[lpc].tags[lpc_nested];
	    crm_debug_4("Checking %s vs. %s", tag, name);
	    if(safe_str_eq(tag, name)) {
		crm_debug_2("Found feature %s from set %s",
			    tag, feature_sets[lpc]);
		current = lpc;
		break;
	    }
	}
	if(current == lpc) {
	    continue;
	}

	for(lpc_nested = 0; lpc_nested < feature_attrs[lpc].length; lpc_nested++) {
	    const char *name = feature_attrs[lpc].tags[lpc_nested];
	    crm_debug_4("Checking for %s", name);
	    value = crm_element_value(xml_obj, name);
	    if(value != NULL) {
		crm_info("Found feature '%s' from set %s",
			 name, feature_sets[lpc]);
		current = lpc;
		break;
	    }
	}
    }

    if(current == (num_sets -1)) {
	return current;
    }
	
    for(xml_child = __xml_first_child(xml_obj); xml_child != NULL; xml_child = __xml_next(xml_child)) {
	current = internal_update_feature_set(xml_child,current);
	if(current == (num_sets -1)) {
	    return current;
	}
    }
    return current;	
}

const char *
feature_set(xmlNode *xml_obj)
{
    int set = internal_update_feature_set(xml_obj, 0);

    if(set >= 0 && set < DIMOF(feature_sets)) {
	return feature_sets[set];
    }
    crm_err("Unknown feature set: %d", set);
    CRM_ASSERT(set >= 0 && set < DIMOF(feature_sets));
    return "0.0";
}

