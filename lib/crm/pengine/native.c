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

#include <crm_internal.h>

#include <crm/pengine/status.h>
#include <crm/pengine/rules.h>
#include <crm/pengine/complex.h>
#include <unpack.h>
#include <utils.h>
#include <crm/msg_xml.h>

#define DELETE_THEN_REFRESH 1

#define VARIANT_NATIVE 1
#include "./variant.h"

void
native_add_running(resource_t *rsc, node_t *node, pe_working_set_t *data_set)
{
	CRM_CHECK(node != NULL, return);

	slist_iter(
		a_node, node_t, rsc->running_on, lpc,
		CRM_CHECK(a_node != NULL, return);
		if(safe_str_eq(a_node->details->id, node->details->id)) {
			return;
		}
		);
	
	crm_debug_3("Adding %s to %s", rsc->id, node->details->uname);
	
	rsc->running_on = g_list_append(rsc->running_on, node);
	if(rsc->variant == pe_native) {
		node->details->running_rsc = g_list_append(
			node->details->running_rsc, rsc);
	}

	if(is_not_set(rsc->flags, pe_rsc_managed)) {
		crm_info("resource %s isnt managed", rsc->id);
		resource_location(rsc, node, INFINITY,
				  "not_managed_default", data_set);
		return;
	}
	
	if(rsc->variant == pe_native && g_list_length(rsc->running_on) > 1) {
		const char *type = crm_element_value(rsc->xml, XML_ATTR_TYPE);
		const char *class = crm_element_value(
			rsc->xml, XML_AGENT_ATTR_CLASS);

		
		/* these are errors because hardly any gets it right
		 *   at the moment and this way the might notice
		 */
		pe_proc_err("Resource %s::%s:%s appears to be active on %d nodes.",
			    class, type, rsc->id, g_list_length(rsc->running_on));
		cl_log(LOG_ERR, "See %s for more information.",
		       HAURL("v2/faq/resource_too_active"));
		
		if(rsc->recovery_type == recovery_stop_only) {
			crm_debug("Making sure %s doesn't come up again", rsc->id);
			/* make sure it doesnt come up again */
			pe_free_shallow_adv(rsc->allowed_nodes, TRUE);
			rsc->allowed_nodes = node_list_dup(
				data_set->nodes, FALSE, FALSE);
			slist_iter(
				node, node_t, rsc->allowed_nodes, lpc,
				node->weight = -INFINITY;
				);
			
		} else if(rsc->recovery_type == recovery_block) {
		    clear_bit(rsc->flags, pe_rsc_managed);
		}
		
	} else {
		crm_debug_3("Resource %s is active on: %s",
			    rsc->id, node->details->uname);
	}
	
	if(rsc->parent != NULL) {
		native_add_running(rsc->parent, node, data_set);
	}
	
}


gboolean native_unpack(resource_t *rsc, pe_working_set_t *data_set)
{
	native_variant_data_t *native_data = NULL;

	crm_debug_3("Processing resource %s...", rsc->id);

	crm_malloc0(native_data, sizeof(native_variant_data_t));

	rsc->allowed_nodes	= NULL;
	rsc->running_on		= NULL;

	rsc->variant_opaque = native_data;
	return TRUE;
}

resource_t *
native_find_child(resource_t *rsc, const char *id)
{
    if(rsc->children) {
	return pe_find_resource(rsc->children, id);
    }
    return NULL;
}

GListPtr native_children(resource_t *rsc)
{
	return rsc->children;
}

static void
hash_copy_field(gpointer key, gpointer value, gpointer user_data) 
{
	const char *name    = key;
	const char *s_value = value;

	GHashTable *hash_copy = user_data;
	g_hash_table_insert(hash_copy, crm_strdup(name), crm_strdup(s_value));
}

char *
native_parameter(
	resource_t *rsc, node_t *node, gboolean create, const char *name,
	pe_working_set_t *data_set)
{
	char *value_copy = NULL;
	const char *value = NULL;
	GHashTable *hash = rsc->parameters;
	GHashTable *local_hash = NULL;

	CRM_CHECK(rsc != NULL, return NULL);
	CRM_CHECK(name != NULL && strlen(name) != 0, return NULL);

	crm_debug_2("Looking up %s in %s", name, rsc->id);
	
	if(create) {
		if(node != NULL) {
			crm_debug_2("Creating hash with node %s",
				  node->details->uname);
		} else {
			crm_debug_2("Creating default hash");
		}
		
		local_hash = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			g_hash_destroy_str, g_hash_destroy_str);
		
		g_hash_table_foreach(
			rsc->parameters, hash_copy_field, local_hash);
		unpack_instance_attributes(
			rsc->xml, XML_TAG_ATTR_SETS,
			node?node->details->attrs:NULL,
			local_hash, NULL, data_set->now);

		hash = local_hash;
	}
		
	value = g_hash_table_lookup(hash, name);
	if(value == NULL) {
		/* try meta attributes instead */
		value = g_hash_table_lookup(rsc->meta, name);
	}
	
	if(value != NULL) {
		value_copy = crm_strdup(value);
	}
	if(local_hash != NULL) {
		g_hash_table_destroy(local_hash);
	}
	return value_copy;
}

gboolean native_active(resource_t *rsc, gboolean all)
{	
	slist_iter(
		a_node, node_t, rsc->running_on, lpc,

		if(a_node->details->online == FALSE) {
			crm_debug("Resource %s: node %s is offline",
				  rsc->id, a_node->details->uname);
		} else if(a_node->details->unclean) {
			crm_debug("Resource %s: node %s is unclean",
				  rsc->id, a_node->details->uname);
		} else {
			crm_debug("Resource %s active on %s",
				  rsc->id, a_node->details->uname);
			return TRUE;
		}
		);
	
	return FALSE;
}

struct print_data_s 
{
		long options;
		void *print_data;
};

static void native_print_attr(gpointer key, gpointer value, gpointer user_data)
{
	long options = ((struct print_data_s*)user_data)->options;
	void *print_data = ((struct print_data_s*)user_data)->print_data;
	status_print("Option: %s = %s\n", (char*)key, (char*)value);
}

void
native_print(
	resource_t *rsc, const char *pre_text, long options, void *print_data)
{
	node_t *node = NULL;	
	const char *prov = NULL;
	const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);

	if(safe_str_eq(class, "ocf")) {
		prov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
	}
	
	if(rsc->running_on != NULL) {
		node = rsc->running_on->data;
	}
	
	if(options & pe_print_html) {
		if(is_not_set(rsc->flags, pe_rsc_managed)) {
			status_print("<font color=\"yellow\">");

		} else if(is_set(rsc->flags, pe_rsc_failed)) {
			status_print("<font color=\"red\">");
			
		} else if(rsc->variant == pe_native
			  && g_list_length(rsc->running_on) == 0) {
			status_print("<font color=\"red\">");

		} else if(g_list_length(rsc->running_on) > 1) {
			status_print("<font color=\"orange\">");

		} else {
			status_print("<font color=\"green\">");
		}
	}

	if((options & pe_print_rsconly) || g_list_length(rsc->running_on) > 1) {
		const char *desc = NULL;
		desc = crm_element_value(rsc->xml, XML_ATTR_DESC);
		status_print("%s%s\t(%s%s%s:%s%s)%s%s",
			     pre_text?pre_text:"", rsc->id,
			     prov?prov:"", prov?"::":"",
			     class, crm_element_value(rsc->xml, XML_ATTR_TYPE),
			     is_set(rsc->flags, pe_rsc_orphan)?" ORPHANED":"",
			     desc?": ":"", desc?desc:"");

	} else {
		status_print("%s%s\t(%s%s%s:%s%s):\t%s %s%s%s",
			     pre_text?pre_text:"", rsc->id,
			     prov?prov:"", prov?"::":"",
			     class, crm_element_value(rsc->xml, XML_ATTR_TYPE),
			     is_set(rsc->flags, pe_rsc_orphan)?" ORPHANED":"",
			     (rsc->variant!=pe_native)?"":role2text(rsc->role),
			     (rsc->variant!=pe_native)?"":node!=NULL?node->details->uname:"",
			     is_set(rsc->flags, pe_rsc_managed)?"":" (unmanaged)",
			     is_set(rsc->flags, pe_rsc_failed)?" FAILED":"");
		
#if CURSES_ENABLED
		if(options & pe_print_ncurses) {
			move(-1, 0);
		}
#endif
	}
	
	if(options & pe_print_html) {
		status_print(" </font> ");
	}
	
	if((options & pe_print_rsconly)) {
		
	} else if(g_list_length(rsc->running_on) > 1) {
		if(options & pe_print_html) {
			status_print("<ul>\n");
		} else if((options & pe_print_printf)
			  || (options & pe_print_ncurses)) {
			status_print("[");
		}
		
		slist_iter(node, node_t, rsc->running_on, lpc,
			   if(options & pe_print_html) {
				   status_print("<li>\n%s",
						node->details->uname);

			   } else if((options & pe_print_printf)
				     || (options & pe_print_ncurses)) {
				   status_print("\t%s", node->details->uname);

			   } else if((options & pe_print_log)) {
				   status_print("\t%d : %s",
						lpc, node->details->uname);

			   } else {
				   status_print("%s", node->details->uname);
			   }
			   if(options & pe_print_html) {
				   status_print("</li>\n");

			   }
			);
		
		if(options & pe_print_html) {
			status_print("</ul>\n");
		} else if((options & pe_print_printf)
			  || (options & pe_print_ncurses)) {
			status_print(" ]");
		}
	}

	if(options & pe_print_html) {
		status_print("<br/>\n");
	} else if((options & pe_print_printf) || (options & pe_print_ncurses)) {
		status_print("\n");
	}

	if(options & pe_print_details) {
		struct print_data_s pdata;
		pdata.options = options;
		pdata.print_data = print_data;
		g_hash_table_foreach(rsc->parameters, native_print_attr, &pdata);
	}

	if(options & pe_print_dev) {
		status_print("%s\t(%s%svariant=%s, priority=%f)", pre_text,
			     is_set(rsc->flags, pe_rsc_provisional)?"provisional, ":"",
			     is_set(rsc->flags, pe_rsc_runnable)?"":"non-startable, ",
			     crm_element_name(rsc->xml),
			     (double)rsc->priority);
		status_print("%s\tAllowed Nodes", pre_text);
		slist_iter(node, node_t, rsc->allowed_nodes, lpc,
			   status_print("%s\t * %s %d",
					pre_text,
					node->details->uname,
					node->weight);
			);	
	}

	if(options & pe_print_max_details) {
		status_print("%s\t=== Allowed Nodes\n", pre_text);
		slist_iter(
			node, node_t, rsc->allowed_nodes, lpc,
			print_node("\t", node, FALSE);
			);
	}
}

void native_free(resource_t *rsc)
{
	crm_debug_4("Freeing resource action list (not the data)");
	common_free(rsc);
}


enum rsc_role_e
native_resource_state(const resource_t *rsc, gboolean current)
{
	enum rsc_role_e role = rsc->next_role;
	if(current) {
		role = rsc->role;
	}
	crm_debug_2("%s state: %s", rsc->id, role2text(role));
	return role;
}

node_t *native_location(resource_t *rsc, GListPtr *list, gboolean current) 
{
    node_t *one = NULL;
    GListPtr result = NULL;

    if(rsc->children) {
	slist_iter(child, resource_t, rsc->children, lpc,
		   child->fns->location(child, &result, current);
	    );
	
    } else if(current && rsc->running_on) {
	result = g_list_copy(rsc->running_on);
	
    } else if(current == FALSE && rsc->allocated_to) {
	result = g_list_append(NULL, rsc->allocated_to);
    }

    if(result && g_list_length(result) == 1) {
	one = g_list_nth_data(result, 0);
    }
    
    if(list) {
	slist_iter(node, node_t, result, lpc,
		   if(*list == NULL || pe_find_node_id(*list, node->details->id) == NULL) {
		       *list = g_list_append(*list, node);
		   }
	    );
    }

    g_list_free(result);	
    return one;
}
