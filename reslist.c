/*
  Copyright Red Hat, Inc. 2004

  This program is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by the
  Free Software Foundation; either version 2, or (at your option) any
  later version.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; see the file COPYING.  If not, write to the
  Free Software Foundation, Inc.,  675 Mass Ave, Cambridge, 
  MA 02139, USA.
*/
#include <libxml/parser.h>
#include <libxml/xmlmemory.h>
#include <libxml/xpath.h>
#include <stdlib.h>
#include <stdio.h>
#include <resgroup.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <list.h>
#include <libgen.h>
#include <reslist.h>
#include <xmlconf.h>


void
res_build_name(char *buf, size_t buflen, resource_t *res)
{
	snprintf(buf, buflen, "%s:%s", res->r_rule->rr_type,
		 res->r_attrs[0].ra_value);
}

/**
   Find and determine an attribute's value. 

   @param res		Resource node to look examine
   @param attrname	Attribute to retrieve.
   @return 		value of attribute or NULL if not found
 */
char *
res_attr_value(resource_t *res, char *attrname)
{
	resource_attr_t *ra;
	int x;

	for (x = 0; res->r_attrs && res->r_attrs[x].ra_name; x++) {
		if (strcmp(attrname, res->r_attrs[x].ra_name))
			continue;

		ra = &res->r_attrs[x];

		if (ra->ra_flags & RA_INHERIT)
			/* Can't check inherited resources */
			return NULL;

		return ra->ra_value;
	}

	return NULL;
}


/**
   Find and determine an attribute's value.  Takes into account inherited
   attribute flag, and append attribute flag, which isn't implemented yet.

   @param node		Resource tree node to look examine
   @param attrname	Attribute to retrieve.
   @param ptype		Resource type to look for (if inheritance)
   @return 		value of attribute or NULL if not found
 */
static char *
_attr_value(resource_node_t *node, char *attrname, char *ptype)
{
	resource_t *res;
	resource_attr_t *ra;
	char *c, p_type[32];
	ssize_t len;
	int x;

	if (!node)
		return NULL;

	res = node->rn_resource;

	/* Go up the tree if it's not the right parent type */
	if (ptype && strcmp(res->r_rule->rr_type, ptype))
		return _attr_value(node->rn_parent, attrname, ptype);

	for (x = 0; res->r_attrs && res->r_attrs[x].ra_name; x++) {
		if (strcmp(attrname, res->r_attrs[x].ra_name))
			continue;

		ra = &res->r_attrs[x];

		if (!(ra->ra_flags & RA_INHERIT))
			return ra->ra_value;
		/* 
		   Handle resource_type%field to be more precise, so we
		   don't have to worry about this being a child
		   of an unexpected type.  E.g. lots of things have the
		   "name" attribute.
		 */
		c = strchr(ra->ra_value, '%');
		if (!c) {
			/* Someone doesn't care or uses older
			   semantics on inheritance */
			return _attr_value(node->rn_parent, ra->ra_value,
					   NULL);
		}
		
		len = (c - ra->ra_value);
		memset(p_type, 0, sizeof(p_type));
		memcpy(p_type, ra->ra_value, len);
		
		/* Skip the "%" and recurse */
		return _attr_value(node->rn_parent, ++c, p_type);
	}

	return NULL;
}


char *
attr_value(resource_node_t *node, char *attrname)
{
	return _attr_value(node, attrname, NULL);
}


char *
primary_attr_value(resource_t *res)
{
	int x;
	resource_attr_t *ra;

	for (x = 0; res->r_attrs && res->r_attrs[x].ra_name; x++) {
		ra = &res->r_attrs[x];

		if (!(ra->ra_flags & RA_PRIMARY))
			continue;

		return ra->ra_value;
	}

	return NULL;
}


/**
   Find a resource given its reference.  A reference is the value of the
   primary attribute.

   @param reslist	List of resources to traverse.
   @param type		Type of resource to look for.
   @param ref		Reference
   @return		Resource matching type/ref or NULL if none.
 */   
resource_t *
find_resource_by_ref(resource_t **reslist, char *type, char *ref)
{
	resource_t *curr;
	int x;

	list_do(reslist, curr) {
		if (strcmp(curr->r_rule->rr_type, type))
			continue;

		/*
		   This should be one operation - the primary attr
		   is generally at the head of the array.
		 */
		for (x = 0; curr->r_attrs && curr->r_attrs[x].ra_name;
		     x++) {
			if (!(curr->r_attrs[x].ra_flags & RA_PRIMARY))
				continue;
			if (strcmp(ref, curr->r_attrs[x].ra_value))
				continue;

			return curr;
		}
	} while (!list_done(reslist, curr));

	return NULL;
}


/**
   Store a resource in the resource list if it's legal to do so.
   Otherwise, don't store it.
   Note: This function needs to be rewritten; it's way too long and way
   too indented.

   @param reslist	Resource list to store the new resource.
   @param newres	Resource to store
   @return 		0 on succes; nonzero on failure.
 */
int
store_resource(resource_t **reslist, resource_t *newres)
{
	resource_t *curr;
	int x, y;

	if (!*reslist) {
		/* first resource */
		list_insert(reslist, newres);
		return 0;
	}

	list_do(reslist, curr) {

		if (strcmp(curr->r_rule->rr_type, newres->r_rule->rr_type))
		    	continue;

		for (x = 0; newres->r_attrs && newres->r_attrs[x].ra_name;
		     x++) {
			/*
			   Look for conflicting primary/unique keys
			 */
			if (!(newres->r_attrs[x].ra_flags &
			    (RA_PRIMARY | RA_UNIQUE)))
				continue;

			for (y = 0; curr->r_attrs[y].ra_name; y++) {
				if (curr->r_attrs[y].ra_flags & RA_INHERIT)
					continue;

				if (strcmp(curr->r_attrs[y].ra_name,
					   newres->r_attrs[x].ra_name))
					continue;
				if (!strcmp(curr->r_attrs[y].ra_value,
					    newres->r_attrs[x].ra_value)) {
					/*
					   Unique/primary is not unique
					 */
				fprintf(stderr,
                                               "%s attribute collision. "
                                               "type=%s attr=%s value=%s\n",
					       (newres->r_attrs[x].ra_flags&
                                                RA_PRIMARY)?"Primary":
                                               "Unique",
					       newres->r_rule->rr_type,
					       newres->r_attrs[x].ra_name,
					       newres->r_attrs[x].ra_value
					       );
					return -1;
				}
				break;
			}
		}
	} while (!list_done(reslist, curr));

	list_insert(reslist, newres);
	return 0;
}


/**
   Obliterate a resource_t structure.

   @param res		Resource to free.
 */
void
destroy_resource(resource_t *res)
{
	int x;

	if (res->r_name)
		free(res->r_name);

	if (res->r_attrs) {
		for (x = 0; res->r_attrs && res->r_attrs[x].ra_name; x++) {
			free(res->r_attrs[x].ra_name);
			free(res->r_attrs[x].ra_value);
		}

		free(res->r_attrs);
	}

	if (res->r_actions) {
		/* Don't free the strings; they're part of the rule */
		free(res->r_actions);
	}

	free(res);
}



/**
   Obliterate a resource_t list.

   @param list		Resource list to free.
 */
void
destroy_resources(resource_t **list)
{
	resource_t *res;

	while ((res = *list)) {
		list_remove(list, res);
		destroy_resource(res);
	}
}


void *
act_dup(resource_act_t *acts)
{
	int x;
	resource_act_t *newacts;

	for (x = 0; acts[x].ra_name; x++);

	++x;
	x *= sizeof(resource_act_t);

	newacts = malloc(x);
	if (!newacts)
		return NULL;

	memcpy(newacts, acts, x);

	return newacts;
}


/* Copied from resrules.c -- _get_actions */
void
_get_actions_ccs(char *base, resource_t *res)
{
	char xpath[256];
	int idx = 0;
	char *act, *ret;
	int interval, timeout, depth;

	do {
		/* setting these to -1 prevents overwriting with 0 */
		interval = -1;
		depth = -1;
		act = NULL;
		timeout = -1;

		snprintf(xpath, sizeof(xpath),
			 "%s/action[%d]/@name", base, ++idx);

		if (conf_get(xpath, &act) != 0)
			break;

		snprintf(xpath, sizeof(xpath),
			 "%s/action[%d]/@timeout", base, idx);
		if (conf_get(xpath, &ret) == 0 && ret) {
			timeout = expand_time(ret);
			if (timeout < 0)
				timeout = 0;
			free(ret);
		}

		snprintf(xpath, sizeof(xpath),
			 "%s/action[%d]/@interval", base, idx);
		if (conf_get(xpath, &ret) == 0 && ret) {
			interval = expand_time(ret);
			if (interval < 0)
				interval = 0;
			free(ret);
		}

		if (!strcmp(act, "status") || !strcmp(act, "monitor")) {
			snprintf(xpath, sizeof(xpath),
				 "%s/action[%d]/@depth", base, idx);
			if (conf_get(xpath, &ret) == 0 && ret) {
				depth = atoi(ret);
				if (depth < 0)
					depth = 0;
				
				/* */
				if (ret[0] == '*')
					depth = -1;
				free(ret);
			}
		}

		if (store_action(&res->r_actions, act, depth, timeout,
				 interval) != 0)
			free(act);
	} while (1);
}


/**
   Try to load all the attributes in our rule set.  If none are found,
   or an error occurs, return NULL and move on to the next one.

   @param rule		Resource rule set to use when looking for data
   @param base		Base XPath path to start with.
   @return		New resource if legal or NULL on failure/error
 */
resource_t *
load_resource(resource_rule_t *rule, char *base)
{
	resource_t *res;
	char ccspath[1024];
	char *attrname, *attr;
	int x, found = 0, flags;

	res = malloc(sizeof(*res));
	if (!res) {
		fprintf(stderr,"Out of memory\n");
			return NULL;
	}

	memset(res, 0, sizeof(*res));
	res->r_rule = rule;

	for (x = 0; res->r_rule->rr_attrs &&
	     res->r_rule->rr_attrs[x].ra_name; x++) {

		flags = rule->rr_attrs[x].ra_flags;
		attrname = strdup(rule->rr_attrs[x].ra_name);
		if (!attrname) {
			destroy_resource(res);
			return NULL;
		}

		/*
		   Ask CCS for the respective attribute
		 */
		attr = NULL;
		snprintf(ccspath, sizeof(ccspath), "%s/@%s", base, attrname);

		if (conf_get(ccspath, &attr) != 0) {

			if (flags & (RA_REQUIRED | RA_PRIMARY)) {
				/* Missing required attribute.  We're done. */
				free(attrname);
				destroy_resource(res);
				return NULL;
			}

			if (!(flags & RA_INHERIT)) {
				/*
				   If we don't have the inherit flag, see if
				   we have a value anyway.  If we do,
				   this value is the default value, and
				   should be used.
				 */
				if (!rule->rr_attrs[x].ra_value) {
					free(attrname);
					continue;
				}

				/* Copy default value from resource rule */
				attr = strdup(rule->rr_attrs[x].ra_value);
			}
		}

		found = 1;

		/*
		   If we are supposed to inherit and we don't have an
		   instance of the specified attribute in CCS, then we
		   keep the inherit flag and use it as the attribute.

		   However, if we _do_ have the attribute for this instance,
		   we drop the inherit flag and use the attribute.
		 */
		if (flags & RA_INHERIT) {
		       	if (attr) {
				flags &= ~RA_INHERIT;
			} else {
				attr = strdup(rule->rr_attrs[x].ra_value);
				if (!attr) {
					destroy_resource(res);
					free(attrname);
					return NULL;
				}
			}
		}

		/*
		   Store the attribute.  We'll ensure all required
		   attributes are present soon.
		 */
		if (attrname && attr)
			store_attribute(&res->r_attrs, attrname, attr, flags);
	}

	if (!found) {
		destroy_resource(res);
		return NULL;
	}

	res->r_actions = act_dup(rule->rr_actions);
	_get_actions_ccs(base, res);

	return res;
}


/**
   Read all resources in the resource manager block in CCS.

   @param reslist	Empty list to fill with resources.
   @param rulelist	List of rules to use when searching CCS.
   @return		0 on success, nonzero on failure.
 */
int
load_resources(resource_t **reslist, resource_rule_t **rulelist)
{
	int resID = 0;
	resource_t *newres;
	resource_rule_t *currule;
	char tok[256];

	list_do(rulelist, currule) {

		for (resID = 1; ; resID++) {
			snprintf(tok, sizeof(tok), RESOURCE_BASE "/%s[%d]",
				 currule->rr_type, resID);
			
			newres = load_resource(currule, tok);
			if (!newres)
				break;

		       if (store_resource(reslist, newres) != 0) {
	       		      fprintf(stderr,
				      "Error storing %s resource\n",
				      newres->r_rule->rr_type);

			       destroy_resource(newres);
		       }

		       /* Just information */
		       newres->r_flags = RF_DEFINED;
		}
	} while (!list_done(rulelist, currule));

	return 0;
}

