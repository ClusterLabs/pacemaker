/*
  Copyright Red Hat, Inc. 2004-2006

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
  Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
  MA 02110-1301 USA

  Fix for #193859 - relocation of a service w/o umounting file-systems
    by Navid Sheikhol-Eslami [ navid at redhat dot com ]
*/
#include <libxml/parser.h>
#include <libxml/xmlmemory.h>
#include <libxml/xpath.h>
#include <stdlib.h>
#include <stdio.h>
#include <list.h>
#include <sys/wait.h>
#include <resgroup.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <reslist.h>
#include <assert.h>
#include <xmlconf.h>

/* XXX from resrules.c */
int store_childtype(resource_child_t ** childp, char *name, int start,
                    int stop, int forbid, int flags);
int _res_op(xmlNode ** xpp, xmlNode * rmp, resource_node_t ** tree, resource_t * first, char *type);
static inline int


_res_op_internal(xmlNode ** xpp, xmlNode * rmp, resource_node_t ** tree, resource_t * first,
                 char *type, resource_node_t * node);

/* XXX from reslist.c */
void *act_dup(resource_act_t * acts);

/**
   Fold a resource into an XML node.

   @param xpp		XML node pp
   @param rmp		resources block pp
   @param node		Resource tree node we're dealing with
   @param op		Operation to perform (stop/start/etc.)
   @param depth		OCF Check level/depth
   @return		Return value of script.
   @see			build_env
 */
static int
res_do_flatten(xmlNode ** xpp, xmlNode * rmp, resource_node_t * node, const char *arg, int depth)
{
    xmlNode *n, *r;
    resource_attr_t *ra;
    resource_t *res = node->rn_resource;
    char *val;
    char buf[256];
    int x, y;

    n = xmlNewNode(NULL, (xmlChar *) node->rn_resource->r_rule->rr_type);

    xmlSetProp(n, (xmlChar *) "rgmanager-meta-agent",
               (xmlChar *) basename(node->rn_resource->r_rule->rr_agent));

    /* Multiple-instance resources must be decomposed into separate
       resources */
    if (node->rn_resource->r_refs > 1) {
        snprintf(buf, sizeof(buf), "%s_%d",
                 primary_attr_value(node->rn_resource), node->rn_resource->r_incarnations);
        ++node->rn_resource->r_incarnations;
    } else {
        snprintf(buf, sizeof(buf), "%s", primary_attr_value(node->rn_resource));
    }

    for (x = 0; node->rn_resource->r_attrs && node->rn_resource->r_attrs[x].ra_name; x++) {
        ra = &node->rn_resource->r_attrs[x];

        if (ra->ra_flags & RA_PRIMARY) {
            xmlSetProp(n, (xmlChar *) ra->ra_name, (xmlChar *) buf);
        } else {
            val = attr_value(node, res->r_attrs[x].ra_name);
            if (!val)
                continue;

            for (y = 0; res->r_rule->rr_attrs[y].ra_name; y++) {
                if (strcmp(ra->ra_name, res->r_rule->rr_attrs[y].ra_name))
                    continue;

                if (!res->r_rule->rr_attrs[y].ra_value ||
                    strcmp(val, res->r_rule->rr_attrs[y].ra_value))
                    xmlSetProp(n, (xmlChar *) ra->ra_name, (xmlChar *) val);
            }
        }
    }

    if (!*xpp) {
        /* Add top-level container */
        *xpp = n;
    } else {
        if (!rmp) {
            xmlAddChild(*xpp, n);
        } else {
            r = xmlNewNode(NULL, (xmlChar *) node->rn_resource->r_rule->rr_type);
            xmlSetProp(r, (xmlChar *) "ref", (xmlChar *) primary_attr_value(node->rn_resource));
            xmlAddChild(rmp, n);
            xmlAddChild(*xpp, r);
        }
    }

    return 0;
}

static inline void
assign_restart_policy(resource_t * curres, resource_node_t * parent,
                      resource_node_t * node, char *base)
{
    char *val;
    int max_restarts = 0;
    time_t restart_expire_time = 0;
    char tok[1024];

    if (!curres || !node)
        return;
    if (parent && !(node->rn_flags & RF_INDEPENDENT))
        return;

    if (node->rn_flags & RF_INDEPENDENT) {
        /* per-resource-node failures / expire times */
        snprintf(tok, sizeof(tok), "%s/@__max_restarts", base);
        if (conf_get(tok, &val) == 0) {
            max_restarts = atoi(val);
            if (max_restarts <= 0)
                max_restarts = 0;
            free(val);
        }

        snprintf(tok, sizeof(tok), "%s/@__restart_expire_time", base);
        if (conf_get(tok, &val) == 0) {
            restart_expire_time = (time_t) expand_time(val);
            if ((int64_t) restart_expire_time <= 0)
                restart_expire_time = 0;
            free(val);
        }
        //if (restart_expire_time == 0 || max_restarts == 0)
        return;
        //goto out_assign;
    }

    val = (char *)res_attr_value(curres, "max_restarts");
    if (!val)
        return;
    max_restarts = atoi(val);
    if (max_restarts <= 0)
        return;
    val = res_attr_value(curres, "restart_expire_time");
    if (val) {
        restart_expire_time = (time_t) expand_time(val);
        if ((int64_t) restart_expire_time < 0)
            return;
    }
//out_assign:
    return;
}

static inline int
do_load_resource(char *base,
                 resource_rule_t * rule,
                 resource_node_t ** tree,
                 resource_t ** reslist, resource_node_t * parent, resource_node_t ** newnode)
{
    char tok[512];
    char *ref;
    resource_node_t *node;
    resource_t *curres;
    time_t failure_expire = 0;
    int max_failures = 0;

    snprintf(tok, sizeof(tok), "%s/@ref", base);

    if (conf_get(tok, &ref) != 0) {
        /* There wasn't an existing resource. See if there
           is one defined inline */
        curres = load_resource(rule, base);
        if (!curres) {
            /* No ref and no new one inline == 
               no more of the selected type */
            return 1;
        }

        if (store_resource(reslist, curres) != 0) {
            fprintf(stderr, "Error storing %s resource\n", curres->r_rule->rr_type);
            destroy_resource(curres);
            return -1;
        }

        curres->r_flags = RF_INLINE;

    } else {

        curres = find_resource_by_ref(reslist, rule->rr_type, ref);
        if (!curres) {
            fprintf(stderr, "Error: Reference to nonexistent "
                    "resource %s (type %s)\n", ref, rule->rr_type);
            free(ref);
            return -1;
        }

        if (curres->r_flags & RF_INLINE) {
            fprintf(stderr, "Error: Reference to inlined "
                    "resource %s (type %s) is illegal\n", ref, rule->rr_type);
            free(ref);
            return -1;
        }
        free(ref);
    }

    /* Load it if its max refs hasn't been exceeded */
    if (rule->rr_maxrefs && (curres->r_refs >= rule->rr_maxrefs)) {
        fprintf(stderr, "Warning: Max references exceeded for resource"
                " %s (type %s)\n", curres->r_attrs[0].ra_name, rule->rr_type);
        return -1;
    }

    node = malloc(sizeof(*node));
    if (!node)
        return -1;

    memset(node, 0, sizeof(*node));

    //printf("New resource tree node: %s:%s \n", curres->r_rule->rr_type,curres->r_attrs->ra_value);

    node->rn_child = NULL;
    node->rn_parent = parent;
    node->rn_resource = curres;
    node->rn_state = RES_STOPPED;
    node->rn_flags = 0;
    node->rn_actions = (resource_act_t *) act_dup(curres->r_actions);

    if (parent) {
        /* Independent subtree / non-critical for top-level is
         * not useful and can interfere with restart thresholds for
         * non critical resources */
        snprintf(tok, sizeof(tok), "%s/@__independent_subtree", base);
        if (conf_get(tok, &ref) == 0) {
            if (atoi(ref) == 1 || strcasecmp(ref, "yes") == 0)
                node->rn_flags |= RF_INDEPENDENT;
            if (atoi(ref) == 2 || strcasecmp(ref, "non-critical") == 0) {
                curres->r_flags |= RF_NON_CRITICAL;
            }
            free(ref);
        }
    }

    snprintf(tok, sizeof(tok), "%s/@__enforce_timeouts", base);
    if (conf_get(tok, &ref) == 0) {
        if (atoi(ref) > 0 || strcasecmp(ref, "yes") == 0)
            node->rn_flags |= RF_ENFORCE_TIMEOUTS;
        free(ref);
    }

    /* per-resource-node failures / expire times */
    snprintf(tok, sizeof(tok), "%s/@__max_failures", base);
    if (conf_get(tok, &ref) == 0) {
        max_failures = atoi(ref);
        if (max_failures < 0)
            max_failures = 0;
        free(ref);
    }

    snprintf(tok, sizeof(tok), "%s/@__failure_expire_time", base);
    if (conf_get(tok, &ref) == 0) {
        failure_expire = (time_t) expand_time(ref);
        if ((int64_t) failure_expire < 0)
            failure_expire = 0;
        free(ref);
    }

    if (max_failures && failure_expire) {
        /*
           node->rn_failure_counter = restart_init(failure_expire,
           max_failures);
         */
    }

    curres->r_refs++;

    if (curres->r_refs > 1 && (curres->r_flags & RF_NON_CRITICAL)) {
        res_build_name(tok, sizeof(tok), curres);
        fprintf(stderr, "Non-critical flag for %s is being cleared due to multiple references.\n",
                tok);
        curres->r_flags &= ~RF_NON_CRITICAL;
    }

    if (curres->r_flags & RF_NON_CRITICAL) {
        /* Independent subtree is implied if a
         * resource is non-critical
         */
        node->rn_flags |= RF_NON_CRITICAL | RF_INDEPENDENT;

    }

    assign_restart_policy(curres, parent, node, base);

    *newnode = node;

    list_insert(tree, node);

    return 0;
}

/**
   Build the resource tree.  If a new resource is defined inline, add it to
   the resource list.  All rules, however, must have already been read in.

   @param tree		Tree to modify/insert on to
   @param parent	Parent node, if one exists.
   @param rule		Rule surrounding the new node
   @param rulelist	List of all rules allowed in the tree.
   @param reslist	List of all currently defined resources
   @param base		Base CCS path.
   @see			destroy_resource_tree
 */
#define RFL_FOUND 0x1
#define RFL_FORBID 0x2
static int
build_tree(resource_node_t ** tree,
           resource_node_t * parent,
           resource_rule_t * rule, resource_rule_t ** rulelist, resource_t ** reslist, char *base)
{
    char tok[512];
    resource_rule_t *childrule;
    resource_node_t *node;
    char *ref;
    char *tmp;
    int ccount = 0, x = 0, y = 0, flags = 0;

    //printf("DESCEND: %s / %s\n", rule?rule->rr_type:"(none)", base);

    /* Pass 1: typed / defined children */
    for (y = 0; rule && rule->rr_childtypes && rule->rr_childtypes[y].rc_name; y++) {

        flags = 0;
        list_for(rulelist, childrule, x) {
            if (strcmp(rule->rr_childtypes[y].rc_name, childrule->rr_type))
                continue;

            flags |= RFL_FOUND;

            if (rule->rr_childtypes[y].rc_forbid)
                flags |= RFL_FORBID;

            break;
        }

        if (flags & RFL_FORBID)
            /* Allow all *but* forbidden */
            continue;

        if (!(flags & RFL_FOUND))
            /* Not found?  Wait for pass 2 */
            continue;

        //printf("looking for %s %s @ %s\n",
        //rule->rr_childtypes[y].rc_name,
        //childrule->rr_type, base);
        for (x = 1;; x++) {

            /* Search for base/type[x]/@ref - reference an existing
               resource */
            snprintf(tok, sizeof(tok), "%s/%s[%d]", base, childrule->rr_type, x);

            flags = 1;
            switch (do_load_resource(tok, childrule, tree, reslist, parent, &node)) {
                case -1:
                    continue;
                case 1:
                    /* 1 == no more */
                    //printf("No resource found @ %s\n", tok);
                    flags = 0;
                    break;
                case 0:
                    break;
            }
            if (!flags)
                break;

            /* Got a child :: bump count */
            snprintf(tok, sizeof(tok), "%s/%s[%d]", base, childrule->rr_type, x);

            /* Kaboom */
            build_tree(&node->rn_child, node, childrule, rulelist, reslist, tok);

        }
    }

    /* Pass 2: untyped children */
    for (ccount = 1;; ccount++) {
        snprintf(tok, sizeof(tok), "%s/child::*[%d]", base, ccount);

        if (conf_get(tok, &ref) != 0) {
            /* End of the line. */
            //printf("End of the line: %s\n", tok);
            break;
        }

        tmp = strchr(ref, '=');
        if (tmp) {
            *tmp = 0;
        } else {
            /* no = sign... bad */
            free(ref);
            continue;
        }

        /* Find the resource rule */
        flags = 0;
        list_for(rulelist, childrule, x) {
            if (!strcasecmp(childrule->rr_type, ref)) {
                /* Ok, matching rule found */
                flags = 1;
                break;
            }
        }
        /* No resource rule matching the child?  Press on... */
        if (!flags) {
            free(ref);
            continue;
        }

        flags = 0;
        /* Don't descend on anything we should have already picked
           up on in the above loop */
        for (y = 0; rule && rule->rr_childtypes && rule->rr_childtypes[y].rc_name; y++) {
            /* SKIP defined child types of any type */
            if (strcmp(rule->rr_childtypes[y].rc_name, ref))
                continue;
            if (rule->rr_childtypes[y].rc_flags == 0) {
                /* 2 = defined as a real child */
                flags = 2;
                break;
            }

            flags = 1;
            break;
        }

        free(ref);
        if (flags == 2)
            continue;

        x = 1;
        switch (do_load_resource(tok, childrule, tree, reslist, parent, &node)) {
            case -1:
                continue;
            case 1:
                /* no more found */
                x = 0;
                fprintf(stderr, "No resource found @ %s\n", tok);
                break;
            case 0:
                /* another is found */
                break;
        }
        if (!x)                 /* no more found */
            break;

        /* childrule = rule set of this child at this point */
        /* tok = set above; if we got this far, we're all set */
        /* Kaboom */

        build_tree(&node->rn_child, node, childrule, rulelist, reslist, tok);
    }

    //printf("ASCEND: %s / %s\n", rule?rule->rr_type:"(none)", base);
    return 0;
}

/**
   Set up to call build_tree.  Hides the nastiness from the user.

   @param tree		Tree pointer.  Should start as a pointer to NULL.
   @param rulelist	List of all rules allowed
   @param reslist	List of all currently defined resources
   @return 		0
   @see			build_tree destroy_resource_tree
 */
int
build_resource_tree(resource_node_t ** tree, resource_rule_t ** rulelist, resource_t ** reslist)
{
    resource_node_t *root = NULL;
    char tok[512];

    snprintf(tok, sizeof(tok), "%s", RESOURCE_TREE_ROOT);

    /* Find and build the list of root nodes */
    build_tree(&root, NULL, NULL /*curr */ , rulelist, reslist, tok);

    if (root)
        *tree = root;

    return 0;
}

/**
   Deconstruct a resource tree.

   @param tree		Tree to obliterate.
   @see			build_resource_tree
 */
void
destroy_resource_tree(resource_node_t ** tree)
{
    resource_node_t *node;

    while ((node = *tree)) {
        if ((*tree)->rn_child)
            destroy_resource_tree(&(*tree)->rn_child);

        list_remove(tree, node);

        if (node->rn_actions) {
            free(node->rn_actions);
        }
        free(node);
    }
}

static inline int
_do_child_levels(xmlNode ** xpp, xmlNode * rmp, resource_node_t ** tree, resource_t * first)
{
    resource_node_t *node = *tree;
    resource_t *res = node->rn_resource;
    resource_rule_t *rule = res->r_rule;
    int l, lev, x, rv = 0;

    for (l = 1; l <= RESOURCE_MAX_LEVELS; l++) {

        for (x = 0; rule->rr_childtypes && rule->rr_childtypes[x].rc_name; x++) {

            lev = rule->rr_childtypes[x].rc_startlevel;

            if (!lev || lev != l)
                continue;

            /* Do op on all children at our level */
            rv |= _res_op(xpp, rmp, &node->rn_child, first, rule->rr_childtypes[x].rc_name);

            if (rv & SFL_FAILURE)
                return rv;
        }

        if (rv != 0)
            return rv;
    }

    return rv;
}

static inline int
_xx_child_internal(xmlNode ** xpp, xmlNode * rmp, resource_node_t * node, resource_t * first,
                   resource_node_t * child)
{
    int x;
    resource_rule_t *rule = node->rn_resource->r_rule;

    for (x = 0; rule->rr_childtypes && rule->rr_childtypes[x].rc_name; x++) {
        if (!strcmp(child->rn_resource->r_rule->rr_type, rule->rr_childtypes[x].rc_name)) {
            if (rule->rr_childtypes[x].rc_startlevel || rule->rr_childtypes[x].rc_stoplevel) {
                return 0;
            }
        }
    }

    return _res_op_internal(xpp, rmp, &child, first, child->rn_resource->r_rule->rr_type, child);
}

static inline int
_do_child_default_level(xmlNode ** xpp, xmlNode * rmp, resource_node_t ** tree, resource_t * first)
{
    resource_node_t *node = *tree, *child;
    int y, rv = 0;

    list_for(&node->rn_child, child, y) {
        rv |= _xx_child_internal(xpp, rmp, node, first, child);

        if (rv & SFL_FAILURE)
            return rv;
    }

    return rv;
}

/**
   Nasty codependent function.  Perform an operation by numerical level
   at some point in the tree.  This allows indirectly-dependent resources
   (such as IP addresses and user scripts) to have ordering without requiring
   a direct dependency.

   @param tree		Resource tree to search/perform operations on
   @param first		Resource we're looking to perform the operation on,
   			if one exists.
   @param ret		Unused, but will be used to store status information
   			such as resources consumed, etc, in the future.
   @param op		Operation to perform if either first is found,
   			or no first is declared (in which case, all nodes
			in the subtree).
   @see			_res_op res_exec
 */
static int
_res_op_by_level(xmlNode ** xpp, xmlNode * rmp, resource_node_t ** tree, resource_t * first)
{
    resource_node_t *node = *tree;
    resource_t *res = node->rn_resource;
    resource_rule_t *rule = res->r_rule;
    int rv = 0;

    if (!rule->rr_childtypes)
        return _res_op(xpp, rmp, &node->rn_child, first, NULL);

    rv |= _do_child_levels(xpp, rmp, tree, first);
    if (rv & SFL_FAILURE)
        return rv;

    /* default level after specified ones */
    rv |= _do_child_default_level(xpp, rmp, tree, first);

    return rv;
}

/**
   Nasty codependent function.  Perform an operation by type for all siblings
   at some point in the tree.  This allows indirectly-dependent resources
   (such as IP addresses and user scripts) to have ordering without requiring
   a direct dependency.

   @param tree		Resource tree to search/perform operations on
   @param first		Resource we're looking to perform the operation on,
   			if one exists.
   @param type		Type to look for.
   @see			_res_op_by_level res_exec
 */
static inline int
_res_op_internal(xmlNode ** xpp, xmlNode * rmp,
                 resource_node_t __attribute__ ((unused)) ** tree,
                 resource_t * first, char *type, resource_node_t * node)
{
    int rv = 0, me;

    /* Restore default operation. */

    /* If we're starting by type, do that funky thing. */
    if (type && strlen(type) && strcmp(node->rn_resource->r_rule->rr_type, type))
        return 0;

    /* If the resource is found, all nodes in the subtree must
       have the operation performed as well. */
    me = !first || (node->rn_resource == first);

    /* Start starts before children */
    if (me) {

        rv = res_do_flatten(xpp, rmp, node, NULL, 0);

    }

    if (node->rn_child) {
        rv |= _res_op_by_level(xpp, rmp, &node, me ? NULL : first);
    }

    return rv;
}

/**
   Nasty codependent function.  Perform an operation by type for all siblings
   at some point in the tree.  This allows indirectly-dependent resources
   (such as IP addresses and user scripts) to have ordering without requiring
   a direct dependency.

   @param tree		Resource tree to search/perform operations on
   @param first		Resource we're looking to perform the operation on,
   			if one exists.
   @param type		Type to look for.
   @see			_res_op_by_level res_exec
 */
int
_res_op(xmlNode ** xpp, xmlNode * rmp, resource_node_t ** tree, resource_t * first, char *type)
{
    resource_node_t *node;
    int count = 0, rv = 0;

    list_for(tree, node, count) {
        rv |= _res_op_internal(xpp, rmp, tree, first, type, node);

        if (rv & SFL_FAILURE)
            return rv;
    }

    return rv;
}

/**
   Flatten resources for a service and return the pointer to it.

   @param tree		Tree to search for our resource.
   @param res		Resource to start/stop
   @param ret		Unused
 */
int
res_flatten(xmlNode ** xpp, xmlNode * rmp, resource_node_t ** tree, resource_t * res)
{
    return _res_op(xpp, rmp, tree, res, NULL);
}
