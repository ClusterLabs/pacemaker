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
#ifndef _RESLIST_H
#  define _RESLIST_H

#  include <stdint.h>
#  include <libxml/parser.h>
#  include <libxml/xmlmemory.h>
#  include <libxml/xpath.h>

#  define RA_PRIMARY	(1<<0)  /** Primary key */
#  define RA_UNIQUE	(1<<1)  /** Unique for given type */
#  define RA_REQUIRED	(1<<2)  /** Required (or an error if not present */
#  define RA_INHERIT	(1<<3)  /** Inherit a parent resource's attr */
#  define RA_RECONFIG	(1<<4)  /** Allow inline reconfiguration */

#  define RF_INLINE	(1<<0)
#  define RF_DEFINED	(1<<1)
#  define RF_NEEDSTART	(1<<2)  /** Used when adding/changing resources */
#  define RF_NEEDSTOP	(1<<3)  /** Used when deleting/changing resources */
#  define RF_COMMON	(1<<4)  /** " */
#  define RF_INDEPENDENT	(1<<5)
                                /** Define this for a resource if it is
				  otherwise an independent subtree */
#  define RF_RECONFIG	(1<<6)

#  define RF_INIT		(1<<7)
                                /** Resource rule: Initialize this resource
				  class on startup */
#  define RF_DESTROY	(1<<8)  /** Resource rule flag: Destroy this
				  resource class if you delete it from
				  the configuration */
#  define RF_ENFORCE_TIMEOUTS (1<<9)
                                   /** Enforce timeouts for this node */
#  define RF_NON_CRITICAL (1<<10)
                                /** stop this resource if it fails */
#  define RF_QUIESCE	(1<<11) /** don't restart this resource */

#  define RES_STOPPED	(0)
#  define RES_STARTED	(1)
#  define RES_FAILED	(2)
#  define RES_DISABLED	(3)

#  ifndef SHAREDIR
#    define SHAREDIR		"/usr/share/cluster"
#  endif

#  define RESOURCE_ROOTDIR	SHAREDIR
#  define RESOURCE_TREE_ROOT	"//rm"
#  define RESOURCE_BASE		RESOURCE_TREE_ROOT "/resources"
#  define RESOURCE_ROOT_FMT 	RESOURCE_TREE_ROOT "/%s[%d]"

#  define RESOURCE_MAX_LEVELS	100

/* Include OCF definitions */
//#include <res-ocf.h>

typedef struct _resource_attribute {
    char *ra_name;
    char *ra_value;
    int ra_flags;
    int _pad_;
} resource_attr_t;

typedef struct _resource_child {
    char *rc_name;
    int rc_startlevel;
    int rc_stoplevel;
    int rc_forbid;
    int rc_flags;
} resource_child_t;

typedef struct _resource_act {
    char *ra_name;
    time_t ra_timeout;
    time_t ra_last;
    time_t ra_interval;
    int ra_depth;
    int _pad_;
} resource_act_t;

typedef struct _resource_rule {
    list_head();
    char *rr_type;
    char *rr_agent;
    char *rr_version;           /** agent XML spec version; OCF-ism */
    int rr_flags;
    int rr_maxrefs;
    resource_attr_t *rr_attrs;
    resource_child_t *rr_childtypes;
    resource_act_t *rr_actions;
} resource_rule_t;

typedef struct _resource {
    list_head();
    resource_rule_t *r_rule;
    char *r_name;
    resource_attr_t *r_attrs;
    resource_act_t *r_actions;
    int r_flags;
    int r_refs;
    int r_incarnations;         /** Number of instances running locally */
    int _pad_;                  /* align */
} resource_t;

typedef struct _rg_node {
    list_head();
    struct _rg_node *rn_child, *rn_parent;
    resource_t *rn_resource;
    resource_act_t *rn_actions;
    int rn_state;               /* State of this instance of rn_resource */
    int rn_flags;
    int rn_last_status;
    int rn_last_depth;
    int rn_checked;
    int rn_pad;
} resource_node_t;

typedef struct _fod_node {
    list_head();
    char *fdn_name;
    int fdn_prio;
    int fdn_nodeid;             /* on rhel4 this will be 64-bit int */
} fod_node_t;

typedef struct _fod {
    list_head();
    char *fd_name;
    fod_node_t *fd_nodes;
    int fd_flags;
    int _pad_;                  /* align */
} fod_t;

/*
   Exported Functions
 */
int res_flatten(xmlNode ** n, xmlNode * r, resource_node_t ** tree, resource_t * res);

int expand_time(char *val);
int store_action(resource_act_t ** actsp, char *name, int depth, int timeout, int interval);

/*
   Load/kill resource rule sets
 */
int load_resource_rules(const char *rpath, resource_rule_t ** rules);
void destroy_resource_rules(resource_rule_t ** rules);

/*
   Load/kill resource sets
 */
int load_resources(resource_t ** reslist, resource_rule_t ** rulelist);
void dump_resources(FILE * fp, resource_t ** reslist);
void destroy_resources(resource_t ** list);

/*
   Construct/deconstruct resource trees
 */
int build_resource_tree(resource_node_t ** tree,
                        resource_rule_t ** rulelist, resource_t ** reslist);
void destroy_resource_tree(resource_node_t ** tree);

/*
   Construct/deconstruct failover domains
 */
int construct_domains(fod_t ** domains);
void deconstruct_domains(fod_t ** domains);

/*
   Handy functions
 */
resource_t *find_resource_by_ref(resource_t ** reslist, char *type, char *ref);
resource_rule_t *find_rule_by_type(resource_rule_t ** rulelist, char *type);
void res_build_name(char *, size_t, resource_t *);

/*
   Internal functions; shouldn't be needed.
 */
int store_attribute(resource_attr_t ** attrsp, char *name, char *value, int flags);

resource_t *load_resource(resource_rule_t * rule, const char *base);
int store_resource(resource_t ** reslist, resource_t * newres);
void destroy_resource(resource_t * res);

char *attr_value(resource_node_t * node, const char *attrname);
char *res_attr_value(resource_t * res, const char *attrname);
char *primary_attr_value(resource_t *);
void *act_dup(resource_act_t * acts);

#endif                          /* _RESLIST_H */
