/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PENGINE_COMPLEX__H
#  define PENGINE_COMPLEX__H

#  define n_object_classes 3

/*#define PE_OBJ_F_	""*/

#  define PE_OBJ_T_NATIVE	"native"
#  define PE_OBJ_T_GROUP	"group"
#  define PE_OBJ_T_INCARNATION	"clone"
#  define PE_OBJ_T_MASTER	"master"

enum pe_obj_types {
    pe_unknown = -1,
    pe_native = 0,
    pe_group = 1,
    pe_clone = 2,
    pe_master = 3,
    pe_container = 4,
};

enum pe_obj_types get_resource_type(const char *name);
const char *get_resource_typename(enum pe_obj_types type);

typedef struct resource_object_functions_s {
    gboolean(*unpack) (resource_t *, pe_working_set_t *);
    resource_t *(*find_rsc) (resource_t * parent, const char *search, node_t * node, int flags);
    /* parameter result must be free'd */
    char *(*parameter) (resource_t *, node_t *, gboolean, const char *, pe_working_set_t *);
    void (*print) (resource_t *, const char *, long, void *);
     gboolean(*active) (resource_t *, gboolean);
    enum rsc_role_e (*state) (const resource_t *, gboolean);
    pe_node_t *(*location) (const pe_resource_t*, GList**, int);
    void (*free) (resource_t *);
} resource_object_functions_t;

extern resource_object_functions_t resource_class_functions[];
void get_meta_attributes(GHashTable * meta_hash, resource_t * rsc, node_t * node,
                         pe_working_set_t * data_set);
void get_rsc_attributes(GHashTable * meta_hash, resource_t * rsc, node_t * node,
                        pe_working_set_t * data_set);

#ifdef ENABLE_VERSIONED_ATTRS
void pe_get_versioned_attributes(xmlNode * meta_hash, resource_t * rsc, node_t * node,
                                 pe_working_set_t * data_set);
#endif

typedef struct resource_alloc_functions_s resource_alloc_functions_t;

gboolean is_parent(resource_t *child, resource_t *rsc);
resource_t *uber_parent(resource_t * rsc);

#endif
