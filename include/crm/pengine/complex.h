/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PENGINE_COMPLEX__H
#  define PENGINE_COMPLEX__H

#ifdef __cplusplus
extern "C" {
#endif

enum pe_obj_types {
    pe_unknown = -1,
    pe_native = 0,
    pe_group = 1,
    pe_clone = 2,
    pe_container = 3,
};

typedef struct resource_object_functions_s {
    gboolean (*unpack) (pe_resource_t*, pe_working_set_t*);
    pe_resource_t *(*find_rsc) (pe_resource_t *parent, const char *search,
                                const pe_node_t *node, int flags);
    /* parameter result must be free'd */
    char *(*parameter) (pe_resource_t*, pe_node_t*, gboolean, const char*,
                        pe_working_set_t*);
    void (*print) (pe_resource_t*, const char*, long, void*);
    gboolean (*active) (pe_resource_t*, gboolean);
    enum rsc_role_e (*state) (const pe_resource_t*, gboolean);
    pe_node_t *(*location) (const pe_resource_t*, GList**, int);
    void (*free) (pe_resource_t*);
} resource_object_functions_t;

extern resource_object_functions_t resource_class_functions[];
void get_meta_attributes(GHashTable * meta_hash, pe_resource_t *rsc,
                         pe_node_t *node, pe_working_set_t *data_set);
void get_rsc_attributes(GHashTable *meta_hash, pe_resource_t *rsc,
                        pe_node_t *node, pe_working_set_t *data_set);

#ifdef ENABLE_VERSIONED_ATTRS
void pe_get_versioned_attributes(xmlNode *meta_hash, pe_resource_t *rsc,
                                 pe_node_t *node, pe_working_set_t *data_set);
#endif

typedef struct resource_alloc_functions_s resource_alloc_functions_t;

gboolean is_parent(pe_resource_t *child, pe_resource_t *rsc);
pe_resource_t *uber_parent(pe_resource_t *rsc);

#ifdef __cplusplus
}
#endif

#endif
