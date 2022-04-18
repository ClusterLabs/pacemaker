/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <crm/common/xml.h>
#include <crm/pengine/internal.h>
#include <crm/pengine/status.h>
#include <crm/pengine/pe_types.h>

/* Needed to access replicas inside a bundle. */
#define PE__VARIANT_BUNDLE 1
#include <lib/pengine/variant.h>

xmlNode *input = NULL;
pe_working_set_t *data_set = NULL;

pe_node_t *cluster01, *cluster02, *httpd_bundle_0;
pe_resource_t *exim_group, *inactive_group, *promotable_clone, *inactive_clone;
pe_resource_t *httpd_bundle, *mysql_clone_group;

static int
setup(void **state) {
    char *path = NULL;

    crm_xml_init();

    path = crm_strdup_printf("%s/crm_mon.xml", getenv("PCMK_CTS_CLI_DIR"));
    input = filename2xml(path);
    free(path);

    if (input == NULL) {
        return 1;
    }

    data_set = pe_new_working_set();

    if (data_set == NULL) {
        return 1;
    }

    pe__set_working_set_flags(data_set, pe_flag_no_counts|pe_flag_no_compat);
    data_set->input = input;

    cluster_status(data_set);

    /* Get references to the cluster nodes so we don't have to find them repeatedly. */
    cluster01 = pe_find_node(data_set->nodes, "cluster01");
    cluster02 = pe_find_node(data_set->nodes, "cluster02");
    httpd_bundle_0 = pe_find_node(data_set->nodes, "httpd-bundle-0");

    /* Get references to several resources we use frequently. */
    for (GList *iter = data_set->resources; iter != NULL; iter = iter->next) {
        pe_resource_t *rsc = (pe_resource_t *) iter->data;

        if (strcmp(rsc->id, "exim-group") == 0) {
            exim_group = rsc;
        } else if (strcmp(rsc->id, "httpd-bundle") == 0) {
            httpd_bundle = rsc;
        } else if (strcmp(rsc->id, "inactive-clone") == 0) {
            inactive_clone = rsc;
        } else if (strcmp(rsc->id, "inactive-group") == 0) {
            inactive_group = rsc;
        } else if (strcmp(rsc->id, "mysql-clone-group") == 0) {
            mysql_clone_group = rsc;
        } else if (strcmp(rsc->id, "promotable-clone") == 0) {
            promotable_clone = rsc;
        }
    }

    return 0;
}

static int
teardown(void **state) {
    pe_free_working_set(data_set);

    return 0;
}

static void
bad_args(void **state) {
    pe_resource_t *rsc = (pe_resource_t *) g_list_first(data_set->resources)->data;
    char *id = rsc->id;
    char *name = NULL;

    assert_non_null(rsc);

    assert_null(native_find_rsc(NULL, "dummy", NULL, 0));
    assert_null(native_find_rsc(rsc, NULL, NULL, 0));

    /* No resources exist with these names. */
    name = crm_strdup_printf("%sX", rsc->id);
    assert_null(native_find_rsc(rsc, name, NULL, 0));
    free(name);

    name = crm_strdup_printf("x%s", rsc->id);
    assert_null(native_find_rsc(rsc, name, NULL, 0));
    free(name);

    name = g_ascii_strup(rsc->id, -1);
    assert_null(native_find_rsc(rsc, name, NULL, 0));
    g_free(name);

    /* Fails because resource ID is NULL. */
    rsc->id = NULL;
    assert_null(native_find_rsc(rsc, id, NULL, 0));
    rsc->id = id;
}

static void
primitive_rsc(void **state) {
    pe_resource_t *dummy = NULL;

    /* Find the "dummy" resource, which is the only one with that ID in the set. */
    for (GList *iter = data_set->resources; iter != NULL; iter = iter->next) {
        pe_resource_t *rsc = (pe_resource_t *) iter->data;

        if (strcmp(rsc->id, "dummy") == 0) {
            dummy = rsc;
            break;
        }
    }

    assert_non_null(dummy);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(dummy, native_find_rsc(dummy, "dummy", NULL, 0));
    assert_ptr_equal(dummy, native_find_rsc(dummy, "dummy", NULL, pe_find_current));

    /* Fails because resource is not a clone (nor cloned). */
    assert_null(native_find_rsc(dummy, "dummy", NULL, pe_find_clone));
    assert_null(native_find_rsc(dummy, "dummy", cluster02, pe_find_clone));

    /* Fails because dummy is not running on cluster01, even with the right flags. */
    assert_null(native_find_rsc(dummy, "dummy", cluster01, pe_find_current));

    /* Fails because pe_find_current is required if a node is given. */
    assert_null(native_find_rsc(dummy, "dummy", cluster02, 0));

    /* Passes because dummy is running on cluster02. */
    assert_ptr_equal(dummy, native_find_rsc(dummy, "dummy", cluster02, pe_find_current));
}

static void
group_rsc(void **state) {
    assert_non_null(exim_group);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(exim_group, native_find_rsc(exim_group, "exim-group", NULL, 0));
    assert_ptr_equal(exim_group, native_find_rsc(exim_group, "exim-group", NULL, pe_find_current));

    /* Fails because resource is not a clone (nor cloned). */
    assert_null(native_find_rsc(exim_group, "exim-group", NULL, pe_find_clone));
    assert_null(native_find_rsc(exim_group, "exim-group", cluster01, pe_find_clone));

    /* Fails because none of exim-group's children are running on cluster01, even with the right flags. */
    assert_null(native_find_rsc(exim_group, "exim-group", cluster01, pe_find_current));

    /* Fails because pe_find_current is required if a node is given. */
    assert_null(native_find_rsc(exim_group, "exim-group", cluster01, 0));

    /* Passes because one of exim-group's children is running on cluster02. */
    assert_ptr_equal(exim_group, native_find_rsc(exim_group, "exim-group", cluster02, pe_find_current));
}

static void
inactive_group_rsc(void **state) {
    assert_non_null(inactive_group);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(inactive_group, native_find_rsc(inactive_group, "inactive-group", NULL, 0));
    assert_ptr_equal(inactive_group, native_find_rsc(inactive_group, "inactive-group", NULL, pe_find_current));
    assert_ptr_equal(inactive_group, native_find_rsc(inactive_group, "inactive-group", NULL, pe_find_inactive));

    /* Fails because resource is not a clone (nor cloned). */
    assert_null(native_find_rsc(inactive_group, "inactive-group", NULL, pe_find_clone));
    assert_null(native_find_rsc(inactive_group, "inactive-group", cluster01, pe_find_clone));

    /* Fails because none of inactive-group's children are running. */
    assert_null(native_find_rsc(inactive_group, "inactive-group", cluster01, pe_find_current));
    assert_null(native_find_rsc(inactive_group, "inactive-group", cluster02, pe_find_current));

    /* Passes because of flags. */
    assert_ptr_equal(inactive_group, native_find_rsc(inactive_group, "inactive-group", cluster01, pe_find_inactive));
    /* Passes because of flags. */
    assert_ptr_equal(inactive_group, native_find_rsc(inactive_group, "inactive-group", cluster02, pe_find_inactive));
}

static void
group_member_rsc(void **state) {
    pe_resource_t *public_ip = NULL;

    /* Find the "Public-IP" resource, a member of "exim-group". */
    for (GList *iter = exim_group->children; iter != NULL; iter = iter->next) {
        pe_resource_t *rsc = (pe_resource_t *) iter->data;

        if (strcmp(rsc->id, "Public-IP") == 0) {
            public_ip = rsc;
            break;
        }
    }

    assert_non_null(public_ip);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(public_ip, native_find_rsc(public_ip, "Public-IP", NULL, 0));
    assert_ptr_equal(public_ip, native_find_rsc(public_ip, "Public-IP", NULL, pe_find_current));

    /* Fails because resource is not a clone (nor cloned). */
    assert_null(native_find_rsc(public_ip, "Public-IP", NULL, pe_find_clone));
    assert_null(native_find_rsc(public_ip, "Public-IP", cluster02, pe_find_clone));

    /* Fails because Public-IP is not running on cluster01, even with the right flags. */
    assert_null(native_find_rsc(public_ip, "Public-IP", cluster01, pe_find_current));

    /* Fails because pe_find_current is required if a node is given. */
    assert_null(native_find_rsc(public_ip, "Public-IP", cluster02, 0));

    /* Passes because Public-IP is running on cluster02. */
    assert_ptr_equal(public_ip, native_find_rsc(public_ip, "Public-IP", cluster02, pe_find_current));
}

static void
inactive_group_member_rsc(void **state) {
    pe_resource_t *inactive_dummy_1 = NULL;

    /* Find the "inactive-dummy-1" resource, a member of "inactive-group". */
    for (GList *iter = inactive_group->children; iter != NULL; iter = iter->next) {
        pe_resource_t *rsc = (pe_resource_t *) iter->data;

        if (strcmp(rsc->id, "inactive-dummy-1") == 0) {
            inactive_dummy_1 = rsc;
            break;
        }
    }

    assert_non_null(inactive_dummy_1);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(inactive_dummy_1, native_find_rsc(inactive_dummy_1, "inactive-dummy-1", NULL, 0));
    assert_ptr_equal(inactive_dummy_1, native_find_rsc(inactive_dummy_1, "inactive-dummy-1", NULL, pe_find_current));

    /* Fails because resource is not a clone (nor cloned). */
    assert_null(native_find_rsc(inactive_dummy_1, "inactive-dummy-1", NULL, pe_find_clone));
    assert_null(native_find_rsc(inactive_dummy_1, "inactive-dummy-1", cluster01, pe_find_clone));

    /* Fails because inactive-dummy-1 is not running. */
    assert_null(native_find_rsc(inactive_dummy_1, "inactive-dummy-1", cluster01, pe_find_current));
    assert_null(native_find_rsc(inactive_dummy_1, "inactive-dummy-1", cluster02, pe_find_current));

    /* Passes because of flags. */
    assert_ptr_equal(inactive_dummy_1, native_find_rsc(inactive_dummy_1, "inactive-dummy-1", cluster01, pe_find_inactive));
    /* Passes because of flags. */
    assert_ptr_equal(inactive_dummy_1, native_find_rsc(inactive_dummy_1, "inactive-dummy-1", cluster02, pe_find_inactive));
}

static void
clone_rsc(void **state) {
    assert_non_null(promotable_clone);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(promotable_clone, native_find_rsc(promotable_clone, "promotable-clone", NULL, 0));
    assert_ptr_equal(promotable_clone, native_find_rsc(promotable_clone, "promotable-clone", NULL, pe_find_current));
    assert_ptr_equal(promotable_clone, native_find_rsc(promotable_clone, "promotable-clone", NULL, pe_find_clone));

    /* Fails because pe_find_current is required if a node is given. */
    assert_null(native_find_rsc(promotable_clone, "promotable-clone", cluster01, 0));

    /* Passes because one of ping-clone's children is running on cluster01. */
    assert_ptr_equal(promotable_clone, native_find_rsc(promotable_clone, "promotable-clone", cluster01, pe_find_current));

    /* Fails because pe_find_current is required if a node is given. */
    assert_null(native_find_rsc(promotable_clone, "promotable-clone", cluster02, 0));

    /* Passes because one of ping_clone's children is running on cluster02. */
    assert_ptr_equal(promotable_clone, native_find_rsc(promotable_clone, "promotable-clone", cluster02, pe_find_current));

    /* Passes for previous reasons, plus includes pe_find_clone check. */
    assert_ptr_equal(promotable_clone, native_find_rsc(promotable_clone, "promotable-clone", cluster01, pe_find_clone|pe_find_current));
    assert_ptr_equal(promotable_clone, native_find_rsc(promotable_clone, "promotable-clone", cluster02, pe_find_clone|pe_find_current));
}

static void
inactive_clone_rsc(void **state) {
    assert_non_null(inactive_clone);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(inactive_clone, native_find_rsc(inactive_clone, "inactive-clone", NULL, 0));
    assert_ptr_equal(inactive_clone, native_find_rsc(inactive_clone, "inactive-clone", NULL, pe_find_current));
    assert_ptr_equal(inactive_clone, native_find_rsc(inactive_clone, "inactive-clone", NULL, pe_find_clone));
    assert_ptr_equal(inactive_clone, native_find_rsc(inactive_clone, "inactive-clone", NULL, pe_find_inactive));

    /* Fails because none of inactive-clone's children are running. */
    assert_null(native_find_rsc(inactive_clone, "inactive-clone", cluster01, pe_find_current|pe_find_clone));
    assert_null(native_find_rsc(inactive_clone, "inactive-clone", cluster02, pe_find_current|pe_find_clone));

    /* Passes because of flags. */
    assert_ptr_equal(inactive_clone, native_find_rsc(inactive_clone, "inactive-clone", cluster01, pe_find_inactive));
    /* Passes because of flags. */
    assert_ptr_equal(inactive_clone, native_find_rsc(inactive_clone, "inactive-clone", cluster02, pe_find_inactive));
}

static void
clone_instance_rsc(void **state) {
    pe_resource_t *promotable_0 = NULL;
    pe_resource_t *promotable_1 = NULL;

    /* Find the "promotable-rsc:0" and "promotable-rsc:1" resources, members of "promotable-clone". */
    for (GList *iter = promotable_clone->children; iter != NULL; iter = iter->next) {
        pe_resource_t *rsc = (pe_resource_t *) iter->data;

        if (strcmp(rsc->id, "promotable-rsc:0") == 0) {
            promotable_0 = rsc;
        } else if (strcmp(rsc->id, "promotable-rsc:1") == 0) {
            promotable_1 = rsc;
        }
    }

    assert_non_null(promotable_0);
    assert_non_null(promotable_1);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(promotable_0, native_find_rsc(promotable_0, "promotable-rsc:0", NULL, 0));
    assert_ptr_equal(promotable_0, native_find_rsc(promotable_0, "promotable-rsc:0", NULL, pe_find_current));
    assert_ptr_equal(promotable_1, native_find_rsc(promotable_1, "promotable-rsc:1", NULL, 0));
    assert_ptr_equal(promotable_1, native_find_rsc(promotable_1, "promotable-rsc:1", NULL, pe_find_current));

    /* Fails because pe_find_current is required if a node is given. */
    assert_null(native_find_rsc(promotable_0, "promotable-rsc:0", cluster02, 0));
    assert_null(native_find_rsc(promotable_1, "promotable-rsc:1", cluster01, 0));

    /* Check that the resource is running on the node we expect. */
    assert_ptr_equal(promotable_0, native_find_rsc(promotable_0, "promotable-rsc:0", cluster02, pe_find_current));
    assert_null(native_find_rsc(promotable_0, "promotable-rsc:0", cluster01, pe_find_current));
    assert_ptr_equal(promotable_1, native_find_rsc(promotable_1, "promotable-rsc:1", cluster01, pe_find_current));
    assert_null(native_find_rsc(promotable_1, "promotable-rsc:1", cluster02, pe_find_current));

    /* Passes because NULL was passed for node and primitive name was given, with correct flags. */
    assert_ptr_equal(promotable_0, native_find_rsc(promotable_0, "promotable-rsc", NULL, pe_find_clone));

    /* Passes because pe_find_any matches any instance's base name. */
    assert_ptr_equal(promotable_0, native_find_rsc(promotable_0, "promotable-rsc", NULL, pe_find_any));
    assert_ptr_equal(promotable_1, native_find_rsc(promotable_1, "promotable-rsc", NULL, pe_find_any));

    /* Passes because pe_find_anon matches. */
    assert_ptr_equal(promotable_0, native_find_rsc(promotable_0, "promotable-rsc", NULL, pe_find_anon));
    assert_ptr_equal(promotable_1, native_find_rsc(promotable_1, "promotable-rsc", NULL, pe_find_anon));

    /* Check that the resource is running on the node we expect. */
    assert_ptr_equal(promotable_0, native_find_rsc(promotable_0, "promotable-rsc", cluster02, pe_find_any|pe_find_current));
    assert_ptr_equal(promotable_0, native_find_rsc(promotable_0, "promotable-rsc", cluster02, pe_find_anon|pe_find_current));
    assert_null(native_find_rsc(promotable_0, "promotable-rsc", cluster01, pe_find_any|pe_find_current));
    assert_null(native_find_rsc(promotable_0, "promotable-rsc", cluster01, pe_find_anon|pe_find_current));
    assert_ptr_equal(promotable_1, native_find_rsc(promotable_1, "promotable-rsc", cluster01, pe_find_any|pe_find_current));
    assert_ptr_equal(promotable_1, native_find_rsc(promotable_1, "promotable-rsc", cluster01, pe_find_anon|pe_find_current));
    assert_null(native_find_rsc(promotable_1, "promotable-rsc", cluster02, pe_find_any|pe_find_current));
    assert_null(native_find_rsc(promotable_1, "promotable-rsc", cluster02, pe_find_anon|pe_find_current));

    /* Fails because incorrect flags were given along with primitive name. */
    assert_null(native_find_rsc(promotable_0, "promotable-rsc", NULL, pe_find_current));
    assert_null(native_find_rsc(promotable_1, "promotable-rsc", NULL, pe_find_current));

    /* And then we check failure possibilities again, except passing promotable_clone
     * instead of promotable_X as the first argument to native_find_rsc.
     */

    /* Fails because pe_find_current is required if a node is given. */
    assert_null(native_find_rsc(promotable_clone, "promotable-rsc:0", cluster02, 0));
    assert_null(native_find_rsc(promotable_clone, "promotable-rsc:1", cluster01, 0));

    /* Check that the resource is running on the node we expect. */
    assert_ptr_equal(promotable_0, native_find_rsc(promotable_clone, "promotable-rsc:0", cluster02, pe_find_current));
    assert_ptr_equal(promotable_0, native_find_rsc(promotable_clone, "promotable-rsc", cluster02, pe_find_any|pe_find_current));
    assert_ptr_equal(promotable_0, native_find_rsc(promotable_clone, "promotable-rsc", cluster02, pe_find_anon|pe_find_current));
    assert_ptr_equal(promotable_1, native_find_rsc(promotable_clone, "promotable-rsc:1", cluster01, pe_find_current));
    assert_ptr_equal(promotable_1, native_find_rsc(promotable_clone, "promotable-rsc", cluster01, pe_find_any|pe_find_current));
    assert_ptr_equal(promotable_1, native_find_rsc(promotable_clone, "promotable-rsc", cluster01, pe_find_anon|pe_find_current));
}

static void
renamed_rsc(void **state) {
    pe_resource_t *promotable_0 = NULL;
    pe_resource_t *promotable_1 = NULL;

    /* Find the "promotable-rsc:0" and "promotable-rsc:1" resources, members of "promotable-clone". */
    for (GList *iter = promotable_clone->children; iter != NULL; iter = iter->next) {
        pe_resource_t *rsc = (pe_resource_t *) iter->data;

        if (strcmp(rsc->id, "promotable-rsc:0") == 0) {
            promotable_0 = rsc;
        } else if (strcmp(rsc->id, "promotable-rsc:1") == 0) {
            promotable_1 = rsc;
        }
    }

    assert_non_null(promotable_0);
    assert_non_null(promotable_1);

    /* Passes because pe_find_renamed means the base name matches clone_name. */
    assert_ptr_equal(promotable_0, native_find_rsc(promotable_0, "promotable-rsc", NULL, pe_find_renamed));
    assert_ptr_equal(promotable_1, native_find_rsc(promotable_1, "promotable-rsc", NULL, pe_find_renamed));
}

static void
bundle_rsc(void **state) {
    assert_non_null(httpd_bundle);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(httpd_bundle, native_find_rsc(httpd_bundle, "httpd-bundle", NULL, 0));
    assert_ptr_equal(httpd_bundle, native_find_rsc(httpd_bundle, "httpd-bundle", NULL, pe_find_current));

    /* Fails because resource is not a clone (nor cloned). */
    assert_null(native_find_rsc(httpd_bundle, "httpd-bundle", NULL, pe_find_clone));
    assert_null(native_find_rsc(httpd_bundle, "httpd-bundle", cluster01, pe_find_clone));

    /* Fails because pe_find_current is required if a node is given. */
    assert_null(native_find_rsc(httpd_bundle, "httpd-bundle", cluster01, 0));

    /* Passes because one of httpd_bundle's children is running on cluster01. */
    assert_ptr_equal(httpd_bundle, native_find_rsc(httpd_bundle, "httpd-bundle", cluster01, pe_find_current));
}

static void
bundle_replica_rsc(void **state) {
    pe__bundle_variant_data_t *bundle_data = NULL;
    pe__bundle_replica_t *replica_0 = NULL;

    pe_resource_t *ip_0 = NULL;
    pe_resource_t *child_0 = NULL;
    pe_resource_t *container_0 = NULL;
    pe_resource_t *remote_0 = NULL;

    get_bundle_variant_data(bundle_data, httpd_bundle);
    replica_0 = (pe__bundle_replica_t *) bundle_data->replicas->data;

    ip_0 = replica_0->ip;
    child_0 = replica_0->child;
    container_0 = replica_0->container;
    remote_0 = replica_0->remote;

    assert_non_null(ip_0);
    assert_non_null(child_0);
    assert_non_null(container_0);
    assert_non_null(remote_0);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(ip_0, native_find_rsc(ip_0, "httpd-bundle-ip-192.168.122.131", NULL, 0));
    assert_ptr_equal(child_0, native_find_rsc(child_0, "httpd:0", NULL, 0));
    assert_ptr_equal(container_0, native_find_rsc(container_0, "httpd-bundle-docker-0", NULL, 0));
    assert_ptr_equal(remote_0, native_find_rsc(remote_0, "httpd-bundle-0", NULL, 0));

    /* Fails because pe_find_current is required if a node is given. */
    assert_null(native_find_rsc(ip_0, "httpd-bundle-ip-192.168.122.131", cluster01, 0));
    assert_null(native_find_rsc(child_0, "httpd:0", httpd_bundle_0, 0));
    assert_null(native_find_rsc(container_0, "httpd-bundle-docker-0", cluster01, 0));
    assert_null(native_find_rsc(remote_0, "httpd-bundle-0", cluster01, 0));

    /* Check that the resource is running on the node we expect. */
    assert_ptr_equal(ip_0, native_find_rsc(ip_0, "httpd-bundle-ip-192.168.122.131", cluster01, pe_find_current));
    assert_null(native_find_rsc(ip_0, "httpd-bundle-ip-192.168.122.131", cluster02, pe_find_current));
    assert_null(native_find_rsc(ip_0, "httpd-bundle-ip-192.168.122.131", httpd_bundle_0, pe_find_current));
    assert_ptr_equal(child_0, native_find_rsc(child_0, "httpd:0", httpd_bundle_0, pe_find_current));
    assert_null(native_find_rsc(child_0, "httpd:0", cluster01, pe_find_current));
    assert_null(native_find_rsc(child_0, "httpd:0", cluster02, pe_find_current));
    assert_ptr_equal(container_0, native_find_rsc(container_0, "httpd-bundle-docker-0", cluster01, pe_find_current));
    assert_null(native_find_rsc(container_0, "httpd-bundle-docker-0", cluster02, pe_find_current));
    assert_null(native_find_rsc(container_0, "httpd-bundle-docker-0", httpd_bundle_0, pe_find_current));
    assert_ptr_equal(remote_0, native_find_rsc(remote_0, "httpd-bundle-0", cluster01, pe_find_current));
    assert_null(native_find_rsc(remote_0, "httpd-bundle-0", cluster02, pe_find_current));
    assert_null(native_find_rsc(remote_0, "httpd-bundle-0", httpd_bundle_0, pe_find_current));

    /* Passes because pe_find_any matches any replica's base name. */
    assert_ptr_equal(child_0, native_find_rsc(child_0, "httpd", NULL, pe_find_any));

    /* Passes because pe_find_anon matches. */
    assert_ptr_equal(child_0, native_find_rsc(child_0, "httpd", NULL, pe_find_anon));

    /* Check that the resource is running on the node we expect. */
    assert_ptr_equal(child_0, native_find_rsc(child_0, "httpd", httpd_bundle_0, pe_find_any|pe_find_current));
    assert_ptr_equal(child_0, native_find_rsc(child_0, "httpd", httpd_bundle_0, pe_find_anon|pe_find_current));
    assert_null(native_find_rsc(child_0, "httpd", cluster01, pe_find_any|pe_find_current));
    assert_null(native_find_rsc(child_0, "httpd", cluster01, pe_find_anon|pe_find_current));
    assert_null(native_find_rsc(child_0, "httpd", cluster02, pe_find_any|pe_find_current));
    assert_null(native_find_rsc(child_0, "httpd", cluster02, pe_find_anon|pe_find_current));

    /* Fails because incorrect flags were given along with base name. */
    assert_null(native_find_rsc(child_0, "httpd", NULL, pe_find_current));

    /* And then we check failure possibilities again, except passing httpd-bundle
     * instead of X_0 as the first argument to native_find_rsc.
     */

    /* Fails because pe_find_current is required if a node is given. */
    assert_null(native_find_rsc(httpd_bundle, "httpd-bundle-ip-192.168.122.131", cluster01, 0));
    assert_null(native_find_rsc(httpd_bundle, "httpd:0", httpd_bundle_0, 0));
    assert_null(native_find_rsc(httpd_bundle, "httpd-bundle-docker-0", cluster01, 0));
    assert_null(native_find_rsc(httpd_bundle, "httpd-bundle-0", cluster01, 0));

    /* Check that the resource is running on the node we expect. */
    assert_ptr_equal(ip_0, native_find_rsc(httpd_bundle, "httpd-bundle-ip-192.168.122.131", cluster01, pe_find_current));
    assert_ptr_equal(child_0, native_find_rsc(httpd_bundle, "httpd:0", httpd_bundle_0, pe_find_current));
    assert_ptr_equal(container_0, native_find_rsc(httpd_bundle, "httpd-bundle-docker-0", cluster01, pe_find_current));
    assert_ptr_equal(remote_0, native_find_rsc(httpd_bundle, "httpd-bundle-0", cluster01, pe_find_current));
}

static void
clone_group_rsc(void **rsc) {
    assert_non_null(mysql_clone_group);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(mysql_clone_group, native_find_rsc(mysql_clone_group, "mysql-clone-group", NULL, 0));
    assert_ptr_equal(mysql_clone_group, native_find_rsc(mysql_clone_group, "mysql-clone-group", NULL, pe_find_current));
    assert_ptr_equal(mysql_clone_group, native_find_rsc(mysql_clone_group, "mysql-clone-group", NULL, pe_find_clone));

    /* Fails because pe_find_current is required if a node is given. */
    assert_null(native_find_rsc(mysql_clone_group, "mysql-clone-group", cluster01, 0));

    /* Passes because one of mysql-clone-group's children is running on cluster01. */
    assert_ptr_equal(mysql_clone_group, native_find_rsc(mysql_clone_group, "mysql-clone-group", cluster01, pe_find_current));

    /* Fails because pe_find_current is required if a node is given. */
    assert_null(native_find_rsc(mysql_clone_group, "mysql-clone-group", cluster02, 0));

    /* Passes because one of mysql-clone-group's children is running on cluster02. */
    assert_ptr_equal(mysql_clone_group, native_find_rsc(mysql_clone_group, "mysql-clone-group", cluster02, pe_find_current));

    /* Passes for previous reasons, plus includes pe_find_clone check. */
    assert_ptr_equal(mysql_clone_group, native_find_rsc(mysql_clone_group, "mysql-clone-group", cluster01, pe_find_clone|pe_find_current));
    assert_ptr_equal(mysql_clone_group, native_find_rsc(mysql_clone_group, "mysql-clone-group", cluster02, pe_find_clone|pe_find_current));
}

static void
clone_group_instance_rsc(void **rsc) {
    pe_resource_t *mysql_group_0 = NULL;
    pe_resource_t *mysql_group_1 = NULL;

    /* Find the "mysql-group:0" and "mysql-group:1" resources, members of "mysql-clone-group". */
    for (GList *iter = mysql_clone_group->children; iter != NULL; iter = iter->next) {
        pe_resource_t *rsc = (pe_resource_t *) iter->data;

        if (strcmp(rsc->id, "mysql-group:0") == 0) {
            mysql_group_0 = rsc;
        } else if (strcmp(rsc->id, "mysql-group:1") == 0) {
            mysql_group_1 = rsc;
        }
    }

    assert_non_null(mysql_group_0);
    assert_non_null(mysql_group_1);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(mysql_group_0, native_find_rsc(mysql_group_0, "mysql-group:0", NULL, 0));
    assert_ptr_equal(mysql_group_0, native_find_rsc(mysql_group_0, "mysql-group:0", NULL, pe_find_current));
    assert_ptr_equal(mysql_group_1, native_find_rsc(mysql_group_1, "mysql-group:1", NULL, 0));
    assert_ptr_equal(mysql_group_1, native_find_rsc(mysql_group_1, "mysql-group:1", NULL, pe_find_current));

    /* Fails because pe_find_current is required if a node is given. */
    assert_null(native_find_rsc(mysql_group_0, "mysql-group:0", cluster02, 0));
    assert_null(native_find_rsc(mysql_group_1, "mysql-group:1", cluster01, 0));

    /* Check that the resource is running on the node we expect. */
    assert_ptr_equal(mysql_group_0, native_find_rsc(mysql_group_0, "mysql-group:0", cluster02, pe_find_current));
    assert_null(native_find_rsc(mysql_group_0, "mysql-group:0", cluster01, pe_find_current));
    assert_ptr_equal(mysql_group_1, native_find_rsc(mysql_group_1, "mysql-group:1", cluster01, pe_find_current));
    assert_null(native_find_rsc(mysql_group_1, "mysql-group:1", cluster02, pe_find_current));

    /* Passes because NULL was passed for node and base name was given, with correct flags. */
    assert_ptr_equal(mysql_group_0, native_find_rsc(mysql_group_0, "mysql-group" , NULL, pe_find_clone));

    /* Passes because pe_find_any matches any base name. */
    assert_ptr_equal(mysql_group_0, native_find_rsc(mysql_group_0, "mysql-group" , NULL, pe_find_any));
    assert_ptr_equal(mysql_group_1, native_find_rsc(mysql_group_1, "mysql-group" , NULL, pe_find_any));

    /* Passes because pe_find_anon matches. */
    assert_ptr_equal(mysql_group_0, native_find_rsc(mysql_group_0, "mysql-group" , NULL, pe_find_anon));
    assert_ptr_equal(mysql_group_1, native_find_rsc(mysql_group_1, "mysql-group" , NULL, pe_find_anon));

    /* Check that the resource is running on the node we expect. */
    assert_ptr_equal(mysql_group_0, native_find_rsc(mysql_group_0, "mysql-group", cluster02, pe_find_any|pe_find_current));
    assert_ptr_equal(mysql_group_0, native_find_rsc(mysql_group_0, "mysql-group", cluster02, pe_find_anon|pe_find_current));
    assert_null(native_find_rsc(mysql_group_0, "mysql-group", cluster01, pe_find_any|pe_find_current));
    assert_null(native_find_rsc(mysql_group_0, "mysql-group", cluster01, pe_find_anon|pe_find_current));
    assert_ptr_equal(mysql_group_1, native_find_rsc(mysql_group_1, "mysql-group", cluster01, pe_find_any|pe_find_current));
    assert_ptr_equal(mysql_group_1, native_find_rsc(mysql_group_1, "mysql-group", cluster01, pe_find_anon|pe_find_current));
    assert_null(native_find_rsc(mysql_group_1, "mysql-group", cluster02, pe_find_any|pe_find_current));
    assert_null(native_find_rsc(mysql_group_1, "mysql-group", cluster02, pe_find_anon|pe_find_current));

    /* Fails because incorrect flags were given along with base name. */
    assert_null(native_find_rsc(mysql_group_0, "mysql-group", NULL, pe_find_current));
    assert_null(native_find_rsc(mysql_group_1, "mysql-group", NULL, pe_find_current));

    /* And then we check failure possibilities again, except passing mysql_clone_group
     * instead of mysql_group_X as the first argument to native_find_rsc.
     */

    /* Fails because pe_find_current is required if a node is given. */
    assert_null(native_find_rsc(mysql_clone_group, "mysql-group:0", cluster02, 0));
    assert_null(native_find_rsc(mysql_clone_group, "mysql-group:1", cluster01, 0));

    /* Check that the resource is running on the node we expect. */
    assert_ptr_equal(mysql_group_0, native_find_rsc(mysql_clone_group, "mysql-group:0", cluster02, pe_find_current));
    assert_ptr_equal(mysql_group_0, native_find_rsc(mysql_clone_group, "mysql-group", cluster02, pe_find_any|pe_find_current));
    assert_ptr_equal(mysql_group_0, native_find_rsc(mysql_clone_group, "mysql-group", cluster02, pe_find_anon|pe_find_current));
    assert_ptr_equal(mysql_group_1, native_find_rsc(mysql_clone_group, "mysql-group:1", cluster01, pe_find_current));
    assert_ptr_equal(mysql_group_1, native_find_rsc(mysql_clone_group, "mysql-group", cluster01, pe_find_any|pe_find_current));
    assert_ptr_equal(mysql_group_1, native_find_rsc(mysql_clone_group, "mysql-group", cluster01, pe_find_anon|pe_find_current));
}

static void
clone_group_member_rsc(void **state) {
    pe_resource_t *mysql_proxy = NULL;

    /* Find the "mysql-proxy" resource, a member of "mysql-group". */
    for (GList *iter = mysql_clone_group->children; iter != NULL; iter = iter->next) {
        pe_resource_t *rsc = (pe_resource_t *) iter->data;

        if (strcmp(rsc->id, "mysql-group:0") == 0) {
            for (GList *iter2 = rsc->children; iter2 != NULL; iter2 = iter2->next) {
                pe_resource_t *child = (pe_resource_t *) iter2->data;

                if (strcmp(child->id, "mysql-proxy:0") == 0) {
                    mysql_proxy = child;
                    break;
                }
            }

            break;
        }
    }

    assert_non_null(mysql_proxy);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(mysql_proxy, native_find_rsc(mysql_proxy, "mysql-proxy:0", NULL, 0));
    assert_ptr_equal(mysql_proxy, native_find_rsc(mysql_proxy, "mysql-proxy:0", NULL, pe_find_current));

    /* Passes because resource's parent is a clone. */
    assert_ptr_equal(mysql_proxy, native_find_rsc(mysql_proxy, "mysql-proxy:0", NULL, pe_find_clone));
    assert_ptr_equal(mysql_proxy, native_find_rsc(mysql_proxy, "mysql-proxy:0", cluster02, pe_find_clone|pe_find_current));

    /* Fails because mysql-proxy:0 is not running on cluster01, even with the right flags. */
    assert_null(native_find_rsc(mysql_proxy, "mysql-proxy:0", cluster01, pe_find_current));

    /* Fails because pe_find_current is required if a node is given. */
    assert_null(native_find_rsc(mysql_proxy, "mysql-proxy:0", cluster02, 0));

    /* Passes because mysql-proxy:0 is running on cluster02. */
    assert_ptr_equal(mysql_proxy, native_find_rsc(mysql_proxy, "mysql-proxy:0", cluster02, pe_find_current));
}

int main(int argc, char **argv) {
    /* TODO: Add tests for finding on allocated node (passing a node without
     * pe_find_current, after scheduling, for a resource that is starting/stopping/moving.
     */

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(bad_args),
        cmocka_unit_test(primitive_rsc),
        cmocka_unit_test(group_rsc),
        cmocka_unit_test(inactive_group_rsc),
        cmocka_unit_test(group_member_rsc),
        cmocka_unit_test(inactive_group_member_rsc),
        cmocka_unit_test(clone_rsc),
        cmocka_unit_test(inactive_clone_rsc),
        cmocka_unit_test(clone_instance_rsc),
        cmocka_unit_test(renamed_rsc),
        cmocka_unit_test(bundle_rsc),
        cmocka_unit_test(bundle_replica_rsc),
        cmocka_unit_test(clone_group_rsc),
        cmocka_unit_test(clone_group_instance_rsc),
        cmocka_unit_test(clone_group_member_rsc),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, setup, teardown);
}
