/*
 * Copyright 2022-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/scheduler.h>
#include <crm/common/xml.h>
#include <crm/pengine/internal.h>
#include <crm/pengine/status.h>

xmlNode *input = NULL;
pcmk_scheduler_t *scheduler = NULL;

pcmk_node_t *cluster01, *cluster02, *httpd_bundle_0;
pcmk_resource_t *exim_group, *inactive_group;
pcmk_resource_t *promotable_clone, *inactive_clone;
pcmk_resource_t *httpd_bundle, *mysql_clone_group;

static int
setup(void **state) {
    char *path = NULL;

    pcmk__xml_init();

    path = crm_strdup_printf("%s/crm_mon.xml", getenv("PCMK_CTS_CLI_DIR"));
    input = pcmk__xml_read(path);
    free(path);

    if (input == NULL) {
        return 1;
    }

    scheduler = pe_new_working_set();

    if (scheduler == NULL) {
        return 1;
    }

    pcmk__set_scheduler_flags(scheduler, pcmk__sched_no_counts);
    scheduler->input = input;

    pcmk_unpack_scheduler_input(scheduler);

    /* Get references to the cluster nodes so we don't have to find them repeatedly. */
    cluster01 = pcmk_find_node(scheduler, "cluster01");
    cluster02 = pcmk_find_node(scheduler, "cluster02");
    httpd_bundle_0 = pcmk_find_node(scheduler, "httpd-bundle-0");

    /* Get references to several resources we use frequently. */
    for (GList *iter = scheduler->priv->resources;
         iter != NULL; iter = iter->next) {

        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

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
    pe_free_working_set(scheduler);
    pcmk__xml_cleanup();
    return 0;
}

static void
bad_args(void **state) {
    pcmk_resource_t *rsc = g_list_first(scheduler->priv->resources)->data;
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
    pcmk_resource_t *dummy = NULL;

    /* Find the "dummy" resource, which is the only one with that ID in the set. */
    for (GList *iter = scheduler->priv->resources;
         iter != NULL; iter = iter->next) {

        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

        if (strcmp(rsc->id, "dummy") == 0) {
            dummy = rsc;
            break;
        }
    }

    assert_non_null(dummy);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(dummy, native_find_rsc(dummy, "dummy", NULL, 0));
    assert_ptr_equal(dummy,
                     native_find_rsc(dummy, "dummy", NULL,
                                     pcmk_rsc_match_current_node));

    /* Fails because resource is not a clone (nor cloned). */
    assert_null(native_find_rsc(dummy, "dummy", NULL,
                                pcmk_rsc_match_clone_only));
    assert_null(native_find_rsc(dummy, "dummy", cluster02,
                                pcmk_rsc_match_clone_only));

    /* Fails because dummy is not running on cluster01, even with the right flags. */
    assert_null(native_find_rsc(dummy, "dummy", cluster01,
                                pcmk_rsc_match_current_node));

    // Fails because pcmk_rsc_match_current_node is required if a node is given
    assert_null(native_find_rsc(dummy, "dummy", cluster02, 0));

    /* Passes because dummy is running on cluster02. */
    assert_ptr_equal(dummy,
                     native_find_rsc(dummy, "dummy", cluster02,
                                     pcmk_rsc_match_current_node));
}

static void
group_rsc(void **state) {
    assert_non_null(exim_group);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(exim_group, native_find_rsc(exim_group, "exim-group", NULL, 0));
    assert_ptr_equal(exim_group,
                     native_find_rsc(exim_group, "exim-group", NULL,
                                     pcmk_rsc_match_current_node));

    /* Fails because resource is not a clone (nor cloned). */
    assert_null(native_find_rsc(exim_group, "exim-group", NULL,
                                pcmk_rsc_match_clone_only));
    assert_null(native_find_rsc(exim_group, "exim-group", cluster01,
                                pcmk_rsc_match_clone_only));

    /* Fails because none of exim-group's children are running on cluster01, even with the right flags. */
    assert_null(native_find_rsc(exim_group, "exim-group", cluster01,
                                pcmk_rsc_match_current_node));

    // Fails because pcmk_rsc_match_current_node is required if a node is given
    assert_null(native_find_rsc(exim_group, "exim-group", cluster01, 0));

    /* Passes because one of exim-group's children is running on cluster02. */
    assert_ptr_equal(exim_group,
                     native_find_rsc(exim_group, "exim-group", cluster02,
                                     pcmk_rsc_match_current_node));
}

static void
inactive_group_rsc(void **state) {
    assert_non_null(inactive_group);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(inactive_group, native_find_rsc(inactive_group, "inactive-group", NULL, 0));
    assert_ptr_equal(inactive_group,
                     native_find_rsc(inactive_group, "inactive-group", NULL,
                                     pcmk_rsc_match_current_node));

    /* Fails because resource is not a clone (nor cloned). */
    assert_null(native_find_rsc(inactive_group, "inactive-group", NULL,
                                pcmk_rsc_match_clone_only));
    assert_null(native_find_rsc(inactive_group, "inactive-group", cluster01,
                                pcmk_rsc_match_clone_only));

    /* Fails because none of inactive-group's children are running. */
    assert_null(native_find_rsc(inactive_group, "inactive-group", cluster01,
                                pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(inactive_group, "inactive-group", cluster02,
                                pcmk_rsc_match_current_node));
}

static void
group_member_rsc(void **state) {
    pcmk_resource_t *public_ip = NULL;

    /* Find the "Public-IP" resource, a member of "exim-group". */
    for (GList *iter = exim_group->priv->children;
         iter != NULL; iter = iter->next) {

        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

        if (strcmp(rsc->id, "Public-IP") == 0) {
            public_ip = rsc;
            break;
        }
    }

    assert_non_null(public_ip);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(public_ip, native_find_rsc(public_ip, "Public-IP", NULL, 0));
    assert_ptr_equal(public_ip,
                     native_find_rsc(public_ip, "Public-IP", NULL,
                                     pcmk_rsc_match_current_node));

    /* Fails because resource is not a clone (nor cloned). */
    assert_null(native_find_rsc(public_ip, "Public-IP", NULL,
                                pcmk_rsc_match_clone_only));
    assert_null(native_find_rsc(public_ip, "Public-IP", cluster02,
                                pcmk_rsc_match_clone_only));

    /* Fails because Public-IP is not running on cluster01, even with the right flags. */
    assert_null(native_find_rsc(public_ip, "Public-IP", cluster01,
                                pcmk_rsc_match_current_node));

    // Fails because pcmk_rsc_match_current_node is required if a node is given
    assert_null(native_find_rsc(public_ip, "Public-IP", cluster02, 0));

    /* Passes because Public-IP is running on cluster02. */
    assert_ptr_equal(public_ip,
                     native_find_rsc(public_ip, "Public-IP", cluster02,
                                     pcmk_rsc_match_current_node));
}

static void
inactive_group_member_rsc(void **state) {
    pcmk_resource_t *inactive_dummy_1 = NULL;

    /* Find the "inactive-dummy-1" resource, a member of "inactive-group". */
    for (GList *iter = inactive_group->priv->children;
         iter != NULL; iter = iter->next) {

        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

        if (strcmp(rsc->id, "inactive-dummy-1") == 0) {
            inactive_dummy_1 = rsc;
            break;
        }
    }

    assert_non_null(inactive_dummy_1);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(inactive_dummy_1, native_find_rsc(inactive_dummy_1, "inactive-dummy-1", NULL, 0));
    assert_ptr_equal(inactive_dummy_1,
                     native_find_rsc(inactive_dummy_1, "inactive-dummy-1", NULL,
                                     pcmk_rsc_match_current_node));

    /* Fails because resource is not a clone (nor cloned). */
    assert_null(native_find_rsc(inactive_dummy_1, "inactive-dummy-1", NULL,
                                pcmk_rsc_match_clone_only));
    assert_null(native_find_rsc(inactive_dummy_1, "inactive-dummy-1", cluster01,
                                pcmk_rsc_match_clone_only));

    /* Fails because inactive-dummy-1 is not running. */
    assert_null(native_find_rsc(inactive_dummy_1, "inactive-dummy-1", cluster01,
                                pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(inactive_dummy_1, "inactive-dummy-1", cluster02,
                                pcmk_rsc_match_current_node));
}

static void
clone_rsc(void **state) {
    assert_non_null(promotable_clone);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(promotable_clone, native_find_rsc(promotable_clone, "promotable-clone", NULL, 0));
    assert_ptr_equal(promotable_clone,
                     native_find_rsc(promotable_clone, "promotable-clone", NULL,
                                     pcmk_rsc_match_current_node));
    assert_ptr_equal(promotable_clone,
                     native_find_rsc(promotable_clone, "promotable-clone", NULL,
                                     pcmk_rsc_match_clone_only));

    // Fails because pcmk_rsc_match_current_node is required if a node is given
    assert_null(native_find_rsc(promotable_clone, "promotable-clone", cluster01, 0));

    /* Passes because one of ping-clone's children is running on cluster01. */
    assert_ptr_equal(promotable_clone,
                     native_find_rsc(promotable_clone, "promotable-clone",
                                     cluster01, pcmk_rsc_match_current_node));

    // Fails because pcmk_rsc_match_current_node is required if a node is given
    assert_null(native_find_rsc(promotable_clone, "promotable-clone", cluster02, 0));

    /* Passes because one of ping_clone's children is running on cluster02. */
    assert_ptr_equal(promotable_clone,
                     native_find_rsc(promotable_clone, "promotable-clone",
                                     cluster02, pcmk_rsc_match_current_node));

    // Passes for previous reasons, plus includes pcmk_rsc_match_clone_only
    assert_ptr_equal(promotable_clone,
                     native_find_rsc(promotable_clone, "promotable-clone",
                                     cluster01,
                                     pcmk_rsc_match_clone_only
                                     |pcmk_rsc_match_current_node));
    assert_ptr_equal(promotable_clone,
                     native_find_rsc(promotable_clone, "promotable-clone",
                                     cluster02,
                                     pcmk_rsc_match_clone_only
                                     |pcmk_rsc_match_current_node));
}

static void
inactive_clone_rsc(void **state) {
    assert_non_null(inactive_clone);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(inactive_clone, native_find_rsc(inactive_clone, "inactive-clone", NULL, 0));
    assert_ptr_equal(inactive_clone,
                     native_find_rsc(inactive_clone, "inactive-clone", NULL,
                                     pcmk_rsc_match_current_node));
    assert_ptr_equal(inactive_clone,
                     native_find_rsc(inactive_clone, "inactive-clone", NULL,
                                     pcmk_rsc_match_clone_only));

    /* Fails because none of inactive-clone's children are running. */
    assert_null(native_find_rsc(inactive_clone, "inactive-clone", cluster01,
                                pcmk_rsc_match_current_node
                                |pcmk_rsc_match_clone_only));
    assert_null(native_find_rsc(inactive_clone, "inactive-clone", cluster02,
                                pcmk_rsc_match_current_node
                                |pcmk_rsc_match_clone_only));
}

static void
clone_instance_rsc(void **state) {
    pcmk_resource_t *promotable_0 = NULL;
    pcmk_resource_t *promotable_1 = NULL;

    /* Find the "promotable-rsc:0" and "promotable-rsc:1" resources, members of "promotable-clone". */
    for (GList *iter = promotable_clone->priv->children;
         iter != NULL; iter = iter->next) {

        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

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
    assert_ptr_equal(promotable_0,
                     native_find_rsc(promotable_0, "promotable-rsc:0", NULL,
                                     pcmk_rsc_match_current_node));
    assert_ptr_equal(promotable_1, native_find_rsc(promotable_1, "promotable-rsc:1", NULL, 0));
    assert_ptr_equal(promotable_1,
                     native_find_rsc(promotable_1, "promotable-rsc:1", NULL,
                                     pcmk_rsc_match_current_node));

    // Fails because pcmk_rsc_match_current_node is required if a node is given
    assert_null(native_find_rsc(promotable_0, "promotable-rsc:0", cluster02, 0));
    assert_null(native_find_rsc(promotable_1, "promotable-rsc:1", cluster01, 0));

    /* Check that the resource is running on the node we expect. */
    assert_ptr_equal(promotable_0,
                     native_find_rsc(promotable_0, "promotable-rsc:0",
                                     cluster02, pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(promotable_0, "promotable-rsc:0", cluster01,
                                pcmk_rsc_match_current_node));
    assert_ptr_equal(promotable_1,
                     native_find_rsc(promotable_1, "promotable-rsc:1",
                                     cluster01, pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(promotable_1, "promotable-rsc:1", cluster02,
                                pcmk_rsc_match_current_node));

    /* Passes because NULL was passed for node and primitive name was given, with correct flags. */
    assert_ptr_equal(promotable_0,
                     native_find_rsc(promotable_0, "promotable-rsc", NULL,
                                     pcmk_rsc_match_clone_only));

    // Passes because pcmk_rsc_match_basename matches any instance's base name
    assert_ptr_equal(promotable_0,
                     native_find_rsc(promotable_0, "promotable-rsc", NULL,
                                     pcmk_rsc_match_basename));
    assert_ptr_equal(promotable_1,
                     native_find_rsc(promotable_1, "promotable-rsc", NULL,
                                     pcmk_rsc_match_basename));

    // Passes because pcmk_rsc_match_anon_basename matches
    assert_ptr_equal(promotable_0,
                     native_find_rsc(promotable_0, "promotable-rsc", NULL,
                                     pcmk_rsc_match_anon_basename));
    assert_ptr_equal(promotable_1,
                     native_find_rsc(promotable_1, "promotable-rsc", NULL,
                                     pcmk_rsc_match_anon_basename));

    /* Check that the resource is running on the node we expect. */
    assert_ptr_equal(promotable_0,
                     native_find_rsc(promotable_0, "promotable-rsc", cluster02,
                                     pcmk_rsc_match_basename
                                     |pcmk_rsc_match_current_node));
    assert_ptr_equal(promotable_0,
                     native_find_rsc(promotable_0, "promotable-rsc", cluster02,
                                     pcmk_rsc_match_anon_basename
                                     |pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(promotable_0, "promotable-rsc", cluster01,
                                pcmk_rsc_match_basename
                                |pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(promotable_0, "promotable-rsc", cluster01,
                                pcmk_rsc_match_anon_basename
                                |pcmk_rsc_match_current_node));
    assert_ptr_equal(promotable_1,
                     native_find_rsc(promotable_1, "promotable-rsc", cluster01,
                                     pcmk_rsc_match_basename
                                     |pcmk_rsc_match_current_node));
    assert_ptr_equal(promotable_1,
                     native_find_rsc(promotable_1, "promotable-rsc", cluster01,
                                     pcmk_rsc_match_anon_basename
                                     |pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(promotable_1, "promotable-rsc", cluster02,
                                pcmk_rsc_match_basename
                                |pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(promotable_1, "promotable-rsc", cluster02,
                                pcmk_rsc_match_anon_basename
                                |pcmk_rsc_match_current_node));

    /* Fails because incorrect flags were given along with primitive name. */
    assert_null(native_find_rsc(promotable_0, "promotable-rsc", NULL,
                                pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(promotable_1, "promotable-rsc", NULL,
                                pcmk_rsc_match_current_node));

    /* And then we check failure possibilities again, except passing promotable_clone
     * instead of promotable_X as the first argument to native_find_rsc.
     */

    // Fails because pcmk_rsc_match_current_node is required if a node is given
    assert_null(native_find_rsc(promotable_clone, "promotable-rsc:0", cluster02, 0));
    assert_null(native_find_rsc(promotable_clone, "promotable-rsc:1", cluster01, 0));

    /* Check that the resource is running on the node we expect. */
    assert_ptr_equal(promotable_0,
                     native_find_rsc(promotable_clone, "promotable-rsc:0",
                                     cluster02, pcmk_rsc_match_current_node));
    assert_ptr_equal(promotable_0,
                     native_find_rsc(promotable_clone, "promotable-rsc",
                                     cluster02,
                                     pcmk_rsc_match_basename
                                     |pcmk_rsc_match_current_node));
    assert_ptr_equal(promotable_0,
                     native_find_rsc(promotable_clone, "promotable-rsc",
                                     cluster02,
                                     pcmk_rsc_match_anon_basename
                                     |pcmk_rsc_match_current_node));
    assert_ptr_equal(promotable_1,
                     native_find_rsc(promotable_clone, "promotable-rsc:1",
                                     cluster01, pcmk_rsc_match_current_node));
    assert_ptr_equal(promotable_1,
                     native_find_rsc(promotable_clone, "promotable-rsc",
                                     cluster01,
                                     pcmk_rsc_match_basename
                                     |pcmk_rsc_match_current_node));
    assert_ptr_equal(promotable_1,
                     native_find_rsc(promotable_clone, "promotable-rsc",
                                     cluster01,
                                     pcmk_rsc_match_anon_basename
                                     |pcmk_rsc_match_current_node));
}

static void
renamed_rsc(void **state) {
    pcmk_resource_t *promotable_0 = NULL;
    pcmk_resource_t *promotable_1 = NULL;

    /* Find the "promotable-rsc:0" and "promotable-rsc:1" resources, members of "promotable-clone". */
    for (GList *iter = promotable_clone->priv->children;
         iter != NULL; iter = iter->next) {

        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

        if (strcmp(rsc->id, "promotable-rsc:0") == 0) {
            promotable_0 = rsc;
        } else if (strcmp(rsc->id, "promotable-rsc:1") == 0) {
            promotable_1 = rsc;
        }
    }

    assert_non_null(promotable_0);
    assert_non_null(promotable_1);

    // Passes because pcmk_rsc_match_history means base name matches history_id
    assert_ptr_equal(promotable_0,
                     native_find_rsc(promotable_0, "promotable-rsc", NULL,
                                     pcmk_rsc_match_history));
    assert_ptr_equal(promotable_1,
                     native_find_rsc(promotable_1, "promotable-rsc", NULL,
                                     pcmk_rsc_match_history));
}

static void
bundle_rsc(void **state) {
    assert_non_null(httpd_bundle);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(httpd_bundle, native_find_rsc(httpd_bundle, "httpd-bundle", NULL, 0));
    assert_ptr_equal(httpd_bundle,
                     native_find_rsc(httpd_bundle, "httpd-bundle", NULL,
                                     pcmk_rsc_match_current_node));

    /* Fails because resource is not a clone (nor cloned). */
    assert_null(native_find_rsc(httpd_bundle, "httpd-bundle", NULL,
                                pcmk_rsc_match_clone_only));
    assert_null(native_find_rsc(httpd_bundle, "httpd-bundle", cluster01,
                                pcmk_rsc_match_clone_only));

    // Fails because pcmk_rsc_match_current_node is required if a node is given
    assert_null(native_find_rsc(httpd_bundle, "httpd-bundle", cluster01, 0));

    /* Passes because one of httpd_bundle's children is running on cluster01. */
    assert_ptr_equal(httpd_bundle,
                     native_find_rsc(httpd_bundle, "httpd-bundle", cluster01,
                                     pcmk_rsc_match_current_node));
}

static bool
bundle_first_replica(pcmk__bundle_replica_t *replica, void *user_data)
{
    pcmk_resource_t *ip_0 = replica->ip;
    pcmk_resource_t *child_0 = replica->child;
    pcmk_resource_t *container_0 = replica->container;
    pcmk_resource_t *remote_0 = replica->remote;

    assert_non_null(ip_0);
    assert_non_null(child_0);
    assert_non_null(container_0);
    assert_non_null(remote_0);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(ip_0, native_find_rsc(ip_0, "httpd-bundle-ip-192.168.122.131", NULL, 0));
    assert_ptr_equal(child_0, native_find_rsc(child_0, "httpd:0", NULL, 0));
    assert_ptr_equal(container_0, native_find_rsc(container_0, "httpd-bundle-docker-0", NULL, 0));
    assert_ptr_equal(remote_0, native_find_rsc(remote_0, "httpd-bundle-0", NULL, 0));

    // Fails because pcmk_rsc_match_current_node is required if a node is given
    assert_null(native_find_rsc(ip_0, "httpd-bundle-ip-192.168.122.131", cluster01, 0));
    assert_null(native_find_rsc(child_0, "httpd:0", httpd_bundle_0, 0));
    assert_null(native_find_rsc(container_0, "httpd-bundle-docker-0", cluster01, 0));
    assert_null(native_find_rsc(remote_0, "httpd-bundle-0", cluster01, 0));

    /* Check that the resource is running on the node we expect. */
    assert_ptr_equal(ip_0,
                     native_find_rsc(ip_0, "httpd-bundle-ip-192.168.122.131",
                                     cluster01, pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(ip_0, "httpd-bundle-ip-192.168.122.131",
                                cluster02, pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(ip_0, "httpd-bundle-ip-192.168.122.131",
                                httpd_bundle_0, pcmk_rsc_match_current_node));
    assert_ptr_equal(child_0,
                     native_find_rsc(child_0, "httpd:0", httpd_bundle_0,
                                     pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(child_0, "httpd:0", cluster01,
                                pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(child_0, "httpd:0", cluster02,
                                pcmk_rsc_match_current_node));
    assert_ptr_equal(container_0,
                     native_find_rsc(container_0, "httpd-bundle-docker-0",
                                     cluster01, pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(container_0, "httpd-bundle-docker-0", cluster02,
                                pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(container_0, "httpd-bundle-docker-0",
                                httpd_bundle_0, pcmk_rsc_match_current_node));
    assert_ptr_equal(remote_0,
                     native_find_rsc(remote_0, "httpd-bundle-0", cluster01,
                                     pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(remote_0, "httpd-bundle-0", cluster02,
                                pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(remote_0, "httpd-bundle-0", httpd_bundle_0,
                                pcmk_rsc_match_current_node));

    // Passes because pcmk_rsc_match_basename matches any replica's base name
    assert_ptr_equal(child_0,
                     native_find_rsc(child_0, "httpd", NULL,
                                     pcmk_rsc_match_basename));

    // Passes because pcmk_rsc_match_anon_basename matches
    assert_ptr_equal(child_0,
                     native_find_rsc(child_0, "httpd", NULL,
                                     pcmk_rsc_match_anon_basename));

    /* Check that the resource is running on the node we expect. */
    assert_ptr_equal(child_0,
                     native_find_rsc(child_0, "httpd", httpd_bundle_0,
                                     pcmk_rsc_match_basename
                                     |pcmk_rsc_match_current_node));
    assert_ptr_equal(child_0,
                     native_find_rsc(child_0, "httpd", httpd_bundle_0,
                                     pcmk_rsc_match_anon_basename
                                     |pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(child_0, "httpd", cluster01,
                                pcmk_rsc_match_basename
                                |pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(child_0, "httpd", cluster01,
                                pcmk_rsc_match_anon_basename
                                |pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(child_0, "httpd", cluster02,
                                pcmk_rsc_match_basename
                                |pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(child_0, "httpd", cluster02,
                                pcmk_rsc_match_anon_basename
                                |pcmk_rsc_match_current_node));

    /* Fails because incorrect flags were given along with base name. */
    assert_null(native_find_rsc(child_0, "httpd", NULL,
                                pcmk_rsc_match_current_node));

    /* And then we check failure possibilities again, except passing httpd-bundle
     * instead of X_0 as the first argument to native_find_rsc.
     */

    // Fails because pcmk_rsc_match_current_node is required if a node is given
    assert_null(native_find_rsc(httpd_bundle, "httpd-bundle-ip-192.168.122.131", cluster01, 0));
    assert_null(native_find_rsc(httpd_bundle, "httpd:0", httpd_bundle_0, 0));
    assert_null(native_find_rsc(httpd_bundle, "httpd-bundle-docker-0", cluster01, 0));
    assert_null(native_find_rsc(httpd_bundle, "httpd-bundle-0", cluster01, 0));

    /* Check that the resource is running on the node we expect. */
    assert_ptr_equal(ip_0,
                     native_find_rsc(httpd_bundle,
                                     "httpd-bundle-ip-192.168.122.131",
                                     cluster01, pcmk_rsc_match_current_node));
    assert_ptr_equal(child_0,
                     native_find_rsc(httpd_bundle, "httpd:0", httpd_bundle_0,
                                     pcmk_rsc_match_current_node));
    assert_ptr_equal(container_0,
                     native_find_rsc(httpd_bundle, "httpd-bundle-docker-0",
                                     cluster01, pcmk_rsc_match_current_node));
    assert_ptr_equal(remote_0,
                     native_find_rsc(httpd_bundle, "httpd-bundle-0", cluster01,
                                     pcmk_rsc_match_current_node));
    return false; // Do not iterate through any further replicas
}

static void
bundle_replica_rsc(void **state)
{
    pe__foreach_bundle_replica(httpd_bundle, bundle_first_replica, NULL);
}

static void
clone_group_rsc(void **rsc) {
    assert_non_null(mysql_clone_group);

    /* Passes because NULL was passed for node, regardless of flags. */
    assert_ptr_equal(mysql_clone_group, native_find_rsc(mysql_clone_group, "mysql-clone-group", NULL, 0));
    assert_ptr_equal(mysql_clone_group,
                     native_find_rsc(mysql_clone_group, "mysql-clone-group",
                                     NULL, pcmk_rsc_match_current_node));
    assert_ptr_equal(mysql_clone_group,
                     native_find_rsc(mysql_clone_group, "mysql-clone-group",
                                     NULL, pcmk_rsc_match_clone_only));

    // Fails because pcmk_rsc_match_current_node is required if a node is given
    assert_null(native_find_rsc(mysql_clone_group, "mysql-clone-group", cluster01, 0));

    /* Passes because one of mysql-clone-group's children is running on cluster01. */
    assert_ptr_equal(mysql_clone_group,
                     native_find_rsc(mysql_clone_group, "mysql-clone-group",
                                     cluster01, pcmk_rsc_match_current_node));

    // Fails because pcmk_rsc_match_current_node is required if a node is given
    assert_null(native_find_rsc(mysql_clone_group, "mysql-clone-group", cluster02, 0));

    /* Passes because one of mysql-clone-group's children is running on cluster02. */
    assert_ptr_equal(mysql_clone_group,
                     native_find_rsc(mysql_clone_group, "mysql-clone-group",
                                     cluster02, pcmk_rsc_match_current_node));

    // Passes for previous reasons, plus includes pcmk_rsc_match_clone_only
    assert_ptr_equal(mysql_clone_group,
                     native_find_rsc(mysql_clone_group, "mysql-clone-group",
                                     cluster01,
                                     pcmk_rsc_match_clone_only
                                     |pcmk_rsc_match_current_node));
    assert_ptr_equal(mysql_clone_group,
                     native_find_rsc(mysql_clone_group, "mysql-clone-group",
                                     cluster02,
                                     pcmk_rsc_match_clone_only
                                     |pcmk_rsc_match_current_node));
}

static void
clone_group_instance_rsc(void **rsc) {
    pcmk_resource_t *mysql_group_0 = NULL;
    pcmk_resource_t *mysql_group_1 = NULL;

    /* Find the "mysql-group:0" and "mysql-group:1" resources, members of "mysql-clone-group". */
    for (GList *iter = mysql_clone_group->priv->children;
         iter != NULL; iter = iter->next) {

        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

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
    assert_ptr_equal(mysql_group_0,
                     native_find_rsc(mysql_group_0, "mysql-group:0", NULL,
                                     pcmk_rsc_match_current_node));
    assert_ptr_equal(mysql_group_1, native_find_rsc(mysql_group_1, "mysql-group:1", NULL, 0));
    assert_ptr_equal(mysql_group_1,
                     native_find_rsc(mysql_group_1, "mysql-group:1", NULL,
                                     pcmk_rsc_match_current_node));

    // Fails because pcmk_rsc_match_current_node is required if a node is given
    assert_null(native_find_rsc(mysql_group_0, "mysql-group:0", cluster02, 0));
    assert_null(native_find_rsc(mysql_group_1, "mysql-group:1", cluster01, 0));

    /* Check that the resource is running on the node we expect. */
    assert_ptr_equal(mysql_group_0,
                     native_find_rsc(mysql_group_0, "mysql-group:0", cluster02,
                                     pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(mysql_group_0, "mysql-group:0", cluster01,
                                pcmk_rsc_match_current_node));
    assert_ptr_equal(mysql_group_1,
                     native_find_rsc(mysql_group_1, "mysql-group:1", cluster01,
                                     pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(mysql_group_1, "mysql-group:1", cluster02,
                                pcmk_rsc_match_current_node));

    /* Passes because NULL was passed for node and base name was given, with correct flags. */
    assert_ptr_equal(mysql_group_0,
                     native_find_rsc(mysql_group_0, "mysql-group" , NULL,
                                     pcmk_rsc_match_clone_only));

    // Passes because pcmk_rsc_match_basename matches any base name
    assert_ptr_equal(mysql_group_0,
                     native_find_rsc(mysql_group_0, "mysql-group" , NULL,
                                     pcmk_rsc_match_basename));
    assert_ptr_equal(mysql_group_1,
                     native_find_rsc(mysql_group_1, "mysql-group" , NULL,
                                     pcmk_rsc_match_basename));

    // Passes because pcmk_rsc_match_anon_basename matches
    assert_ptr_equal(mysql_group_0,
                     native_find_rsc(mysql_group_0, "mysql-group" , NULL,
                                     pcmk_rsc_match_anon_basename));
    assert_ptr_equal(mysql_group_1,
                     native_find_rsc(mysql_group_1, "mysql-group" , NULL,
                                     pcmk_rsc_match_anon_basename));

    /* Check that the resource is running on the node we expect. */
    assert_ptr_equal(mysql_group_0,
                     native_find_rsc(mysql_group_0, "mysql-group", cluster02,
                                     pcmk_rsc_match_basename
                                     |pcmk_rsc_match_current_node));
    assert_ptr_equal(mysql_group_0,
                     native_find_rsc(mysql_group_0, "mysql-group", cluster02,
                                     pcmk_rsc_match_anon_basename
                                     |pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(mysql_group_0, "mysql-group", cluster01,
                                pcmk_rsc_match_basename
                                |pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(mysql_group_0, "mysql-group", cluster01,
                                pcmk_rsc_match_anon_basename
                                |pcmk_rsc_match_current_node));
    assert_ptr_equal(mysql_group_1,
                     native_find_rsc(mysql_group_1, "mysql-group", cluster01,
                                     pcmk_rsc_match_basename
                                     |pcmk_rsc_match_current_node));
    assert_ptr_equal(mysql_group_1,
                     native_find_rsc(mysql_group_1, "mysql-group", cluster01,
                                     pcmk_rsc_match_anon_basename
                                     |pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(mysql_group_1, "mysql-group", cluster02,
                                pcmk_rsc_match_basename
                                |pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(mysql_group_1, "mysql-group", cluster02,
                                pcmk_rsc_match_anon_basename
                                |pcmk_rsc_match_current_node));

    /* Fails because incorrect flags were given along with base name. */
    assert_null(native_find_rsc(mysql_group_0, "mysql-group", NULL,
                                pcmk_rsc_match_current_node));
    assert_null(native_find_rsc(mysql_group_1, "mysql-group", NULL,
                                pcmk_rsc_match_current_node));

    /* And then we check failure possibilities again, except passing mysql_clone_group
     * instead of mysql_group_X as the first argument to native_find_rsc.
     */

    // Fails because pcmk_rsc_match_current_node is required if a node is given
    assert_null(native_find_rsc(mysql_clone_group, "mysql-group:0", cluster02, 0));
    assert_null(native_find_rsc(mysql_clone_group, "mysql-group:1", cluster01, 0));

    /* Check that the resource is running on the node we expect. */
    assert_ptr_equal(mysql_group_0,
                     native_find_rsc(mysql_clone_group, "mysql-group:0",
                                     cluster02, pcmk_rsc_match_current_node));
    assert_ptr_equal(mysql_group_0,
                     native_find_rsc(mysql_clone_group, "mysql-group",
                                     cluster02,
                                     pcmk_rsc_match_basename
                                     |pcmk_rsc_match_current_node));
    assert_ptr_equal(mysql_group_0,
                     native_find_rsc(mysql_clone_group, "mysql-group",
                                     cluster02,
                                     pcmk_rsc_match_anon_basename
                                     |pcmk_rsc_match_current_node));
    assert_ptr_equal(mysql_group_1,
                     native_find_rsc(mysql_clone_group, "mysql-group:1",
                                     cluster01, pcmk_rsc_match_current_node));
    assert_ptr_equal(mysql_group_1,
                     native_find_rsc(mysql_clone_group, "mysql-group",
                                     cluster01,
                                     pcmk_rsc_match_basename
                                     |pcmk_rsc_match_current_node));
    assert_ptr_equal(mysql_group_1,
                     native_find_rsc(mysql_clone_group, "mysql-group",
                                     cluster01,
                                     pcmk_rsc_match_anon_basename
                                     |pcmk_rsc_match_current_node));
}

static void
clone_group_member_rsc(void **state) {
    pcmk_resource_t *mysql_proxy = NULL;

    /* Find the "mysql-proxy" resource, a member of "mysql-group". */
    for (GList *iter = mysql_clone_group->priv->children;
         iter != NULL; iter = iter->next) {

        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

        if (strcmp(rsc->id, "mysql-group:0") == 0) {
            for (GList *iter2 = rsc->priv->children;
                 iter2 != NULL; iter2 = iter2->next) {
                pcmk_resource_t *child = (pcmk_resource_t *) iter2->data;

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
    assert_ptr_equal(mysql_proxy,
                     native_find_rsc(mysql_proxy, "mysql-proxy:0", NULL,
                                     pcmk_rsc_match_current_node));

    /* Passes because resource's parent is a clone. */
    assert_ptr_equal(mysql_proxy,
                     native_find_rsc(mysql_proxy, "mysql-proxy:0", NULL,
                                     pcmk_rsc_match_clone_only));
    assert_ptr_equal(mysql_proxy,
                     native_find_rsc(mysql_proxy, "mysql-proxy:0", cluster02,
                                     pcmk_rsc_match_clone_only
                                     |pcmk_rsc_match_current_node));

    /* Fails because mysql-proxy:0 is not running on cluster01, even with the right flags. */
    assert_null(native_find_rsc(mysql_proxy, "mysql-proxy:0", cluster01,
                                pcmk_rsc_match_current_node));

    // Fails because pcmk_rsc_match_current_node is required if a node is given
    assert_null(native_find_rsc(mysql_proxy, "mysql-proxy:0", cluster02, 0));

    /* Passes because mysql-proxy:0 is running on cluster02. */
    assert_ptr_equal(mysql_proxy,
                     native_find_rsc(mysql_proxy, "mysql-proxy:0", cluster02,
                                     pcmk_rsc_match_current_node));
}

/* TODO: Add tests for finding on assigned node (passing a node without
 * pcmk_rsc_match_current_node, after scheduling, for a resource that is
 * starting/stopping/moving.
 */
PCMK__UNIT_TEST(setup, teardown,
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
                cmocka_unit_test(clone_group_member_rsc))
