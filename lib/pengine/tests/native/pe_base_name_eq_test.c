/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include <crm/common/xml.h>
#include <crm/common/scheduler.h>
#include <crm/pengine/internal.h>
#include <crm/pengine/status.h>

xmlNode *input = NULL;
pcmk_scheduler_t *scheduler = NULL;

pcmk_resource_t *exim_group, *promotable_0, *promotable_1, *dummy;
pcmk_resource_t *httpd_bundle, *mysql_group_0, *mysql_group_1;

static int
setup(void **state) {
    char *path = NULL;

    pcmk__xml_init();

    path = pcmk__assert_asprintf("%s/crm_mon.xml", getenv("PCMK_CTS_CLI_DIR"));
    input = pcmk__xml_read(path);
    free(path);

    if (input == NULL) {
        return 1;
    }

    scheduler = pcmk_new_scheduler();
    if (scheduler == NULL) {
        return 1;
    }

    pcmk__set_scheduler_flags(scheduler, pcmk__sched_no_counts);
    scheduler->input = input;

    cluster_status(scheduler);

    /* Get references to several resources we use frequently. */
    for (GList *iter = scheduler->priv->resources;
         iter != NULL; iter = iter->next) {

        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

        if (strcmp(rsc->id, "dummy") == 0) {
            dummy = rsc;

        } else if (strcmp(rsc->id, "exim-group") == 0) {
            exim_group = rsc;

        } else if (strcmp(rsc->id, "httpd-bundle") == 0) {
            httpd_bundle = rsc;

        } else if (strcmp(rsc->id, "mysql-clone-group") == 0) {
            for (GList *iter = rsc->priv->children;
                 iter != NULL; iter = iter->next) {

                pcmk_resource_t *child = (pcmk_resource_t *) iter->data;

                if (strcmp(child->id, "mysql-group:0") == 0) {
                    mysql_group_0 = child;
                } else if (strcmp(child->id, "mysql-group:1") == 0) {
                    mysql_group_1 = child;
                }
            }

        } else if (strcmp(rsc->id, "promotable-clone") == 0) {
            for (GList *iter = rsc->priv->children;
                 iter != NULL; iter = iter->next) {

                pcmk_resource_t *child = (pcmk_resource_t *) iter->data;

                if (strcmp(child->id, "promotable-rsc:0") == 0) {
                    promotable_0 = child;
                } else if (strcmp(child->id, "promotable-rsc:1") == 0) {
                    promotable_1 = child;
                }
            }
        }
    }

    return 0;
}

static int
teardown(void **state)
{
    pcmk_free_scheduler(scheduler);
    pcmk__xml_cleanup();
    return 0;
}

static void
bad_args(void **state) {
    char *id = dummy->id;

    assert_false(pe_base_name_eq(NULL, "dummy"));
    assert_false(pe_base_name_eq(dummy, NULL));

    dummy->id = NULL;
    assert_false(pe_base_name_eq(dummy, "dummy"));
    dummy->id = id;
}

static void
primitive_rsc(void **state) {
    assert_true(pe_base_name_eq(dummy, "dummy"));
    assert_false(pe_base_name_eq(dummy, "DUMMY"));
    assert_false(pe_base_name_eq(dummy, "dUmMy"));
    assert_false(pe_base_name_eq(dummy, "dummy0"));
    assert_false(pe_base_name_eq(dummy, "dummy:0"));
}

static void
group_rsc(void **state) {
    assert_true(pe_base_name_eq(exim_group, "exim-group"));
    assert_false(pe_base_name_eq(exim_group, "EXIM-GROUP"));
    assert_false(pe_base_name_eq(exim_group, "exim-group0"));
    assert_false(pe_base_name_eq(exim_group, "exim-group:0"));
    assert_false(pe_base_name_eq(exim_group, "Public-IP"));
}

static void
clone_rsc(void **state) {
    assert_true(pe_base_name_eq(promotable_0, "promotable-rsc"));
    assert_true(pe_base_name_eq(promotable_1, "promotable-rsc"));

    assert_false(pe_base_name_eq(promotable_0, "promotable-rsc:0"));
    assert_false(pe_base_name_eq(promotable_1, "promotable-rsc:1"));
    assert_false(pe_base_name_eq(promotable_0, "PROMOTABLE-RSC"));
    assert_false(pe_base_name_eq(promotable_1, "PROMOTABLE-RSC"));
    assert_false(pe_base_name_eq(promotable_0, "Promotable-rsc"));
    assert_false(pe_base_name_eq(promotable_1, "Promotable-rsc"));
}

static void
bundle_rsc(void **state) {
    assert_true(pe_base_name_eq(httpd_bundle, "httpd-bundle"));
    assert_false(pe_base_name_eq(httpd_bundle, "HTTPD-BUNDLE"));
    assert_false(pe_base_name_eq(httpd_bundle, "httpd"));
    assert_false(pe_base_name_eq(httpd_bundle, "httpd-docker-0"));
}

PCMK__UNIT_TEST(setup, teardown,
                cmocka_unit_test(bad_args),
                cmocka_unit_test(primitive_rsc),
                cmocka_unit_test(group_rsc),
                cmocka_unit_test(clone_rsc),
                cmocka_unit_test(bundle_rsc))
