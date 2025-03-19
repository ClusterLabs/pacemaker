/*
 * Copyright 2013-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <ctype.h>
#include <dirent.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/cluster.h>

#include <pacemaker-controld.h>

/* These values don't need to be bits, but these particular values must be kept
 * for backward compatibility during rolling upgrades.
 */
enum throttle_state_e {
    throttle_none       = 0x0000,
    throttle_low        = 0x0001,
    throttle_med        = 0x0010,
    throttle_high       = 0x0100,
    throttle_extreme    = 0x1000,
};

struct throttle_record_s {
    int max;
    enum throttle_state_e mode;
    char *node;
};

static int throttle_job_max = 0;
static float throttle_load_target = 0.0;

#define THROTTLE_FACTOR_LOW    1.2
#define THROTTLE_FACTOR_MEDIUM 1.6
#define THROTTLE_FACTOR_HIGH   2.0

static GHashTable *throttle_records = NULL;
static mainloop_timer_t *throttle_timer = NULL;

static const char *
load2str(enum throttle_state_e mode)
{
    switch (mode) {
        case throttle_extreme:  return "extreme";
        case throttle_high:     return "high";
        case throttle_med:      return "medium";
        case throttle_low:      return "low";
        case throttle_none:     return "negligible";
        default:                return "undetermined";
    }
}

/*!
 * \internal
 * \brief Check a load value against throttling thresholds
 *
 * \param[in] load        Load value to check
 * \param[in] desc        Description of metric (for logging)
 * \param[in] thresholds  Low/medium/high/extreme thresholds
 *
 * \return Throttle mode corresponding to load value
 */
static enum throttle_state_e
throttle_check_thresholds(float load, const char *desc,
                          const float thresholds[4])
{
    if (load > thresholds[3]) {
        crm_notice("Extreme %s detected: %f", desc, load);
        return throttle_extreme;

    } else if (load > thresholds[2]) {
        crm_notice("High %s detected: %f", desc, load);
        return throttle_high;

    } else if (load > thresholds[1]) {
        crm_info("Moderate %s detected: %f", desc, load);
        return throttle_med;

    } else if (load > thresholds[0]) {
        crm_debug("Noticeable %s detected: %f", desc, load);
        return throttle_low;
    }

    crm_trace("Negligible %s detected: %f", desc, load);
    return throttle_none;
}

static enum throttle_state_e
throttle_handle_load(float load, const char *desc, int cores)
{
    float normalize;
    float thresholds[4];

    if (cores == 1) {
        /* On a single core machine, a load of 1.0 is already too high */
        normalize = 0.6;

    } else {
        /* Normalize the load to be per-core */
        normalize = cores;
    }
    thresholds[0] = throttle_load_target * normalize * THROTTLE_FACTOR_LOW;
    thresholds[1] = throttle_load_target * normalize * THROTTLE_FACTOR_MEDIUM;
    thresholds[2] = throttle_load_target * normalize * THROTTLE_FACTOR_HIGH;
    thresholds[3] = load + 1.0; /* never extreme */

    return throttle_check_thresholds(load, desc, thresholds);
}

static enum throttle_state_e
throttle_mode(void)
{
    enum throttle_state_e mode = throttle_none;

    unsigned int cores = pcmk__procfs_num_cores();
    float load;
    float thresholds[4];

    if (pcmk__throttle_cib_load(PCMK__SERVER_BASED, &load)) {
        float cib_max_cpu = 0.95;

        /* The CIB is a single-threaded task and thus cannot consume more
         * than 100% of a CPU (and 1/cores of the overall system load).
         *
         * On a many-cored system, the CIB might therefore be maxed out (causing
         * operations to fail or appear to fail) even though the overall system
         * load is still reasonable.
         *
         * Therefore, the 'normal' thresholds can not apply here, and we need a
         * special case.
         */
        if (cores == 1) {
            cib_max_cpu = 0.4;
        }
        if ((throttle_load_target > 0.0) && (throttle_load_target < cib_max_cpu)) {
            cib_max_cpu = throttle_load_target;
        }

        thresholds[0] = cib_max_cpu * 0.8;
        thresholds[1] = cib_max_cpu * 0.9;
        thresholds[2] = cib_max_cpu;
        /* Can only happen on machines with a low number of cores */
        thresholds[3] = cib_max_cpu * 1.5;

        mode = throttle_check_thresholds(load, "CIB load", thresholds);
    }

    if (throttle_load_target <= 0) {
        /* If we ever make this a valid value, the cluster will at least behave
         * as expected
         */
        return mode;
    }

    if (pcmk__throttle_load_avg(&load)) {
        enum throttle_state_e cpu_load;

        cpu_load = throttle_handle_load(load, "CPU load", cores);
        if (cpu_load > mode) {
            mode = cpu_load;
        }
        crm_debug("Current load is %f across %u core(s)", load, cores);
    }

    return mode;
}

static void
throttle_send_command(enum throttle_state_e mode)
{
    xmlNode *xml = NULL;
    static enum throttle_state_e last = -1;

    if(mode != last) {
        crm_info("New throttle mode: %s load (was %s)",
                 load2str(mode), load2str(last));
        last = mode;

        xml = pcmk__new_request(pcmk_ipc_controld, CRM_SYSTEM_CRMD, NULL,
                                CRM_SYSTEM_CRMD, CRM_OP_THROTTLE, NULL);
        crm_xml_add_int(xml, PCMK__XA_CRM_LIMIT_MODE, mode);
        crm_xml_add_int(xml, PCMK__XA_CRM_LIMIT_MAX, throttle_job_max);

        pcmk__cluster_send_message(NULL, pcmk_ipc_controld, xml);
        pcmk__xml_free(xml);
    }
}

static gboolean
throttle_timer_cb(gpointer data)
{
    throttle_send_command(throttle_mode());
    return TRUE;
}

static void
throttle_record_free(gpointer p)
{
    struct throttle_record_s *r = p;
    free(r->node);
    free(r);
}

static void
throttle_set_load_target(float target)
{
    throttle_load_target = target;
}

/*!
 * \internal
 * \brief Update the maximum number of simultaneous jobs
 *
 * \param[in] preference  Cluster-wide \c PCMK_OPT_NODE_ACTION_LIMIT from the
 *                        CIB
 */
static void
throttle_update_job_max(const char *preference)
{
    long long max = 0LL;

    // Per-node override
    const char *env_limit = pcmk__env_option(PCMK__ENV_NODE_ACTION_LIMIT);

    if (env_limit != NULL) {
        int rc = pcmk__scan_ll(env_limit, &max, 0LL);

        if (rc != pcmk_rc_ok) {
            crm_warn("Ignoring local option PCMK_" PCMK__ENV_NODE_ACTION_LIMIT
                     " because '%s' is not a valid value: %s",
                     env_limit, pcmk_rc_str(rc));
            env_limit = NULL;
        }
    }
    if (env_limit == NULL) {
        // Option validator should prevent invalid values
        CRM_LOG_ASSERT(pcmk__scan_ll(preference, &max, 0LL) == pcmk_rc_ok);
    }

    if (max > 0) {
        throttle_job_max = (max >= INT_MAX)? INT_MAX : (int) max;
    } else {
        // Default is based on the number of cores detected
        throttle_job_max = 2 * pcmk__procfs_num_cores();
    }
}

void
throttle_init(void)
{
    if(throttle_records == NULL) {
        throttle_records = pcmk__strkey_table(NULL, throttle_record_free);
        throttle_timer = mainloop_timer_add("throttle", 30 * 1000, TRUE, throttle_timer_cb, NULL);
    }

    throttle_update_job_max(NULL);
    mainloop_timer_start(throttle_timer);
}

/*!
 * \internal
 * \brief Configure throttle options based on the CIB
 *
 * \param[in,out] options  Name/value pairs for configured options
 */
void
controld_configure_throttle(GHashTable *options)
{
    const char *value = g_hash_table_lookup(options, PCMK_OPT_LOAD_THRESHOLD);

    if (value != NULL) {
        throttle_set_load_target(strtof(value, NULL) / 100.0);
    }

    value = g_hash_table_lookup(options, PCMK_OPT_NODE_ACTION_LIMIT);
    throttle_update_job_max(value);
}

void
throttle_fini(void)
{
    if (throttle_timer != NULL) {
        mainloop_timer_del(throttle_timer);
        throttle_timer = NULL;
    }
    if (throttle_records != NULL) {
        g_hash_table_destroy(throttle_records);
        throttle_records = NULL;
    }
}

int
throttle_get_total_job_limit(int l)
{
    /* Cluster-wide limit */
    GHashTableIter iter;
    int limit = l;
    int peers = pcmk__cluster_num_active_nodes();
    struct throttle_record_s *r = NULL;

    g_hash_table_iter_init(&iter, throttle_records);

    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &r)) {
        switch(r->mode) {

            case throttle_extreme:
                if(limit == 0 || limit > peers/4) {
                    limit = QB_MAX(1, peers/4);
                }
                break;

            case throttle_high:
                if(limit == 0 || limit > peers/2) {
                    limit = QB_MAX(1, peers/2);
                }
                break;
            default:
                break;
        }
    }
    if(limit == l) {

    } else if(l == 0) {
        crm_trace("Using " PCMK_OPT_BATCH_LIMIT "=%d", limit);

    } else {
        crm_trace("Using " PCMK_OPT_BATCH_LIMIT "=%d instead of %d", limit, l);
    }
    return limit;
}

int
throttle_get_job_limit(const char *node)
{
    int jobs = 1;
    struct throttle_record_s *r = NULL;

    r = g_hash_table_lookup(throttle_records, node);
    if(r == NULL) {
        r = pcmk__assert_alloc(1, sizeof(struct throttle_record_s));
        r->node = pcmk__str_copy(node);
        r->mode = throttle_low;
        r->max = throttle_job_max;
        crm_trace("Defaulting to local values for unknown node %s", node);

        g_hash_table_insert(throttle_records, r->node, r);
    }

    switch(r->mode) {
        case throttle_extreme:
        case throttle_high:
            jobs = 1; /* At least one job must always be allowed */
            break;
        case throttle_med:
            jobs = QB_MAX(1, r->max / 4);
            break;
        case throttle_low:
            jobs = QB_MAX(1, r->max / 2);
            break;
        case throttle_none:
            jobs = QB_MAX(1, r->max);
            break;
        default:
            crm_err("Unknown throttle mode %.4x on %s", r->mode, node);
            break;
    }
    return jobs;
}

void
throttle_update(xmlNode *xml)
{
    int max = 0;
    int mode = 0;
    struct throttle_record_s *r = NULL;
    const char *from = crm_element_value(xml, PCMK__XA_SRC);

    pcmk__xe_get_int(xml, PCMK__XA_CRM_LIMIT_MODE, &mode);
    pcmk__xe_get_int(xml, PCMK__XA_CRM_LIMIT_MAX, &max);

    r = g_hash_table_lookup(throttle_records, from);

    if(r == NULL) {
        r = pcmk__assert_alloc(1, sizeof(struct throttle_record_s));
        r->node = pcmk__str_copy(from);
        g_hash_table_insert(throttle_records, r->node, r);
    }

    r->max = max;
    r->mode = (enum throttle_state_e) mode;

    crm_debug("Node %s has %s load and supports at most %d jobs; new job limit %d",
              from, load2str((enum throttle_state_e) mode), max,
              throttle_get_job_limit(from));
}
