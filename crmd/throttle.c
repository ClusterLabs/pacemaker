/*
 * Copyright (C) 2013 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>
#include <ctype.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/cluster.h>
#include <throttle.h>

enum throttle_state_e 
{
    throttle_high = 0x0100,
    throttle_med  = 0x0010,
    throttle_low  = 0x0001,
    throttle_none = 0x0000,
};

struct throttle_record_s 
{
        int cores;
        enum throttle_state_e mode;
        char *node;
};

int throttle_job_max = 0;
float throttle_load_target = 0.0;

#define THROTTLE_FACTOR_LOW    0.6
#define THROTTLE_FACTOR_MEDIUM 0.8
#define THROTTLE_FACTOR_HIGH   1.2

GHashTable *throttle_records = NULL;
mainloop_timer_t *throttle_timer = NULL;

int throttle_num_cores(void)
{
    static int cores = 0;
    char buffer[256];
    FILE *stream = NULL;
    const char *cpufile = "/proc/cpuinfo";

    if(cores) {
        return cores;
    }

    stream = fopen(cpufile, "r");
    if(stream == NULL) {
        int rc = errno;
        crm_warn("Couldn't read %s, assuming a single processor: %s (%d)", cpufile, pcmk_strerror(rc), rc);
        return 1;
    }

    while (fgets(buffer, sizeof(buffer), stream)) {
        if(strstr(buffer, "processor") == buffer) {
            cores++;
        }
    }

    if(cores == 0) {
        crm_warn("No processors found in %s, assuming 1", cpufile);
        return 1;
    }

    fclose(stream);
    return cores;
}

static bool throttle_load_avg(float *load)
{
    char buffer[256];
    FILE *stream = NULL;
    const char *loadfile = "/proc/loadavg";

    if(load == NULL) {
        return FALSE;
    }

    stream = fopen(loadfile, "r");
    if(stream == NULL) {
        int rc = errno;
        crm_warn("Couldn't read %s: %s (%d)", loadfile, pcmk_strerror(rc), rc);
        return FALSE;
    }

    if(fgets(buffer, sizeof(buffer), stream)) {
        char *nl = strstr(buffer, "\n");

        /* Grab the 1-minute average, ignore the rest */
        *load = strtof(buffer, NULL);
        if(nl) { nl[0] = 0; }

        crm_debug("Current load is %f (full: %s)", *load, buffer);
    }

    fclose(stream);
    return TRUE;
}

static bool throttle_io_load(float *load, unsigned int *blocked)
{
    char buffer[64*1024];
    FILE *stream = NULL;
    const char *loadfile = "/proc/stat";

    if(load == NULL) {
        return FALSE;
    }

    stream = fopen(loadfile, "r");
    if(stream == NULL) {
        int rc = errno;
        crm_warn("Couldn't read %s: %s (%d)", loadfile, pcmk_strerror(rc), rc);
        return FALSE;
    }

    if(fgets(buffer, sizeof(buffer), stream)) {
        /* Borrowed from procps-ng's sysinfo.c */

        char *b = NULL;
        long long cpu_use = 0;
        long long cpu_nic = 0;
        long long cpu_sys = 0;
        long long cpu_idl = 0;
        long long cpu_iow = 0; /* not separated out until the 2.5.41 kernel */
        long long cpu_xxx = 0; /* not separated out until the 2.6.0-test4 kernel */
        long long cpu_yyy = 0; /* not separated out until the 2.6.0-test4 kernel */
        long long cpu_zzz = 0; /* not separated out until the 2.6.11 kernel */

        long long divo2 = 0;
        long long duse = 0;
        long long dsys = 0;
        long long didl =0;
        long long diow =0;
        long long dstl = 0;
        long long Div = 0;

        b = strstr(buffer, "cpu ");
        if(b) sscanf(b,  "cpu  %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu",
               &cpu_use, &cpu_nic, &cpu_sys, &cpu_idl, &cpu_iow, &cpu_xxx, &cpu_yyy, &cpu_zzz);

        if(blocked) {
            b = strstr(buffer, "procs_blocked ");
            if(b) sscanf(b,  "procs_blocked %u", blocked);
        }

        duse = cpu_use + cpu_nic;
        dsys = cpu_sys + cpu_xxx + cpu_yyy;
        didl = cpu_idl;
        diow = cpu_iow;
        dstl = cpu_zzz;
        Div = duse + dsys + didl + diow + dstl;
        if (!Div) Div = 1, didl = 1;
        divo2 = Div / 2UL;

        /* vmstat output:
         *
         * procs -----------memory---------- ---swap-- -----io---- -system-- ----cpu---- 
         * r  b   swpd   free   buff  cache     si   so    bi    bo   in   cs us sy id wa
         * 1  0 5537800 958592 204180 1737740    1    1    12    15    0    0  2  1 97  0
         *
         * The last four columns are calculated as:
         *
         * (unsigned)( (100*duse			+ divo2) / Div ),
         * (unsigned)( (100*dsys			+ divo2) / Div ),
         * (unsigned)( (100*didl			+ divo2) / Div ),
         * (unsigned)( (100*diow			+ divo2) / Div )
         *
         */
        *load = (diow + divo2) / Div;
        crm_debug("Current IO load is %f", *load);
    }

    fclose(stream);
    return load;
}

static enum throttle_state_e
throttle_mode(void) 
{
    float load;
    unsigned int blocked = 0;
    int cores = throttle_num_cores();

    enum throttle_state_e mode = throttle_none;

    if(throttle_load_target <= 0) {
        /* If we ever make this a valid value, the cluster will at least behave as expected */
        return mode;
    }

    if(throttle_load_avg(&load)) {
        float simple_load = 0.0;

        if(cores) {
            simple_load = load / cores;
        } else {
            simple_load = load;
        }

        if(simple_load > THROTTLE_FACTOR_HIGH * throttle_load_target) {
            crm_notice("High CPU load detected: %f (limit: %f)", simple_load, throttle_load_target);
            mode |= throttle_high;
        } else if(simple_load > THROTTLE_FACTOR_MEDIUM * throttle_load_target) {
            crm_info("Moderate CPU load detected: %f (limit: %f)", simple_load, throttle_load_target);
            mode |= throttle_med;
        } else if(simple_load > THROTTLE_FACTOR_LOW * throttle_load_target) {
            crm_debug("Noticable CPU load detected: %f (limit: %f)", simple_load, throttle_load_target);
            mode |= throttle_low;
        }
    }

    if(throttle_io_load(&load, &blocked)) {
        float blocked_ratio = 0.0;

        if(load > THROTTLE_FACTOR_HIGH * throttle_load_target) {
            crm_notice("High IO load detected: %f (limit: %f)", load, throttle_load_target);
            mode |= throttle_high;
        } else if(load > THROTTLE_FACTOR_MEDIUM * throttle_load_target) {
            crm_info("Moderate IO load detected: %f (limit: %f)", load, throttle_load_target);
            mode |= throttle_med;
        } else if(load > THROTTLE_FACTOR_LOW * throttle_load_target) {
            crm_info("Noticable IO load detected: %f (limit: %f)", load, throttle_load_target);
            mode |= throttle_low;
        }

        if(cores) {
            blocked_ratio = blocked / cores;
        } else {
            blocked_ratio = blocked;
        }

        if(blocked_ratio > THROTTLE_FACTOR_HIGH * throttle_load_target) {
            crm_notice("High IO indicator detected: %f (limit: %f)", blocked_ratio, throttle_load_target);
            mode |= throttle_high;
        } else if(blocked_ratio > THROTTLE_FACTOR_MEDIUM * throttle_load_target) {
            crm_info("Moderate IO indicator detected: %f (limit: %f)", blocked_ratio, throttle_load_target);
            mode |= throttle_med;
        } else if(blocked_ratio > THROTTLE_FACTOR_LOW * throttle_load_target) {
            crm_debug("Noticable IO indicator detected: %f (limit: %f)", blocked_ratio, throttle_load_target);
            mode |= throttle_low;
        }
    }

    if(mode & throttle_high) {
        return throttle_high;
    } else if(mode & throttle_med) {
        return throttle_med;
    } else if(mode & throttle_low) {
        return throttle_low;
    }
    return throttle_none;
}

static void
throttle_send_command(enum throttle_state_e mode)
{
    xmlNode *xml = NULL;
    int cores = throttle_num_cores();

    xml = create_request(CRM_OP_THROTTLE, NULL, NULL, CRM_SYSTEM_CRMD, CRM_SYSTEM_CRMD, NULL);
    crm_xml_add_int(xml, F_CRM_THROTTLE_MODE, mode);
    crm_xml_add_int(xml, F_CRM_THROTTLE_CORES, cores);

    send_cluster_message(NULL, crm_msg_crmd, xml, TRUE);
    free_xml(xml);

    crm_info("Updated throttle state to %.4x", mode);
}

static gboolean
throttle_timer_cb(gpointer data)
{
    static enum throttle_state_e last = throttle_none;
    enum throttle_state_e now = throttle_mode();

    if(now != last) {
        crm_debug("New throttle mode: %.4x (was %.4x)", now, last);
        throttle_send_command(now);
        last = now;
    }
    return TRUE;
}

static void
throttle_record_free(gpointer p)
{
    struct throttle_record_s *r = p;
    free(r->node);
    free(r);
}

void
throttle_init(void)
{
    float load = 0.0;
    throttle_load_avg(&load);

    throttle_records = g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, throttle_record_free);
    throttle_timer = mainloop_timer_add("throttle", 30* 1000, TRUE, throttle_timer_cb, NULL);
    mainloop_timer_start(throttle_timer);
}

void
throttle_fini(void)
{
    mainloop_timer_del(throttle_timer); throttle_timer = NULL;
    g_hash_table_destroy(throttle_records); throttle_records = NULL;
}


int
throttle_get_job_limit(const char *node)
{
    int jobs = 1;
    int job_max = throttle_job_max;
    struct throttle_record_s *r = NULL;

    r = g_hash_table_lookup(throttle_records, node);
    if(r == NULL) {
        r = calloc(1, sizeof(struct throttle_record_s));
        r->node = strdup(node);
        r->mode = throttle_mode();
        r->cores = throttle_num_cores();
        crm_trace("Defaulting to local values for unknown node %s", node);

        g_hash_table_insert(throttle_records, r->node, r);
    }

    if(job_max <= 0) {
        job_max = r->cores * 2;
    }

    switch(r->mode) {
        case throttle_high:
            jobs = 1; /* At least one job must always be allowed */
            break;
        case throttle_med:
            jobs = QB_MAX(1, job_max / 4);
            break;
        case throttle_low:
            jobs = QB_MAX(1, job_max / 2);
            break;
        case throttle_none:
            jobs = QB_MAX(1, job_max);
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
    int cores = 0;
    enum throttle_state_e mode = 0;
    struct throttle_record_s *r = NULL;
    const char *from = crm_element_value(xml, F_CRM_HOST_FROM);

    crm_element_value_int(xml, F_CRM_THROTTLE_MODE, (int*)&mode);
    crm_element_value_int(xml, F_CRM_THROTTLE_CORES, &cores);

    r = g_hash_table_lookup(throttle_records, from);

    if(r == NULL) {
        r = calloc(1, sizeof(struct throttle_record_s));
        r->node = strdup(from);
        g_hash_table_insert(throttle_records, r->node, r);
    }

    r->cores = cores;
    r->mode = mode;

    crm_debug("Host %s has %d cores and throttle mode %.4x.  New job limit is %d",
              from, cores, mode, throttle_get_job_limit(from));
}

