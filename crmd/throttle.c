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

static float cpu_target = 0.8; /* Ie. 80% configured by the user */
GHashTable *throttle_records = NULL;
mainloop_timer_t *throttle_timer = NULL;

static int throttle_num_cores(void)
{
    static int cores = 0;
    char buffer[256];
    char *iter = NULL;
    char *processor = NULL;
    FILE *stream = NULL;
    const char *cpufile = "/proc/cpuinfo";

    if(cores) {
        return cores;
    }

    stream = fopen(cpufile, "r");
    if(stream == NULL) {
        int rc = errno;
        crm_warn("Couldn't read %s: %s (%d)", cpufile, pcmk_strerror(rc), rc);
        return 0;
    }

    while (fgets(buffer, sizeof(buffer), stream)) {
        if(strstr(buffer, "processor") == buffer) {
            free(processor);
            processor = strdup(buffer);
        }
    }

    if(processor == NULL) {
        crm_warn("No processors found in %s", cpufile);
        return 0;
    }

    iter = processor + strlen("processor");
    while(iter[0] == ':' || isspace(iter[0])) {
        iter++;
    }

    cores = strtol(iter, NULL, 10);
    crm_trace("Got %d from %s", cores, iter);

    cores++; /* Counting starts at 0 */

    free(processor);
    fclose(stream);
    return cores;
}

static float throttle_load_avg(void)
{
    float load = 0.0;
    char buffer[256];
    const char *loadfile = "/proc/loadavg";
    FILE *stream = fopen(loadfile, "r");

    if(stream == NULL) {
        int rc = errno;
        crm_warn("Couldn't read %s: %s (%d)", loadfile, pcmk_strerror(rc), rc);
        return 0;
    }

    if(fgets(buffer, sizeof(buffer), stream)) {
        char *nl = strstr(buffer, "\n");

        /* Grab the 1-minute average, ignore the rest */
        load = strtof(buffer, NULL);
        if(nl) { nl[0] = 0; }

        crm_debug("Current load is %f (full: %s)", load, buffer);
    }

    fclose(stream);
    return load;
}

static enum throttle_state_e
throttle_mode(void) 
{
    float load = throttle_load_avg();
    int cores = throttle_num_cores();
    float simple_load = 0.0;

    enum throttle_state_e mode = throttle_none;

    if(cores) {
        simple_load = load / cores;
    } else {
        simple_load = load;
    }

    if(simple_load > cpu_target) {
        mode |= throttle_high;
    } else if(simple_load > 0.5 * cpu_target) {
        mode |= throttle_med;
    } else if(simple_load > 0.25 * cpu_target) {
        mode |= throttle_low;
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
    throttle_records = g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, throttle_record_free);
    throttle_timer = mainloop_timer_add("throttle", 30* 1000, TRUE, throttle_timer_cb, NULL);
    crm_debug("load avg: %f on %d cores", throttle_load_avg(), throttle_num_cores());
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
    int cores = 0;
    enum throttle_state_e mode = 0;
    struct throttle_record_s *r = NULL;

    r = g_hash_table_lookup(throttle_records, node);
    if(r == NULL) {
        crm_trace("Defaulting to local values for unknown node %s", node);
        mode = throttle_mode();
        cores = throttle_num_cores();

    } else {
        mode = r->mode;
        cores = r->cores;
    }

    switch(mode) {
        case throttle_high:
            jobs = 1; /* At least one job must always be allowed */
            break;
        case throttle_med:
            jobs = QB_MAX(1, cores / 2);
            break;
        case throttle_low:
            jobs = QB_MAX(1, cores);
            break;
        case throttle_none:
            jobs = QB_MAX(1, cores * 2);
            break;
        default:
            crm_err("Unknown throttle mode %.4x", mode);
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

    crm_debug("Host %s has %d cores and throttle mode %.4x.  Job limit = %d",
              from, cores, mode, throttle_get_job_limit(from));
}

