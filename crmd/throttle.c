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

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <ctype.h>
#include <dirent.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/cluster.h>

#include <crmd_fsa.h>
#include <throttle.h>


enum throttle_state_e 
{
    throttle_extreme = 0x1000,
    throttle_high = 0x0100,
    throttle_med  = 0x0010,
    throttle_low  = 0x0001,
    throttle_none = 0x0000,
};

struct throttle_record_s 
{
        int max;
        enum throttle_state_e mode;
        char *node;
};

int throttle_job_max = 0;
float throttle_load_target = 0.0;

#define THROTTLE_FACTOR_LOW    1.2
#define THROTTLE_FACTOR_MEDIUM 1.6
#define THROTTLE_FACTOR_HIGH   2.0

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

    fclose(stream);

    if(cores == 0) {
        crm_warn("No processors found in %s, assuming 1", cpufile);
        return 1;
    }

    return cores;
}

static char *find_cib_loadfile(void) 
{
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;
    char *match = NULL;

    dp = opendir("/proc");
    if (!dp) {
        /* no proc directory to search through */
        crm_notice("Can not read /proc directory to track existing components");
        return FALSE;
    }

    while ((entry = readdir(dp)) != NULL) {
        char procpath[128];
        char value[64];
        char key[16];
        FILE *file;
        int pid;

        strcpy(procpath, "/proc/");
        /* strlen("/proc/") + strlen("/status") + 1 = 14
         * 128 - 14 = 114 */
        strncat(procpath, entry->d_name, 114);

        if (lstat(procpath, &statbuf)) {
            continue;
        }
        if (!S_ISDIR(statbuf.st_mode) || !isdigit(entry->d_name[0])) {
            continue;
        }

        strcat(procpath, "/status");

        file = fopen(procpath, "r");
        if (!file) {
            continue;
        }
        if (fscanf(file, "%15s%63s", key, value) != 2) {
            fclose(file);
            continue;
        }
        fclose(file);

        if (safe_str_neq("cib", value)) {
            continue;
        }

        pid = atoi(entry->d_name);
        if (pid <= 0) {
            continue;
        }

        match = crm_strdup_printf("/proc/%d/stat", pid);
        break;
    }

    closedir(dp);
    return match;
}

static bool throttle_cib_load(float *load) 
{
/*
       /proc/[pid]/stat
              Status information about the process.  This is used by ps(1).  It is defined in /usr/src/linux/fs/proc/array.c.

              The fields, in order, with their proper scanf(3) format specifiers, are:

              pid %d      (1) The process ID.

              comm %s     (2) The filename of the executable, in parentheses.  This is visible whether or not the executable is swapped out.

              state %c    (3) One character from the string "RSDZTW" where R is running, S is sleeping in an interruptible wait, D is waiting in uninterruptible disk sleep, Z is zombie, T is traced or stopped (on a signal), and W is paging.

              ppid %d     (4) The PID of the parent.

              pgrp %d     (5) The process group ID of the process.

              session %d  (6) The session ID of the process.

              tty_nr %d   (7) The controlling terminal of the process.  (The minor device number is contained in the combination of bits 31 to 20 and 7 to 0; the major device number is in bits 15 to 8.)

              tpgid %d    (8) The ID of the foreground process group of the controlling terminal of the process.

              flags %u (%lu before Linux 2.6.22)
                          (9) The kernel flags word of the process.  For bit meanings, see the PF_* defines in the Linux kernel source file include/linux/sched.h.  Details depend on the kernel version.

              minflt %lu  (10) The number of minor faults the process has made which have not required loading a memory page from disk.

              cminflt %lu (11) The number of minor faults that the process's waited-for children have made.

              majflt %lu  (12) The number of major faults the process has made which have required loading a memory page from disk.

              cmajflt %lu (13) The number of major faults that the process's waited-for children have made.

              utime %lu   (14) Amount of time that this process has been scheduled in user mode, measured in clock ticks (divide by sysconf(_SC_CLK_TCK)).  This includes guest time, guest_time (time spent running a virtual CPU, see below), so that applications that are not aware of the guest time field do not lose that time from their calculations.

              stime %lu   (15) Amount of time that this process has been scheduled in kernel mode, measured in clock ticks (divide by sysconf(_SC_CLK_TCK)).
 */

    static char *loadfile = NULL;
    static time_t last_call = 0;
    static long ticks_per_s = 0;
    static unsigned long last_utime, last_stime;

    char buffer[64*1024];
    FILE *stream = NULL;
    time_t now = time(NULL);

    if(load == NULL) {
        return FALSE;
    } else {
        *load = 0.0;
    }

    if(loadfile == NULL) {
        last_call = 0;
        last_utime = 0;
        last_stime = 0;
        loadfile = find_cib_loadfile();
        ticks_per_s = sysconf(_SC_CLK_TCK);
        crm_trace("Found %s", loadfile);
    }

    stream = fopen(loadfile, "r");
    if(stream == NULL) {
        int rc = errno;

        crm_warn("Couldn't read %s: %s (%d)", loadfile, pcmk_strerror(rc), rc);
        free(loadfile); loadfile = NULL;
        return FALSE;
    }

    if(fgets(buffer, sizeof(buffer), stream)) {
        char *comm = calloc(1, 256);
        char state = 0;
        int rc = 0, pid = 0, ppid = 0, pgrp = 0, session = 0, tty_nr = 0, tpgid = 0;
        unsigned long flags = 0, minflt = 0, cminflt = 0, majflt = 0, cmajflt = 0, utime = 0, stime = 0;

        rc = sscanf(buffer,  "%d %[^ ] %c %d %d %d %d %d %lu %lu %lu %lu %lu %lu %lu",
                    &pid, comm, &state,
                    &ppid, &pgrp, &session, &tty_nr, &tpgid,
                    &flags, &minflt, &cminflt, &majflt, &cmajflt, &utime, &stime);
        free(comm);

        if(rc != 15) {
            crm_err("Only %d of 15 fields found in %s", rc, loadfile);
            fclose(stream);
            return FALSE;

        } else if(last_call > 0
           && last_call < now
           && last_utime <= utime
           && last_stime <= stime) {

            time_t elapsed = now - last_call;
            unsigned long delta_utime = utime - last_utime;
            unsigned long delta_stime = stime - last_stime;

            *load = (delta_utime + delta_stime); /* Cast to a float before division */
            *load /= ticks_per_s;
            *load /= elapsed;
            crm_debug("cib load: %f (%lu ticks in %ds)", *load, delta_utime + delta_stime, elapsed);

        } else {
            crm_debug("Init %lu + %lu ticks at %d (%lu tps)", utime, stime, now, ticks_per_s);
        }

        last_call = now;
        last_utime = utime;
        last_stime = stime;

        fclose(stream);
        return TRUE;
    }

    fclose(stream);
    return FALSE;
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
        fclose(stream);
        return TRUE;
    }

    fclose(stream);
    return FALSE;
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
        unsigned long long cpu_use = 0;
        unsigned long long cpu_nic = 0;
        unsigned long long cpu_sys = 0;
        unsigned long long cpu_idl = 0;
        unsigned long long cpu_iow = 0; /* not separated out until the 2.5.41 kernel */
        unsigned long long cpu_xxx = 0; /* not separated out until the 2.6.0-test4 kernel */
        unsigned long long cpu_yyy = 0; /* not separated out until the 2.6.0-test4 kernel */
        unsigned long long cpu_zzz = 0; /* not separated out until the 2.6.11 kernel */

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

        fclose(stream);
        return TRUE;
    }

    fclose(stream);
    return FALSE;
}

static enum throttle_state_e
throttle_handle_load(float load, const char *desc, int cores)
{
    float adjusted_load = load;

    if(cores <= 0) {
        /* No fudging of the supplied load value */

    } else if(cores == 1) {
        /* On a single core machine, a load of 1.0 is already too high */
        adjusted_load = load * THROTTLE_FACTOR_MEDIUM;

    } else {
        /* Normalize the load to be per-core */
        adjusted_load = load / cores;
    }

    if(adjusted_load > THROTTLE_FACTOR_HIGH * throttle_load_target) {
        crm_notice("High %s detected: %f", desc, load);
        return throttle_high;

    } else if(adjusted_load > THROTTLE_FACTOR_MEDIUM * throttle_load_target) {
        crm_info("Moderate %s detected: %f", desc, load);
        return throttle_med;

    } else if(adjusted_load > THROTTLE_FACTOR_LOW * throttle_load_target) {
        crm_debug("Noticable %s detected: %f", desc, load);
        return throttle_low;
    }

    crm_trace("Negligable %s detected: %f", desc, adjusted_load);
    return throttle_none;
}

static enum throttle_state_e
throttle_mode(void)
{
    int cores;
    float load;
    unsigned int blocked = 0;
    enum throttle_state_e mode = throttle_none;

#ifdef ON_SOLARIS
    return throttle_none;
#endif

    cores = throttle_num_cores();
    if(throttle_cib_load(&load)) {
        float cib_max_cpu = 0.95;
        const char *desc = "CIB load";
        /* The CIB is a single threaded task and thus cannot consume
         * more than 100% of a CPU (and 1/cores of the overall system
         * load).
         *
         * On a many cored system, the CIB might therefor be maxed out
         * (causing operations to fail or appear to fail) even though
         * the overall system load is still reasonable.
         *
         * Therefor the 'normal' thresholds can not apply here and we
         * need a special case.
         */
        if(cores == 1) {
            cib_max_cpu = 0.4;
        }
        if(throttle_load_target > 0.0 && throttle_load_target < cib_max_cpu) {
            cib_max_cpu = throttle_load_target;
        }

        if(load > 1.5 * cib_max_cpu) {
            /* Can only happen on machines with a low number of cores */
            crm_notice("Extreme %s detected: %f", desc, load);
            mode |= throttle_extreme;

        } else if(load > cib_max_cpu) {
            crm_notice("High %s detected: %f", desc, load);
            mode |= throttle_high;

        } else if(load > cib_max_cpu * 0.9) {
            crm_info("Moderate %s detected: %f", desc, load);
            mode |= throttle_med;

        } else if(load > cib_max_cpu * 0.8) {
            crm_debug("Noticable %s detected: %f", desc, load);
            mode |= throttle_low;

        } else {
            crm_trace("Negligable %s detected: %f", desc, load);
        }
    }

    if(throttle_load_target <= 0) {
        /* If we ever make this a valid value, the cluster will at least behave as expected */
        return mode;
    }

    if(throttle_load_avg(&load)) {
        mode |= throttle_handle_load(load, "CPU load", cores);
    }

    if(throttle_io_load(&load, &blocked)) {
        mode |= throttle_handle_load(load, "IO load", 0);
        mode |= throttle_handle_load(blocked, "blocked IO ratio", cores);
    }

    if(mode & throttle_extreme) {
        return throttle_extreme;
    } else if(mode & throttle_high) {
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
    static enum throttle_state_e last = -1;

    if(mode != last) {
        crm_info("New throttle mode: %.4x (was %.4x)", mode, last);
        last = mode;

        xml = create_request(CRM_OP_THROTTLE, NULL, NULL, CRM_SYSTEM_CRMD, CRM_SYSTEM_CRMD, NULL);
        crm_xml_add_int(xml, F_CRM_THROTTLE_MODE, mode);
        crm_xml_add_int(xml, F_CRM_THROTTLE_MAX, throttle_job_max);

        send_cluster_message(NULL, crm_msg_crmd, xml, TRUE);
        free_xml(xml);
    }
}

static gboolean
throttle_timer_cb(gpointer data)
{
    static bool send_updates = FALSE;
    enum throttle_state_e now = throttle_none;

    if(send_updates) {
        now = throttle_mode();
        throttle_send_command(now);

    } else if(compare_version(fsa_our_dc_version, "3.0.8") < 0) {
        /* Optimize for the true case */
        crm_trace("DC version %s doesn't support throttling", fsa_our_dc_version);

    } else {
        send_updates = TRUE;
        now = throttle_mode();
        throttle_send_command(now);
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
throttle_update_job_max(const char *preference) 
{
    int max = 0;

    throttle_job_max = 2 * throttle_num_cores();

    if(preference) {
        /* Global preference from the CIB */
        max = crm_int_helper(preference, NULL);
        if(max > 0) {
            throttle_job_max = max;
        }
    }

    preference = getenv("LRMD_MAX_CHILDREN");
    if(preference) {
        /* Legacy env variable */
        max = crm_int_helper(preference, NULL);
        if(max > 0) {
            throttle_job_max = max;
        }
    }

    preference = getenv("PCMK_node_action_limit");
    if(preference) {
        /* Per-node override */
        max = crm_int_helper(preference, NULL);
        if(max > 0) {
            throttle_job_max = max;
        }
    }
}


void
throttle_init(void)
{
    if(throttle_records == NULL) {
        throttle_records = g_hash_table_new_full(
            crm_str_hash, g_str_equal, NULL, throttle_record_free);
        throttle_timer = mainloop_timer_add("throttle", 30 * 1000, TRUE, throttle_timer_cb, NULL);
    }

    throttle_update_job_max(NULL);
    mainloop_timer_start(throttle_timer);
}

void
throttle_fini(void)
{
    mainloop_timer_del(throttle_timer); throttle_timer = NULL;
    g_hash_table_destroy(throttle_records); throttle_records = NULL;
}


int
throttle_get_total_job_limit(int l)
{
    /* Cluster-wide limit */
    GHashTableIter iter;
    int limit = l;
    int peers = crm_active_peers();
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
        /* crm_trace("No change to batch-limit=%d", limit); */

    } else if(l == 0) {
        crm_trace("Using batch-limit=%d", limit);

    } else {
        crm_trace("Using batch-limit=%d instead of %d", limit, l);
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
        r = calloc(1, sizeof(struct throttle_record_s));
        r->node = strdup(node);
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
    enum throttle_state_e mode = 0;
    struct throttle_record_s *r = NULL;
    const char *from = crm_element_value(xml, F_CRM_HOST_FROM);

    crm_element_value_int(xml, F_CRM_THROTTLE_MODE, (int*)&mode);
    crm_element_value_int(xml, F_CRM_THROTTLE_MAX, &max);

    r = g_hash_table_lookup(throttle_records, from);

    if(r == NULL) {
        r = calloc(1, sizeof(struct throttle_record_s));
        r->node = strdup(from);
        g_hash_table_insert(throttle_records, r->node, r);
    }

    r->max = max;
    r->mode = mode;

    crm_debug("Host %s supports a maximum of %d jobs and throttle mode %.4x.  New job limit is %d",
              from, max, mode, throttle_get_job_limit(from));
}

