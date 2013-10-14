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

enum throttle_state_e 
{
    throttle_high = 0x0100,
    throttle_med  = 0x0010,
    throttle_low  = 0x0001,
    throttle_none = 0x0000,
};

void throttle_init(void);
void throttle_fini(void);

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
        /* Grab the 1-minute average, ignore the rest */
        load = strtof(buffer, NULL);
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

    if(simple_load > 0.8) {
        mode |= throttle_high;
    } else if(simple_load > 0.6) {
        mode |= throttle_med;
    } else if(simple_load > 0.4) {
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

static gboolean
throttle_timer_cb(gpointer data)
{
    static enum throttle_state_e last = throttle_none;
    enum throttle_state_e now = throttle_mode();

    if(now != last) {
        crm_debug("New throttle mode: %.4x (was %.4x)", now, last);
        last = now;
    }
    return TRUE;
}

mainloop_timer_t *throttle_timer = NULL;

void
throttle_init(void) 
{
    throttle_timer = mainloop_timer_add("throttle", 30* 1000, TRUE, throttle_timer_cb, NULL);
    crm_debug("load avg: %f on %d cores", throttle_load_avg(), throttle_num_cores());
    /* mainloop_timer_start(throttle_timer); */
}

void
throttle_fini(void) 
{
    mainloop_timer_del(throttle_timer);
}

