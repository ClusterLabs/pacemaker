/*
 * Copyright 2009-2018 International Business Machines, IBM, Mark Hamzy
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

/* gcc -o notifyServicelogEvent `pkg-config --cflags servicelog-1` `pkg-config --libs servicelog-1` notifyServicelogEvent.c
*/

#include <crm_internal.h>

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <servicelog.h>
#include <syslog.h>
#include <unistd.h>
#include <config.h>
#include <inttypes.h>  /* U64T ~ PRIu64, U64TS ~ SCNu64 */

#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/attrd.h>

typedef enum { STATUS_GREEN = 1, STATUS_YELLOW, STATUS_RED } STATUS;

const char *status2char(STATUS status);
STATUS event2status(struct sl_event *event);

const char *
status2char(STATUS status)
{
    switch (status) {
        default:
        case STATUS_GREEN:
            return "green";
        case STATUS_YELLOW:
            return "yellow";
        case STATUS_RED:
            return "red";
    }
}

STATUS
event2status(struct sl_event * event)
{
    STATUS status = STATUS_GREEN;

    crm_debug("Severity = %d, Disposition = %d", event->severity, event->disposition);

    /* @TBD */
    if (event->severity == SL_SEV_WARNING) {
        status = STATUS_YELLOW;
    }

    if (event->disposition == SL_DISP_UNRECOVERABLE) {
        status = STATUS_RED;
    }

    return status;
}

static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help", 0, 0, '?', "\tThis text"},
    {"version", 0, 0, '$', "\tVersion information"},
    {"-spacer-", 0, 0, '-', "\nUsage: notifyServicelogEvent event_id"},
    {"-spacer-", 0, 0, '-',
     "\nWhere event_id is unique unsigned event identifier which is then passed into servicelog"},

    {0, 0, 0, 0}
};

int
main(int argc, char *argv[])
{
    int argerr = 0;
    int flag;
    int index = 0;
    int rc = 0;
    servicelog *slog = NULL;
    struct sl_event *event = NULL;
    uint64_t event_id = 0;

    crm_log_cli_init("notifyServicelogEvent");
    crm_set_options(NULL, "event_id ", long_options,
                    "Gets called upon events written to servicelog database");

    if (argc < 2) {
        argerr++;
    }

    while (1) {
        flag = crm_get_option(argc, argv, &index);
        if (flag == -1)
            break;

        switch (flag) {
            case '?':
            case '$':
                crm_help(flag, CRM_EX_OK);
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (argc - optind != 1) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', CRM_EX_USAGE);
    }

    openlog("notifyServicelogEvent", LOG_NDELAY, LOG_USER);

    if (sscanf(argv[optind], "%" U64TS, &event_id) != 1) {
        crm_err("Error: could not read event_id from args!");

        rc = 1;
        goto cleanup;
    }

    if (event_id == 0) {
        crm_err("Error: event_id is 0!");

        rc = 1;
        goto cleanup;
    }

    rc = servicelog_open(&slog, 0);     /* flags is one of SL_FLAG_xxx */

    if (!slog) {
        crm_err("Error: servicelog_open failed, rc = %d", rc);

        rc = 1;
        goto cleanup;
    }

    if (slog) {
        rc = servicelog_event_get(slog, event_id, &event);
    }

    if (rc == 0) {
        STATUS status = STATUS_GREEN;
        const char *health_component = "#health-ipmi";
        const char *health_status = NULL;

        crm_debug("Event id = %" U64T ", Log timestamp = %s, Event timestamp = %s",
                  event_id, ctime(&(event->time_logged)), ctime(&(event->time_event)));

        status = event2status(event);

        health_status = status2char(status);

        if (health_status) {
            gboolean rc;

            /* @TODO pass attrd_opt_remote when appropriate */
            rc = (attrd_update_delegate(NULL, 'v', NULL, health_component,
                                        health_status, NULL, NULL, NULL, NULL,
                                        attrd_opt_none) > 0);
            crm_debug("Updating attribute ('%s', '%s') = %d",
                      health_component, health_status, rc);
        } else {
            crm_err("Error: status2char failed, status = %d", status);
            rc = 1;
        }
    } else {
        crm_err("Error: servicelog_event_get failed, rc = %d", rc);
    }

  cleanup:
    if (event) {
        servicelog_event_free(event);
    }

    if (slog) {
        servicelog_close(slog);
    }

    closelog();

    return rc;
}
