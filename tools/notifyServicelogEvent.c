/*
 * Original copyright 2009 International Business Machines, IBM, Mark Hamzy
 * Later changes copyright 2009-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
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
#include <inttypes.h>  // PRIu64, SCNu64

#ifndef PCMK__CONFIG_H
#  define PCMK__CONFIG_H
#  include <config.h>
#endif

#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/common/attrd_internal.h>
#include <crm/common/ipc_attrd_internal.h>

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

static pcmk__cli_option_t long_options[] = {
    // long option, argument type, storage, short option, description, flags
    {
        "help", no_argument, NULL, '?',
        "\tThis text", pcmk__option_default
    },
    {
        "version", no_argument, NULL, '$',
        "\tVersion information", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nUsage: notifyServicelogEvent event_id", pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Where event_id is a unique unsigned event identifier which is "
            "then passed into servicelog",
        pcmk__option_paragraph
    },
    { 0, 0, 0, 0 }
};

int
main(int argc, char *argv[])
{
    int argerr = 0;
    int flag;
    int index = 0;

    crm_exit_t exit_code = CRM_EX_OK;
    int rc = pcmk_rc_ok;

    servicelog *slog = NULL;
    struct sl_event *event = NULL;
    uint64_t event_id = 0;

    const char *health_component = "#health-ipmi";
    const char *health_status = NULL;

    pcmk__cli_init_logging("notifyServicelogEvent", 0);
    pcmk__set_cli_options(NULL, "<event_id>", long_options,
                          "handle events written to servicelog database");

    if (argc < 2) {
        argerr++;
    }

    while (1) {
        flag = pcmk__next_cli_option(argc, argv, &index, NULL);
        if (flag == -1)
            break;

        switch (flag) {
            case '?':
            case '$':
                pcmk__cli_help(flag, CRM_EX_OK);
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
        pcmk__cli_help('?', CRM_EX_USAGE);
    }

    openlog("notifyServicelogEvent", LOG_NDELAY, LOG_USER);

    if (sscanf(argv[optind], "%" SCNu64, &event_id) != 1) {
        crm_err("Error: could not read event_id from args!");
        exit_code = CRM_EX_DATAERR;
        goto done;
    }

    if (event_id == 0) {
        crm_err("Error: event_id is 0!");
        exit_code = CRM_EX_DATAERR;
        goto done;
    }

    rc = servicelog_open(&slog, 0);     /* flags is one of SL_FLAG_xxx */
    if (rc != 0) {
        crm_err("Error: Failed to open the servicelog, rc = %d", rc);
        exit_code = CRM_EX_OSERR;
        goto done;
    }

    rc = servicelog_event_get(slog, event_id, &event);
    if (rc != 0) {
        crm_err("Error: Failed to get event from the servicelog, rc = %d", rc);
        exit_code = CRM_EX_OSERR;
        goto done;
    }

    crm_debug("Event id = %" PRIu64 ", Log timestamp = %s, "
              "Event timestamp = %s", event_id, ctime(&(event->time_logged)),
              ctime(&(event->time_event)));

    health_status = status2char(event2status(event));

    // @TODO pass pcmk__node_attr_remote when appropriate
    rc = pcmk__attrd_api_update(NULL, NULL, health_component, health_status,
                                NULL, NULL, NULL, pcmk__node_attr_pattern);
    if (rc == pcmk_rc_ok) {
        crm_debug("Updating attribute %s=%s: %d",
                  health_component, health_status, rc);
    } else {
        crm_err("Could not update %s=%s: %s (%d)",
                health_component, health_status, pcmk_rc_str(rc), rc);
    }

  done:
    if (event != NULL) {
        servicelog_event_free(event);
    }

    if (slog != NULL) {
        servicelog_close(slog);
    }

    closelog();

    if (exit_code == CRM_EX_OK) {
        exit_code = pcmk_rc2exitc(rc);
    }
    crm_exit(exit_code);
}
