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

#include <crm/common/attrd_internal.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/ipc_attrd_internal.h>

const char *summary = "notifyServicelogEvent - handle events written to "
                      "servicelog database";

typedef enum { STATUS_GREEN, STATUS_YELLOW, STATUS_RED } STATUS;

static const char *
status2char(STATUS status)
{
    switch (status) {
        case STATUS_GREEN:
            return "green";
        case STATUS_YELLOW:
            return "yellow";
        case STATUS_RED:
            return "red";
        default:
            return NULL;
    }
}

static STATUS
event2status(struct sl_event * event)
{
    crm_debug("Severity = %d, Disposition = %d", event->severity, event->disposition);

    /* @TBD */
    if (event->disposition == SL_DISP_UNRECOVERABLE) {
        return STATUS_RED;
    }

    if (event->severity == SL_SEV_WARNING) {
        return STATUS_YELLOW;
    }

    return STATUS_GREEN;
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group)
{
    GOptionContext *context = NULL;
    const char *description = "event_id is a unique unsigned event identifier "
                              "that is passed into servicelog.\n";

    context = pcmk__build_arg_context(args, NULL, NULL, "event_id");
    g_option_context_set_description(context, description);

    return context;
}

int
main(int argc, char *argv[])
{
    crm_exit_t exit_code = CRM_EX_OK;
    int rc = pcmk_rc_ok;

    servicelog *slog = NULL;
    struct sl_event *event = NULL;
    uint64_t event_id = 0;

    const char *health_component = "#health-ipmi";
    const char *health_status = NULL;

    GError *error = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(summary);
    gchar **processed_args = pcmk__cmdline_preproc(argv, NULL);
    GOptionContext *context = build_arg_context(args, &output_group);

    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("notifyServicelogEvent", 0);

    if (args->version) {
        printf("Pacemaker %s\n", PACEMAKER_VERSION);
        printf("Written by Andrew Beekhof and the Pacemaker project "
               "contributors\n");
        goto done;
    }

    if (g_strv_length(processed_args) != 2) {
        char *help = g_option_context_get_help(context, TRUE, NULL);

        fprintf(stderr, "%s", help);
        g_free(help);
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    openlog("notifyServicelogEvent", LOG_NDELAY, LOG_USER);

    if (sscanf(argv[optind], "%" SCNu64, &event_id) != 1) {
        g_set_error(&error, PCMK__RC_ERROR, EINVAL,
                    "Error: could not read event_id from args!");
        exit_code = CRM_EX_DATAERR;
        goto done;
    }

    if (event_id == 0) {
        g_set_error(&error, PCMK__RC_ERROR, EINVAL, "Error: event_id is 0!");
        exit_code = CRM_EX_DATAERR;
        goto done;
    }

    rc = servicelog_open(&slog, 0);     /* flags is one of SL_FLAG_xxx */
    if (rc != 0) {
        g_set_error(&error, PCMK__RC_ERROR, EIO,
                    "Error: Failed to open the servicelog, rc = %d", rc);
        exit_code = CRM_EX_OSERR;
        goto done;
    }

    rc = servicelog_event_get(slog, event_id, &event);
    if (rc != 0) {
        g_set_error(&error, PCMK__RC_ERROR, EIO,
                    "Error: Failed to get event from the servicelog, rc = %d",
                    rc);
        exit_code = CRM_EX_OSERR;
        goto done;
    }

    crm_debug("Event id = %" PRIu64 ", Log timestamp = %s, "
              "Event timestamp = %s", event_id, ctime(&(event->time_logged)),
              ctime(&(event->time_event)));

    health_status = status2char(event2status(event));

    // @TODO pass pcmk__node_attr_remote when appropriate
    rc = pcmk__attrd_api_update(NULL, NULL, health_component, health_status,
                                NULL, NULL, NULL, pcmk__node_attr_value);
    if (rc == pcmk_rc_ok) {
        crm_debug("Updating attribute %s=%s: %d",
                  health_component, health_status, rc);
    } else {
        crm_err("Could not update %s=%s: %s (%d)",
                health_component, health_status, pcmk_rc_str(rc), rc);
    }

  done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

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
    pcmk__output_and_clear_error(error, NULL);
    crm_exit(exit_code);
}
