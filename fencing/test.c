/* 
 * Copyright (C) 2009 Andrew Beekhof <andrew@beekhof.net>
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

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/utsname.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/cluster/internal.h>

#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/common/xml.h>


/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    {"verbose",     0, 0, 'V'},
    {"version",     0, 0, '$'},
    {"help",        0, 0, '?'},
    {"passive",     0, 0, 'p'},

    {0, 0, 0, 0}
};
/* *INDENT-ON* */

int st_opts = st_opt_sync_call;

static void st_callback(stonith_t *st, stonith_event_t *e)
{
    if(st->state == stonith_disconnected) {
        exit(1);
    }

    crm_notice("Operation %s requested by %s %s for peer %s.  %s reported: %s (ref=%s)",
               e->operation, e->origin, e->result == pcmk_ok?"completed":"failed",
               e->target, e->executioner ? e->executioner : "<none>",
               pcmk_strerror(e->result), e->id);
}

static  void
st_global_callback(stonith_t * stonith, const xmlNode * msg, int call_id, int rc,
                   xmlNode * output, void *userdata)
{
    crm_log_xml_notice((xmlNode*)msg, "Event");
}


int
main(int argc, char ** argv)
{
    int argerr = 0;
    int flag;
    int option_index = 0;
    int rc = 0;

    char *tmp = NULL;
    struct pollfd pollfd;
    stonith_t *st = NULL;

    stonith_key_value_t *params = NULL;
    gboolean passive_mode = FALSE;

    crm_log_cli_init("stonith-test");
    crm_set_options(NULL, "mode [options]", long_options,
            "Provides a summary of cluster's current state."
            "\n\nOutputs varying levels of detail in a number of different formats.\n");

    params = stonith_key_value_add(params, "pcmk_host_map", "some-host=pcmk-7 pcmk-3=3,4");

    while (1) {
        flag = crm_get_option(argc, argv, &option_index);
        if (flag == -1) {
            break;
        }

        switch(flag) {
        case 'V':
            crm_bump_log_level();
            break;
        case '$':
        case '?':
            crm_help(flag, EX_OK);
            break;
        case 'p':
            passive_mode = TRUE;
            break;
            default:
            ++argerr;
            break;
        }
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', EX_USAGE);
    }

    crm_debug("Create");
    st = stonith_api_new();

    rc = st->cmds->connect(st, crm_system_name, &pollfd.fd);
    crm_debug("Connect: %d", rc);

    rc = st->cmds->register_notification(st, T_STONITH_NOTIFY_DISCONNECT, st_callback);

    if(passive_mode) {
        rc = st->cmds->register_notification(st, T_STONITH_NOTIFY_FENCE, st_callback);
        rc = st->cmds->register_notification(st, STONITH_OP_DEVICE_ADD, st_callback);
        rc = st->cmds->register_notification(st, STONITH_OP_DEVICE_DEL, st_callback);

        st->cmds->register_callback(st, 0, 120, FALSE, NULL, "st_global_callback", st_global_callback);

        crm_info("Looking for notification");
        pollfd.events = POLLIN;
        while(true) {
            rc = poll( &pollfd, 1, 600 * 1000 );    /* wait 10 minutes, -1 forever */
            if (rc > 0 )
               stonith_dispatch( st );
            else
                break;
        }

    } else {
        rc = st->cmds->register_device(st, st_opts, "test-id", "stonith-ng", "fence_xvm", params);
        crm_debug("Register: %d", rc);

        rc = st->cmds->list(st, st_opts, "test-id", &tmp, 10);
        crm_debug("List: %d output: %s\n", rc, tmp ? tmp : "<none>");

        rc = st->cmds->monitor(st, st_opts, "test-id", 10);
        crm_debug("Monitor: %d", rc);

        rc = st->cmds->status(st, st_opts, "test-id", "pcmk-2", 10);
        crm_debug("Status pcmk-2: %d", rc);

        rc = st->cmds->status(st, st_opts, "test-id", "pcmk-1", 10);
        crm_debug("Status pcmk-1: %d", rc);

        rc = st->cmds->fence(st, st_opts, "unknown-host", "off", 60);
        crm_debug("Fence unknown-host: %d", rc);

        rc = st->cmds->status(st, st_opts,  "test-id", "pcmk-1", 10);
        crm_debug("Status pcmk-1: %d", rc);

        rc = st->cmds->fence(st, st_opts, "pcmk-1", "off", 60);
        crm_debug("Fence pcmk-1: %d", rc);

        rc = st->cmds->status(st, st_opts, "test-id", "pcmk-1", 10);
        crm_debug("Status pcmk-1: %d", rc);

        rc = st->cmds->fence(st, st_opts, "pcmk-1", "on", 10);
        crm_debug("Unfence pcmk-1: %d", rc);

        rc = st->cmds->status(st, st_opts, "test-id", "pcmk-1", 10);
        crm_debug("Status pcmk-1: %d", rc);

        rc = st->cmds->fence(st, st_opts, "some-host", "off", 10);
        crm_debug("Fence alias: %d", rc);

        rc = st->cmds->status(st, st_opts, "test-id", "some-host", 10);
        crm_debug("Status alias: %d", rc);

        rc = st->cmds->fence(st, st_opts, "pcmk-1", "on", 10);
        crm_debug("Unfence pcmk-1: %d", rc);

        rc = st->cmds->remove_device(st, st_opts, "test-id");
        crm_debug("Remove test-id: %d", rc);
    }

    stonith_key_value_freeall(params, 1, 1);

    rc = st->cmds->disconnect(st);
    crm_debug("Disconnect: %d", rc);

    crm_debug("Destroy");
    stonith_api_delete(st);

    return rc;
}
