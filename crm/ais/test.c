
/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <clplumbing/Gmain_timeout.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crm/cib.h>

#include <crm/ais.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

int message_timer_id = -1;
int message_timeout_ms = 30*1000;

GMainLoop *mainloop = NULL;

void usage(const char *cmd, int exit_status);

#define OPTARGS	"V?K:S:HE:Dd:i:RNqt:Bv"

int
main(int argc, char **argv)
{
    int rc = 0;
    const char *host = NULL;
    crm_data_t *msg = NULL;
    
    crm_log_init(basename(argv[0]), LOG_DEBUG, FALSE, TRUE, 0, NULL);
    
    msg = create_xml_node(NULL, XML_TAG_OPTIONS);
    crm_xml_add(msg, "hello", "world");
    crm_xml_add(msg, "time", "now");

    if(argc > 1) {
	host = argv[1];
    }
    
    rc = send_ais_message(msg, FALSE, host, crm_msg_ais);
    if (rc != SA_AIS_OK) {
	return 1;
    }

    mainloop = g_main_new(FALSE);
/*     message_timer_id = Gmain_timeout_add( */
/* 	message_timeout_ms, admin_message_timeout, NULL); */
	
    g_main_run(mainloop);
	
    crm_debug_2("%s exiting normally", crm_system_name);
    return 0;
}


void
usage(const char *cmd, int exit_status)
{
    FILE *stream;

    stream = exit_status ? stderr : stdout;

    fprintf(stream, "usage: %s [-?Vs] [command] [command args]\n", cmd);

    fprintf(stream, "Options\n");
    fprintf(stream, "\t--%s (-%c)\t: this help message\n", "help", '?');
    fflush(stream);

    exit(exit_status);
}
