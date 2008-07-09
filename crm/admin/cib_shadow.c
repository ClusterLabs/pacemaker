
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

#include <clplumbing/uids.h>
#include <clplumbing/Gmain_timeout.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ctrl.h>
#include <crm/common/ipc.h>

#include <crm/cib.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

int exit_code = cib_ok;
GMainLoop *mainloop = NULL;
IPC_Channel *crmd_channel = NULL;

const char *host = NULL;
void usage(const char *cmd, int exit_status);

int command_options = cib_sync_call;
const char *cib_action = NULL;

cib_t *real_cib = NULL;

static int force_flag = 0;
#define OPTARGS	"V?wc:d:r:C:D:p:s:"


int
main(int argc, char **argv)
{
    int rc = 0;
    int flag;
    int argerr = 0;
    static int command = '?';
    char *shadow = NULL;
    char *shadow_file = NULL;
    gboolean dangerous_cmd = FALSE;
    struct stat buf;
	
#ifdef HAVE_GETOPT_H
    int option_index = 0;
    static struct option long_options[] = {
	/* Top-level Options */
	{"create",  required_argument, NULL, 'c'},
	{"display", required_argument, NULL, 'P'},
	{"commit",  required_argument, NULL, 'C'},
	{"delete",  required_argument, NULL, 'D'},
	{"reset",   required_argument, NULL, 'r'},
	{"which",   no_argument,       NULL, 'w'},
	{"diff",    required_argument, NULL, 'd'},
	{"switch",  required_argument, NULL, 's'},

	{"force",	no_argument, &force_flag, 1},
	{"xml-text",    required_argument, NULL, 'X'},
	{"xml-file",    required_argument, NULL, 'x'},
	{"xml-pipe",    no_argument, NULL, 'p'},
	{"verbose",     no_argument, NULL, 'V'},
	{"help",        no_argument, NULL, '?'},

	{0, 0, 0, 0}
    };
#endif

    crm_log_init("cib_shadow", LOG_CRIT, FALSE, FALSE, argc, argv);
	
    if(argc < 2) {
	usage(crm_system_name, LSB_EXIT_EINVAL);
    }

    while (1) {
#ifdef HAVE_GETOPT_H
	flag = getopt_long(argc, argv, OPTARGS,
			   long_options, &option_index);
#else
	flag = getopt(argc, argv, OPTARGS);
#endif
	if (flag == -1 || flag == 0)
	    break;

	switch(flag) {
	    case 'c':
	    case 'd':
	    case 's':
	    case 'p':
	    case 'r':
	    case 'w':
		command = flag;
		shadow = crm_strdup(optarg);
		break;
	    case 'C':
	    case 'D':
		command = flag;
		dangerous_cmd = TRUE;
		shadow = crm_strdup(optarg);
		break;
	    case 'V':
		command_options = command_options | cib_verbose;
		cl_log_enable_stderr(TRUE);
		alter_debug(DEBUG_INC);
		break;
	    case '?':
		usage(crm_system_name, LSB_EXIT_OK);
		break;
	    case 'f':
		command_options |= cib_quorum_override;
		break;
	    default:
		printf("Argument code 0%o (%c)"
		       " is not (?yet?) supported\n",
		       flag, flag);
		++argerr;
		break;
	}
    }

    if (optind < argc) {
	printf("non-option ARGV-elements: ");
	while (optind < argc)
	    printf("%s ", argv[optind++]);
	printf("\n");
	usage(crm_system_name, LSB_EXIT_EINVAL);
    }

    if (optind > argc) {
	++argerr;
    }
	
    if (argerr) {
	usage(crm_system_name, LSB_EXIT_GENERIC);
    }

    if(command == 'w') {
	/* which shadow instance is active? */
	const char *local = getenv("CIB_shadow");
	if(local == NULL) {
	    fprintf(stderr, "No shadow instance provided\n");
	    return cib_NOTEXISTS;
	}
	fprintf(stdout, "%s\n", local);
	return 0;
    }
    
    if(shadow == NULL) {
	fprintf(stderr, "No shadow instance provided\n");
	fflush(stderr);
	return CIBRES_MISSING_FIELD;

    } else if(command != 's') {
	const char *local = getenv("CIB_shadow");
	if(local != NULL && safe_str_neq(local, shadow) && force_flag == FALSE) {
	    fprintf(stderr, "The supplied shadow instance (%s) is not the same as the active one (%s).\n"
		    "  To prevent accidental destruction of the cluster,"
		    " the --force flag is required in order to proceed.\n", shadow, local);
	    fflush(stderr);
	    usage(crm_system_name, LSB_EXIT_GENERIC);
	}
    }

    if(dangerous_cmd && force_flag == FALSE) {
	fprintf(stderr, "The supplied command is considered dangerous."
		"  To prevent accidental destruction of the cluster,"
		" the --force flag is required in order to proceed.\n");
	fflush(stderr);
	usage(crm_system_name, LSB_EXIT_GENERIC);
    }

    shadow_file = get_shadow_file(shadow);
    if(command == 'D') {
	/* delete the file */
	rc = stat(shadow_file, &buf);
	if(rc == 0) {
	    rc = unlink(shadow_file);
	    if(rc != 0) {
		fprintf(stderr, "Could not remove shadow instance '%s': %s\n", shadow, strerror(errno));
		return rc;
	    }
	}
	printf("Please remember to unset the CIB_shadow variable by pasting the following into your shell:\n");
	printf("  unset CIB_shadow\n");
	return rc;
    }

    if(command == 'd' || command == 'r' || command == 'c' || command == 'C') {
	real_cib = cib_new_no_shadow();
	rc = real_cib->cmds->signon(real_cib, crm_system_name, cib_command);
	if(rc != cib_ok) {
	    fprintf(stderr, "Signon to CIB failed: %s\n", cib_error2string(rc));
	    return rc;
	}
    }
    
    rc = stat(shadow_file, &buf);
    if(rc != 0 && command != 'c') {
	fprintf(stderr, "Could not access shadow instance '%s': %s\n", shadow, strerror(errno));
	return cib_NOTEXISTS;
    }

    if(command == 'c') {
	xmlNode *output = NULL;
	/* create a shadow instance based on the current cluster config */
	if (rc == 0 && force_flag == FALSE) {
	    fprintf(stderr, "A shadow instance '%s' already exists.\n"
		   "  To prevent accidental destruction of the cluster,"
		   " the --force flag is required in order to proceed.\n", shadow);
	    return cib_EXISTS;
	}
	
	rc = real_cib->cmds->query(real_cib, NULL, &output, command_options);
	if(rc != cib_ok) {
	    fprintf(stderr, "Could not connect to the CIB: %s\n", cib_error2string(rc));
	    return rc;
	}
	
	rc = write_xml_file(output, shadow_file, FALSE);
	if(rc < 0) {
	    fprintf(stderr, "Could not create the shadow instance '%s': %s\n",
		    shadow, strerror(errno));
	    return rc;
	}

	printf("A new shadow instance was created.  To begin using it paste the following into your shell:\n");
	printf("  CIB_shadow=%s ; export CIB_shadow\n", shadow);

    } else if(command == 's') {
	printf("To switch to the named shadow instance, paste the following into your shell:\n");
	printf("  CIB_shadow=%s ; export CIB_shadow\n", shadow);
	return 0;
    
    } else if(command == 'P') {
	/* display the current contents */
	char *output_s = NULL;
	FILE *shadow_FILE = fopen(shadow_file, "r");
	xmlNode *output = file2xml(shadow_FILE, FALSE);
	
	output_s = dump_xml_formatted(output);
	printf("%s", output_s);
	
	crm_free(output_s);
	free_xml(output);
	
    } else if(command == 'd') {
	/* diff against cluster */
	FILE *shadow_FILE = fopen(shadow_file, "r");

	xmlNode *diff = NULL;
	xmlNode *old_config = NULL;
	xmlNode *new_config = file2xml(shadow_FILE, FALSE);
	
	rc = real_cib->cmds->query(real_cib, NULL, &old_config, command_options);
	
	if(rc != cib_ok) {
	    fprintf(stderr, "Could not query the CIB: %s\n", cib_error2string(rc));
	    return rc;
	}

	diff = diff_xml_object(old_config, new_config, FALSE);
	if(diff != NULL) {
	    print_xml_diff(stderr, diff);
	    return 1;
	}
	return 0;	
	
    } else if(command == 'C') {
	/* commit to the cluster */
	FILE *shadow_FILE = fopen(shadow_file, "r");
	xmlNode *input = file2xml(shadow_FILE, FALSE);
	rc = real_cib->cmds->replace(real_cib, NULL, input, command_options);
	if(rc != cib_ok) {
	    fprintf(stderr, "Could not commit shadow instance '%s' to the CIB: %s\n",
		    shadow, cib_error2string(rc));
	    return rc;
	}	
	printf("Please remember to unset the CIB_shadow variable by pasting the following into your shell:\n");
	printf("  unset CIB_shadow\n");
    }

    return rc;
}

void
usage(const char *cmd, int exit_status)
{
    FILE *stream;

    stream = exit_status != 0 ? stderr : stdout;

    fprintf(stream, "usage: %s -[%s]\n", cmd, OPTARGS);
    
    fprintf(stream, "Options\n");
    fprintf(stream, "\t--%s (-%c)\tturn on debug info."
	    "  additional instance increase verbosity\n", "verbose", 'V');
    fprintf(stream, "\t--%s (-%c)\tthis help message\n", "help   ", '?');
    fprintf(stream, "\nCommands\n");
    fprintf(stream, "\t--%s (-%c)\tIndicate the active shadow copy\n", "which  ", 'w');
    fprintf(stream, "\t--%s (-%c) name\tCreate the named shadow copy of the active cluster configuration\n", "create ", 'c');
    fprintf(stream, "\t--%s (-%c) name\tDisplay the contents of the named shadow copy \n", "display", 'P');
    fprintf(stream, "\t--%s (-%c) name\tDisplay the changes in the named shadow copy \n", "diff", 'd');
    fprintf(stream, "\t--%s (-%c) name\tRecreate the named shadow copy from the active cluster configuration\n", "reset  ",   'r');
    fprintf(stream, "\t--%s (-%c) name\tUpload the contents of the named shadow copy to the cluster\n", "commit ",  'C');
    fprintf(stream, "\t--%s (-%c) name\tDelete the contents of the named shadow copy\n", "delete ",  'D');
    fprintf(stream, "\nAdvanced Options\n");
    fprintf(stream, "\t--%s (-%c)\tForce the action to be performed\n", "force ",  'f');
    fprintf(stream, "\t--%s (-%c) name\tSwitch to the named shadow copy \n", "switch", 's');

    fflush(stream);

    exit(exit_status);
}
