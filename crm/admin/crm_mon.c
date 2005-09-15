/* $Id: crm_mon.c,v 1.11 2005/09/15 08:27:40 andrew Exp $ */

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

#include <portability.h>

#include <sys/param.h>

#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <heartbeat.h>
#include <hb_api.h>
#include <clplumbing/uids.h>
#include <clplumbing/cl_pidfile.h>
#include <clplumbing/Gmain_timeout.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ctrl.h>
#include <crm/common/ipc.h>

#include <crm/cib.h>
#include <crm/pengine/pengine.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <crm/dmalloc_wrapper.h>

/* GMainLoop *mainloop = NULL; */
const char *crm_system_name = "crm_mon";

#define OPTARGS	"V?i:nrh:cdp:"

#if CURSES_ENABLED
void usage(const char *cmd, int exit_status);
void blank_screen(void);
int print_status(crm_data_t *cib);
#define printw_at(line, fmt...) move(line, 0); printw(fmt); line++
void wait_for_refresh(int offset, const char *prefix, int seconds);
int print_html_status(crm_data_t *cib, const char *filename);
void make_daemon(gboolean daemonize, const char *pidfile);
gboolean mon_timer_popped(gpointer data);
void mon_update(const HA_Message*, int, int, crm_data_t*,void*);

char *as_html_file = NULL;
char *pid_file = NULL;
gboolean as_console = FALSE;
gboolean group_by_node = FALSE;
gboolean inactive_resources = FALSE;
int interval = 15;
gboolean daemonize = FALSE;
GMainLoop*  mainloop = NULL;
guint timer_id = 0;
cib_t *cib_conn = NULL;
int failed_connections = 0;

int
main(int argc, char **argv)
{
	int argerr = 0;
	int flag;

#ifdef HAVE_GETOPT_H
	int option_index = 0;
	static struct option long_options[] = {
		/* Top-level Options */
		{"verbose", 0, 0, 'V'},
		{"help", 0, 0, '?'},
		{"interval", 1, 0, 'i'},
		{"group-by-node", 0, 0, 'n'},
		{"inactive", 0, 0, 'r'},
		{"as-html", 1, 0, 'h'},		
		{"as-console", 0, 0, 'c'},		
		{"daemonize", 0, 0, 'd'},		
		{"pid-file", 0, 0, 'p'},		

		{0, 0, 0, 0}
	};
#endif
	pid_file = crm_strdup("/tmp/ClusterMon.pid");
	crm_system_name = basename(argv[0]);
	crm_log_init(crm_system_name);
	crm_log_level = LOG_ERR -1;
	
	while (1) {
#ifdef HAVE_GETOPT_H
		flag = getopt_long(argc, argv, OPTARGS,
				   long_options, &option_index);
#else
		flag = getopt(argc, argv, OPTARGS);
#endif
		if (flag == -1)
			break;

		switch(flag) {
			case 'V':
				cl_log_enable_stderr(TRUE);
				alter_debug(DEBUG_INC);
				break;
			case 'i':
				interval = atoi(optarg);
				break;
			case 'n':
				group_by_node = TRUE;
				break;
			case 'r':
				inactive_resources = TRUE;
				break;
			case 'd':
				daemonize = TRUE;
				break;
			case 'p':
				pid_file = crm_strdup(optarg);
				break;
			case 'h':
				as_html_file = crm_strdup(optarg);
				break;
			case 'c':
				as_console = TRUE;
				break;
			default:
				printf("Argument code 0%o (%c) is not (?yet?) supported\n", flag, flag);
				++argerr;
				break;
		}
	}

	if (optind < argc) {
		printf("non-option ARGV-elements: ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
	}
	if (argerr) {
		usage(crm_system_name, LSB_EXIT_GENERIC);
	}

	if(as_html_file == NULL) {
		as_console = TRUE;
	}

	if(daemonize) {
		as_console = FALSE;
	}

	if(daemonize && as_html_file == NULL) {
		usage(crm_system_name, LSB_EXIT_GENERIC);
	}
	
	make_daemon(daemonize, pid_file);

	if(as_console) {
		initscr();
		cbreak();
		noecho();
	}

	crm_info("Starting %s", crm_system_name);
	
	mainloop = g_main_new(FALSE);
	timer_id = Gmain_timeout_add(interval*1000, mon_timer_popped, NULL);
	g_main_run(mainloop);
	return_to_orig_privs();
	
	crm_info("Exiting %s", crm_system_name);	
	
	if(as_console) {
		echo();
		nocbreak();
		endwin();
	}
	return 0;
}

gboolean
mon_timer_popped(gpointer data)
{
	int rc = cib_ok;
	int options = cib_scope_local;

	Gmain_timeout_remove(timer_id);

	if(as_console) {
		move(0, 0);
		printw("Updating...");
		clrtoeol();
		refresh();
	} else {
		crm_notice("Updating...");
	}
	
	if(cib_conn == NULL) {
		crm_debug_4("Creating CIB connection");
		cib_conn = cib_new();
		CRM_DEV_ASSERT(cib_conn != NULL);
	}
	if(cib_conn != NULL && cib_conn->state != cib_connected_query){
		crm_debug_4("Connecting to the CIB");
		if(cib_ok == cib_conn->cmds->signon(
			   cib_conn, crm_system_name, cib_query)) {
			failed_connections = 0;

		} else {
			failed_connections++;
			CRM_DEV_ASSERT(cib_conn->cmds->signoff(cib_conn) == cib_ok);
			wait_for_refresh(0, "Not connected: ", 2*interval);
			return FALSE;
		}
	}
	if(as_console) { blank_screen(); }
	rc = cib_conn->cmds->query(cib_conn, NULL, NULL, options);
	add_cib_op_callback(rc, FALSE, NULL, mon_update);
	return FALSE;
}


void
mon_update(const HA_Message *msg, int call_id, int rc,
	   crm_data_t *output, void*user_data) 
{
	const char *prefix = NULL;
	if(rc == cib_ok) {
		crm_data_t *cib = NULL;
		cib = find_xml_node(output,XML_TAG_CIB,TRUE);
		if(as_html_file) {
			print_html_status(cib, as_html_file);
		}
		if(as_console) {
			print_status(cib);
		}
			
	} else {
		CRM_DEV_ASSERT(cib_conn->cmds->signoff(cib_conn) == cib_ok);
		crm_err("Query failed: %s", cib_error2string(rc));
		prefix = "Query failed! ";
		
	}
	wait_for_refresh(0, prefix, interval);
}

void
wait_for_refresh(int offset, const char *prefix, int seconds) 
{
	int lpc = seconds;

	if(as_console == FALSE) {
		timer_id = Gmain_timeout_add(seconds*1000, mon_timer_popped, NULL);
		return;
	}
	
	crm_notice("%sRefresh in %ds...", prefix?prefix:"", lpc);
	while(lpc > 0) {
		move(offset, 0);
/* 		printw("%sRefresh in \033[01;32m%ds\033[00m...", prefix?prefix:"", lpc); */
		printw("%sRefresh in %ds...", prefix?prefix:"", lpc);
		clrtoeol();
		refresh();
		lpc--;
		if(lpc == 0) {
			timer_id = Gmain_timeout_add(
				1000, mon_timer_popped, NULL);
		} else {
			sleep(1);
		}
	}
}


int
print_status(crm_data_t *cib) 
{
	static int updates = 0;
	int lpc = 0;
	pe_working_set_t data_set;
	node_t *dc = NULL;
	updates++;
	set_working_set_defaults(&data_set);
	data_set.input = cib;
	stage0(&data_set);

	dc = data_set.dc_node;

	lpc++;
	
	printw_at(lpc, "============");
	if(dc == NULL) {
		printw_at(lpc, "Current DC: NONE");
	} else {
		printw_at(lpc, "Current DC: %s (%s)",
			  dc->details->uname, dc->details->id);
	}
	printw_at(lpc, "%d Nodes configured.",
		  g_list_length(data_set.nodes));
	printw_at(lpc, "%d Resources configured.",
		  g_list_length(data_set.resources));
	printw_at(lpc, "============");

	lpc++;
	
	slist_iter(node, node_t, data_set.nodes, lpc2,
		   const char *node_mode = "OFFLINE";
		   if(node->details->standby) {
			   node_mode = "standby";
		   } else if(node->details->online) {
			   node_mode = "online";
		   }
		   
		   printw_at(lpc, "Node: %s (%s): %s",
			     node->details->uname, node->details->id,
			     node_mode);
		   if(group_by_node) {
			   slist_iter(rsc, resource_t,
				      node->details->running_rsc, lpc2,
				      common_printw(rsc, "\t", &lpc);
/* 				      rsc->fns->printw(rsc, "\t", &lpc); */
				      lpc++;
				   );
		   }
		);

	lpc++;
	
	if(group_by_node && inactive_resources) {
		printw_at(lpc, "Full list of resources:");
	}
	if(group_by_node == FALSE || inactive_resources) {
		slist_iter(rsc, resource_t, data_set.resources, lpc2,
			   rsc->fns->printw(rsc, NULL, &lpc);
			   lpc++;
			);
	}
	move(lpc, 0);

	refresh();
	data_set.input = NULL;
	cleanup_calculations(&data_set);
	return lpc;
}

int
print_html_status(crm_data_t *cib, const char *filename) 
{
	static int updates = 0;
	pe_working_set_t data_set;
	node_t *dc = NULL;
	char *filename_tmp = crm_concat(filename, "tmp", '.');

	FILE *stream = fopen(filename_tmp, "w");
	if(stream == NULL) {
		crm_free(filename_tmp);
		return -1;
	}	
	updates++;
	set_working_set_defaults(&data_set);
	data_set.input = cib;
	stage0(&data_set);

	dc = data_set.dc_node;

	fprintf(stream, "<html>");
	fprintf(stream, "<head>");
	fprintf(stream, "<title>Cluster status</title>");
/* content="%d;url=http://webdesign.about.com" */
	fprintf(stream,
		"<meta http-equiv=\"refresh\" content=\"%d\">", interval);
	fprintf(stream, "</head>");

	/*** SUMMARY ***/

	fprintf(stream, "<h2>Cluster summary</h2>");
	{
		char *now_str = NULL;
		time_t now = time(NULL);
		now_str = ctime(&now);
		now_str[24] = EOS; /* replace the newline */
		fprintf(stream, "Last updated: <b>%s</b><br/>\n", now_str);
	}
	
	if(dc == NULL) {
		fprintf(stream, "Current DC: <font color=\"red\"><b>NONE</b></font><br/>");
	} else {
		fprintf(stream, "Current DC: %s (%s)<br/>",
			dc->details->uname, dc->details->id);
	}
	fprintf(stream, "%d Nodes configured.<br/>",
		  g_list_length(data_set.nodes));
	fprintf(stream, "%d Resources configured.<br/>",
		  g_list_length(data_set.resources));

	/*** CONFIG ***/
	
	fprintf(stream, "<h3>Config Options</h3>\n");

	fprintf(stream, "<table>\n");
	fprintf(stream, "<tr><td>Default resource stickiness</td><td>:</td><td>%d</td></tr>\n",
		data_set.default_resource_stickiness);
	
	fprintf(stream, "<tr><td>STONITH of failed nodes</td><td>:</td><td>%s</td></tr>\n",
		data_set.stonith_enabled?"enabled":"disabled");

	fprintf(stream, "<tr><td>Cluster is</td><td>:</td><td>%ssymmetric</td></tr>\n",
		data_set.symmetric_cluster?"":"a-");
	
	fprintf(stream, "<tr><td>No Quorum Policy</td><td>:</td><td>");
	switch (data_set.no_quorum_policy) {
		case no_quorum_freeze:
			fprintf(stream, "Freeze resources");
			break;
		case no_quorum_stop:
			fprintf(stream, "Stop ALL resources");
			break;
		case no_quorum_ignore:
			fprintf(stream, "Ignore");
			break;
	}
	fprintf(stream, "\n</td></tr>\n</table>\n");

	/*** NODE LIST ***/
	
	fprintf(stream, "<h2>Node List</h2>\n");
	fprintf(stream, "<ul>\n");
	slist_iter(node, node_t, data_set.nodes, lpc2,
		   fprintf(stream, "<li>");
		   fprintf(stream, "Node: %s (%s): %s",
			     node->details->uname, node->details->id,
			     node->details->online?"<font color=\"green\">online</font>\n":"<font color=\"orange\"><b>OFFLINE</b></font>\n");
		   if(group_by_node) {
			   fprintf(stream, "<ul>\n");
			   slist_iter(rsc, resource_t,
				      node->details->running_rsc, lpc2,
				      fprintf(stream, "<li>");
				      common_html(rsc, "\t", stream);
				      fprintf(stream, "</li>\n");
				   );
			   fprintf(stream, "</ul>\n");
		   }
		   fprintf(stream, "</li>\n");
		);
	fprintf(stream, "</ul>\n");
	
	if(group_by_node && inactive_resources) {
		fprintf(stream, "<h2>(Partially) Inactive Resources</h2>\n");

	} else if(group_by_node == FALSE)  {
		fprintf(stream, "<h2>Resource List</h2>\n");
	}
	
	if(group_by_node == FALSE || inactive_resources) {
		slist_iter(rsc, resource_t, data_set.resources, lpc2,
			   if(group_by_node && rsc->fns->active(rsc, TRUE)) {
				   continue;
			   }
			   rsc->fns->html(rsc, NULL, stream);
			);
	}

	data_set.input = NULL;
	cleanup_calculations(&data_set);
	fprintf(stream, "</html>");
	fflush(stream);
	fclose(stream);

	if(rename(filename_tmp, filename) != 0) {
		cl_perror("Unable to rename %s->%s", filename_tmp, filename);
	}
	crm_free(filename_tmp);
	return 0;
}


void
blank_screen(void) 
{
	int lpc = 0;
	for(lpc = 0; lpc < LINES; lpc++) {
		move(lpc, 0);
		clrtoeol();
	}
	move(0, 0);
}


void
usage(const char *cmd, int exit_status)
{
	FILE *stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s [-%s]\n", cmd, OPTARGS);
	fprintf(stream, "\t--%s (-%c) \t: This text\n", "help", '?');
	fprintf(stream, "\t--%s (-%c) \t: Increase the debug output\n", "verbose", 'V');
	fprintf(stream, "\t--%s (-%c) <seconds>\t: Update frequency\n", "interval", 'i');
	fprintf(stream, "\t--%s (-%c) \t:Group resources by node\n", "group-by-node", 'n');
	fprintf(stream, "\t--%s (-%c) \t:Display inactive resources\n", "inactive", 'r');
	fprintf(stream, "\t--%s (-%c) \t: Display cluster status on the console\n", "as-console", 'c');
	fprintf(stream, "\t--%s (-%c) <filename>\t: Write cluster status to the named file\n", "as-html", 'h');
	fprintf(stream, "\t--%s (-%c) \t: Run in the background as a daemon\n", "daemonize", 'd');
	fprintf(stream, "\t--%s (-%c) <filename>\t: Daemon pid file location\n", "pid-file", 'p');

	fflush(stream);

	exit(exit_status);
}

void
make_daemon(gboolean daemonize, const char *pidfile)
{
	long pid;
	const char *devnull = "/dev/null";

	if (daemonize == FALSE){
		return;
	}
	
	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "%s: could not start daemon\n",
			crm_system_name);
		perror("fork");
		exit(LSB_EXIT_GENERIC);
	} else if (pid > 0) {
		exit(LSB_EXIT_OK);
	}
	
	if (cl_lock_pidfile(pidfile) < 0 ){
		pid = cl_read_pidfile(pidfile);
		fprintf(stderr, "%s: already running [pid %ld].\n",
			crm_system_name, pid);
		exit(LSB_EXIT_OK);
	}
	
	umask(022);
	close(FD_STDIN);
	(void)open(devnull, O_RDONLY);		/* Stdin:  fd 0 */
	close(FD_STDOUT);
	(void)open(devnull, O_WRONLY);		/* Stdout: fd 1 */
	close(FD_STDERR);
	(void)open(devnull, O_WRONLY);		/* Stderr: fd 2 */
}

#else
int
main(int argc, char **argv)
{
	fprintf(stderr, "The use of %s requires ncurses to be available"
		" during the build process\n", crm_system_name);
	exit(1);
}
#endif
