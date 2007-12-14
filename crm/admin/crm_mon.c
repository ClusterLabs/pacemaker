
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
#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <clplumbing/uids.h>
#include <clplumbing/cl_pidfile.h>
#include <clplumbing/Gmain_timeout.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ctrl.h>
#include <crm/common/ipc.h>

#include <crm/cib.h>
#include <crm/pengine/status.h>
#include <lib/crm/pengine/unpack.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif


/* GMainLoop *mainloop = NULL; */
#define OPTARGS	"V?i:nrh:cdp:s1wX:"


void usage(const char *cmd, int exit_status);
void blank_screen(void);
int print_status(crm_data_t *cib);
void print_warn(const char *descr);
int print_simple_status(crm_data_t *cib);
/* #define printw_at(line, fmt...) move(line, 0); printw(fmt); line++ */
void wait_for_refresh(int offset, const char *prefix, int msec);
int print_html_status(crm_data_t *cib, const char *filename, gboolean web_cgi);
void make_daemon(gboolean daemonize, const char *pidfile);
gboolean mon_timer_popped(gpointer data);
void mon_update(const HA_Message*, int, int, crm_data_t*,void*);

char *xml_file = NULL;
char *as_html_file = NULL;
char *pid_file = NULL;
gboolean as_console = FALSE;
gboolean simple_status = FALSE;
gboolean group_by_node = FALSE;
gboolean inactive_resources = FALSE;
gboolean web_cgi = FALSE;
int interval = 15000;
gboolean daemonize = FALSE;
GMainLoop*  mainloop = NULL;
guint timer_id = 0;
cib_t *cib_conn = NULL;
int failed_connections = 0;
gboolean one_shot = FALSE;
gboolean has_warnings = FALSE;

#if CURSES_ENABLED
#  define print_as(fmt...) if(as_console) {	\
		printw(fmt);			\
	} else {				\
		fprintf(stdout, fmt);		\
	}
#else
#  define print_as(fmt...) fprintf(stdout, fmt);
#endif

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
		{"web-cgi", 0, 0, 'w'},
		{"simple-status", 0, 0, 's'},
		{"as-console", 0, 0, 'c'},		
		{"one-shot", 0, 0, '1'},		
		{"daemonize", 0, 0, 'd'},		
		{"pid-file", 0, 0, 'p'},		
		{"xml-file", 1, 0, 'X'},		

		{0, 0, 0, 0}
	};
#endif
	pid_file = crm_strdup("/tmp/ClusterMon.pid");
	crm_log_init(basename(argv[0]), LOG_ERR-1, FALSE, FALSE, 0, NULL);

	if (strcmp(crm_system_name, "crm_mon.cgi")==0) {
		web_cgi = TRUE;
		one_shot = TRUE;
	}
	
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
				interval = crm_get_msec(optarg);
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
			case 'X':
				xml_file = crm_strdup(optarg);
				one_shot = TRUE;
				break;
			case 'h':
				as_html_file = crm_strdup(optarg);
				break;
			case 'w':
			        web_cgi = TRUE;
				one_shot = TRUE;
				break;
			case 'c':
#if CURSES_ENABLED
				as_console = TRUE;
#else
				printf("You need to have curses available at compile time to enable console mode\n");
				argerr++;
#endif
				break;
			case 's':
			        simple_status = TRUE;
				one_shot = TRUE;
				break;
			case '1':
				one_shot = TRUE;
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

	if(as_html_file == NULL && !web_cgi && !simple_status) {
#if CURSES_ENABLED
		as_console = TRUE;
#else
		printf("Defaulting to one-shot mode\n");
		printf("You need to have curses available at compile time to enable console mode\n");
		one_shot = TRUE;
#endif
	}

	if(daemonize) {
		as_console = FALSE;
	}

	if(one_shot) {
		daemonize = FALSE;
		as_console = FALSE;
	}
	
	if(daemonize && as_html_file == NULL) {
		usage(crm_system_name, LSB_EXIT_GENERIC);
	}
	
	make_daemon(daemonize, pid_file);

#if CURSES_ENABLED
	if(as_console) {
		initscr();
		cbreak();
		noecho();
	}
#endif
	
	crm_info("Starting %s", crm_system_name);
	mainloop = g_main_new(FALSE);

	if(one_shot == FALSE) {
		timer_id = Gmain_timeout_add(
			interval, mon_timer_popped, NULL);

	} else if(xml_file != NULL) {
		FILE *xml_strm = fopen(xml_file, "r");
		crm_data_t *cib_object = NULL;			
		if(strstr(xml_file, ".bz2") != NULL) {
			cib_object = file2xml(xml_strm, TRUE);
		} else {
			cib_object = file2xml(xml_strm, FALSE);
		}
		if(xml_strm != NULL) {
			fclose(xml_strm);
		}
		one_shot = TRUE;
		mon_update(NULL, 0, cib_ok, cib_object, NULL);
	}

	mon_timer_popped(NULL);
	g_main_run(mainloop);
	return_to_orig_privs();
	
	crm_info("Exiting %s", crm_system_name);	
	
#if CURSES_ENABLED
	if(as_console) {
		echo();
		nocbreak();
		endwin();
	}
#endif
	return 0;
}

gboolean
mon_timer_popped(gpointer data)
{
	int rc = cib_ok;
	int options = cib_scope_local;

	if(timer_id > 0) {
		Gmain_timeout_remove(timer_id);
	}
	
	if(as_console) {
#if CURSES_ENABLED
		move(0, 0);
		printw("Updating...\n");
		clrtoeol();
		refresh();
#endif
		
	} else {
		crm_notice("Updating...");
	}
	
	if(cib_conn == NULL) {
		crm_debug_4("Creating CIB connection");
		cib_conn = cib_new();
	}

	CRM_DEV_ASSERT(cib_conn != NULL);
	if(crm_assert_failed) {
		return FALSE;
		
	} else if(cib_conn->state != cib_connected_query){
		crm_debug_4("Connecting to the CIB");
#if CURSES_ENABLED
		if(as_console) {
			printw("Signing on...\n");
			clrtoeol();
			refresh();
		}
#endif
		if(cib_ok == cib_conn->cmds->signon(
			   cib_conn, crm_system_name, cib_query)) {
			failed_connections = 0;

		} else if (simple_status || one_shot) {
			fprintf(stdout, "Critical: Unable to connect to the CIB\n");
			exit(2);
		} else {
			failed_connections++;
			CRM_DEV_ASSERT(cib_conn->cmds->signoff(cib_conn) == cib_ok);
			wait_for_refresh(0, "Not connected: ", 2*interval);
			return FALSE;
		}
#if CURSES_ENABLED
		if(as_console) {
			printw("Querying...\n");
			clrtoeol();
			refresh();
		}
#endif
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
#if CRM_DEPRECATED_SINCE_2_0_4
		if( safe_str_eq(crm_element_name(output), XML_TAG_CIB) ) {
			cib = output;
		} else {
			cib = find_xml_node(output,XML_TAG_CIB,TRUE);
		}
#else
		cib = output;
		CRM_DEV_ASSERT(safe_str_eq(crm_element_name(cib), XML_TAG_CIB));
#endif		
		if(as_html_file || web_cgi) {
			print_html_status(cib, as_html_file, web_cgi);
		} else if (simple_status) {
			print_simple_status(cib);
			if (has_warnings) {
				exit(1); 
			}
		} else {
			print_status(cib);
		}
		if(one_shot) {
			exit(LSB_EXIT_OK);
		}
		
			
	} else if(simple_status) {
		fprintf(stderr, "Critical: query failed: %s", cib_error2string(rc));
		exit(2);
	} else if(one_shot) {
		fprintf(stderr, "Query failed: %s", cib_error2string(rc));
		exit(LSB_EXIT_OK);

	} else {
		CRM_DEV_ASSERT(cib_conn->cmds->signoff(cib_conn) == cib_ok);
		crm_err("Query failed: %s", cib_error2string(rc));
		prefix = "Query failed! ";
		
	}
	wait_for_refresh(0, prefix, interval);
}

void
wait_for_refresh(int offset, const char *prefix, int msec) 
{
	int lpc = msec / 1000;

	if(as_console == FALSE) {
		timer_id = Gmain_timeout_add(msec, mon_timer_popped, NULL);
		return;
	}
	
	crm_notice("%sRefresh in %ds...", prefix?prefix:"", lpc);
	while(lpc > 0) {
#if CURSES_ENABLED
		move(0, 0);
/* 		printw("%sRefresh in \033[01;32m%ds\033[00m...", prefix?prefix:"", lpc); */
		printw("%sRefresh in %ds...\n", prefix?prefix:"", lpc);
		clrtoeol();
		refresh();
#endif
		lpc--;
		if(lpc == 0) {
			timer_id = Gmain_timeout_add(
				1000, mon_timer_popped, NULL);
		} else {
			sleep(1);
		}
	}
}

#define mon_warn(fmt...) do {			\
		if (!has_warnings) {			\
			print_as("Warning:");	\
		} else {			\
			print_as(",");		\
		}				\
		print_as(fmt);			\
		has_warnings = TRUE;			\
	} while(0)

int
print_simple_status(crm_data_t *cib) 
{
	node_t *dc = NULL;
	int nodes_online = 0;
	int nodes_standby = 0;
	pe_working_set_t data_set;

	set_working_set_defaults(&data_set);
	data_set.input = cib;
	cluster_status(&data_set);

	dc = data_set.dc_node;

	if(dc == NULL) {
		mon_warn("No DC ");
	}

	slist_iter(node, node_t, data_set.nodes, lpc2,
		   if(node->details->standby) {
			   nodes_standby++;
		   } else if(node->details->online) {
			   nodes_online++;
		   } else {
			   mon_warn("offline node: %s", node->details->uname);
		   }
	);
	
	if (!has_warnings) {
		print_as("Ok: %d nodes online", nodes_online);
		if (nodes_standby > 0) {
			print_as(", %d standby nodes", nodes_standby);
		}
		print_as(", %d resources configured",
			g_list_length(data_set.resources));
	}
	
	print_as("\n");
	data_set.input = NULL;
	cleanup_calculations(&data_set);
	return 0;
}

int
print_status(crm_data_t *cib) 
{
	node_t *dc = NULL;
	static int updates = 0;
	pe_working_set_t data_set;
	char *since_epoch = NULL;
	time_t a_time = time(NULL);
	int configured_resources = 0;
	int print_opts = pe_print_ncurses;
	if(as_console) {
		blank_screen();
	} else {
		print_opts = pe_print_printf;
	}

	updates++;
	set_working_set_defaults(&data_set);
	data_set.input = cib;
	cluster_status(&data_set);

	dc = data_set.dc_node;

	print_as("\n\n============\n");

	if(a_time == (time_t)-1) {
		cl_perror("set_node_tstamp(): Invalid time returned");
		return 1;
	}
	
	since_epoch = ctime(&a_time);
	if(since_epoch != NULL) {
		print_as("Last updated: %s", since_epoch);
	}

	if(dc == NULL) {
		print_as("Current DC: NONE\n");
	} else {
		print_as("Current DC: %s (%s)\n",
			  dc->details->uname, dc->details->id);
	}

	slist_iter(rsc, resource_t, data_set.resources, lpc,
		   if(is_not_set(rsc->flags, pe_rsc_orphan)) {
			   configured_resources++;
		   }
		);
	
	print_as("%d Nodes configured.\n", g_list_length(data_set.nodes));
	print_as("%d Resources configured.\n", configured_resources);
	print_as("============\n\n");

	slist_iter(node, node_t, data_set.nodes, lpc2,
		   const char *node_mode = "OFFLINE";
		   if(node->details->standby) {
			   node_mode = "standby";
		   } else if(node->details->online) {
			   node_mode = "online";
		   }
		   
		   print_as("Node: %s (%s): %s\n",
			  node->details->uname, node->details->id,
			  node_mode);
		   if(group_by_node) {
			   slist_iter(rsc, resource_t,
				      node->details->running_rsc, lpc2,
 				      rsc->fns->print(
					      rsc, "\t", print_opts|pe_print_rsconly, stdout);
				   );
		   }
		);

	if(group_by_node == FALSE && inactive_resources) {
		print_as("\nFull list of resources:\n");

	} else if(inactive_resources) {
		print_as("\nInactive resources:\n");
	}
	
	if(group_by_node == FALSE || inactive_resources) {
		print_as("\n");
		slist_iter(rsc, resource_t, data_set.resources, lpc2,
			   gboolean is_active = rsc->fns->active(rsc, TRUE);
			   gboolean partially_active = rsc->fns->active(rsc, FALSE);
			   if(is_set(rsc->flags, pe_rsc_orphan) && is_active == FALSE) {
				   continue;
				   
			   } else if(group_by_node == FALSE) {
				   if(partially_active || inactive_resources) {
					   rsc->fns->print(rsc, NULL, print_opts, stdout);
				   }
				   
			   } else if(is_active == FALSE && inactive_resources) {
				   rsc->fns->print(rsc, NULL, print_opts, stdout);
			   }
			);
	}

	if(xml_has_children(data_set.failed)) {
		print_as("\nFailed actions:\n");
		xml_child_iter(data_set.failed, xml_op, 
			       const char *id = ID(xml_op);
			       const char *rc = crm_element_value(xml_op, XML_LRM_ATTR_RC);
			       const char *node = crm_element_value(xml_op, XML_ATTR_UNAME);
			       const char *call = crm_element_value(xml_op, XML_LRM_ATTR_CALLID);
			       const char *status_s = crm_element_value(xml_op, XML_LRM_ATTR_OPSTATUS);
			       int status = crm_parse_int(status_s, "0");
			       
			       print_as("    %s (node=%s, call=%s, rc=%s): %s\n",
					id, node, call, rc, op_status2text(status));
			);
	}
	
#if CURSES_ENABLED
	if(as_console) {
		refresh();
	}
#endif
	data_set.input = NULL;
	cleanup_calculations(&data_set);
	return 0;
}

int
print_html_status(crm_data_t *cib, const char *filename, gboolean web_cgi) 
{
	FILE *stream;
	node_t *dc = NULL;
	static int updates = 0;
	pe_working_set_t data_set;
	char *filename_tmp = NULL;

	if (web_cgi) {
		stream=stdout;
		fprintf(stream, "Content-type: text/html\n\n");

	} else {
		filename_tmp = crm_concat(filename, "tmp", '.');
		stream = fopen(filename_tmp, "w");
		cl_perror("Cannot open %s for writing", filename_tmp);
		if(stream == NULL) {
			crm_free(filename_tmp);
			return -1;
		}	
	}

	updates++;
	set_working_set_defaults(&data_set);
	data_set.input = cib;
	cluster_status(&data_set);

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
				      rsc->fns->print(rsc, NULL,
						      pe_print_html, stream);
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
			   rsc->fns->print(rsc, NULL, pe_print_html, stream);
			);
	}

	data_set.input = NULL;
	cleanup_calculations(&data_set);
	fprintf(stream, "</html>");
	fflush(stream);
	fclose(stream);

	if (!web_cgi) {
		if(rename(filename_tmp, filename) != 0) {
			cl_perror("Unable to rename %s->%s", filename_tmp, filename);
		}
		crm_free(filename_tmp);
	}
	return 0;
}


void
blank_screen(void) 
{
#if CURSES_ENABLED
	int lpc = 0;
	for(lpc = 0; lpc < LINES; lpc++) {
		move(lpc, 0);
		clrtoeol();
	}
	move(0, 0);
#endif
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
	fprintf(stream, "\t--%s (-%c) \t: Display the cluster status once as "
		"a simple one line output (suitable for nagios)\n", "simple-status", 's');
	fprintf(stream, "\t--%s (-%c) \t: Display the cluster status once on "
		"the console and exit (doesnt use ncurses)\n", "one-shot", '1');
	fprintf(stream, "\t--%s (-%c) <filename>\t: Write cluster status to the named file\n", "as-html", 'h');
	fprintf(stream, "\t--%s (-%c) \t: Web mode with output suitable for cgi\n", "web-cgi", 'w');
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
	close(0);
	close(1);
	close(2);
	(void)open(devnull, O_RDONLY);		/* Stdin:  fd 0 */
	(void)open(devnull, O_WRONLY);		/* Stdout: fd 1 */
	(void)open(devnull, O_WRONLY);		/* Stderr: fd 2 */
}
