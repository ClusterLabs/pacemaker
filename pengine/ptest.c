
/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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
#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/transition.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/msg_xml.h>

#include <crm/cib.h>

#include <glib.h>
#include <pengine.h>
#include <lib/pengine/utils.h>
#include <allocate.h>
#if HAVE_LIBXML2
#  include <libxml/parser.h>
#endif

gboolean use_stdin = FALSE;
gboolean do_simulation = FALSE;
gboolean inhibit_exit = FALSE;
gboolean all_actions = FALSE;
extern xmlNode *do_calculations(pe_working_set_t * data_set, xmlNode * xml_input, ha_time_t * now);
extern void cleanup_calculations(pe_working_set_t * data_set);
char *use_date = NULL;

FILE *dot_strm = NULL;

#define DOT_PREFIX "PE_DOT: "
/* #define DOT_PREFIX "" */

#define dot_write(fmt...) if(dot_strm != NULL) {	\
	fprintf(dot_strm, fmt);				\
	fprintf(dot_strm, "\n");			\
    } else {						\
	crm_debug(DOT_PREFIX""fmt);			\
    }

static void
init_dotfile(void)
{
    dot_write(" digraph \"g\" {");
/* 	dot_write("	size = \"30,30\""); */
/* 	dot_write("	graph ["); */
/* 	dot_write("		fontsize = \"12\""); */
/* 	dot_write("		fontname = \"Times-Roman\""); */
/* 	dot_write("		fontcolor = \"black\""); */
/* 	dot_write("		bb = \"0,0,398.922306,478.927856\""); */
/* 	dot_write("		color = \"black\""); */
/* 	dot_write("	]"); */
/* 	dot_write("	node ["); */
/* 	dot_write("		fontsize = \"12\""); */
/* 	dot_write("		fontname = \"Times-Roman\""); */
/* 	dot_write("		fontcolor = \"black\""); */
/* 	dot_write("		shape = \"ellipse\""); */
/* 	dot_write("		color = \"black\""); */
/* 	dot_write("	]"); */
/* 	dot_write("	edge ["); */
/* 	dot_write("		fontsize = \"12\""); */
/* 	dot_write("		fontname = \"Times-Roman\""); */
/* 	dot_write("		fontcolor = \"black\""); */
/* 	dot_write("		color = \"black\""); */
/* 	dot_write("	]"); */
}

static char *
create_action_name(action_t * action)
{
    char *action_name = NULL;
    const char *action_host = NULL;

    if (action->node) {
        action_host = action->node->details->uname;
        action_name = crm_concat(action->uuid, action_host, ' ');

    } else if (is_set(action->flags, pe_action_pseudo)) {
        action_name = strdup(action->uuid);

    } else {
        action_host = "<none>";
        action_name = crm_concat(action->uuid, action_host, ' ');
    }
    if (safe_str_eq(action->task, RSC_CANCEL)) {
        char *tmp_action_name = action_name;

        action_name = crm_concat("Cancel", tmp_action_name, ' ');
        free(tmp_action_name);
    }

    return action_name;
}

gboolean USE_LIVE_CIB = FALSE;
/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",           0, 0, '?', "This text"},
    {"version",        0, 0, '$', "Version information"  },
    {"verbose",        0, 0, 'V', "Increase debug output\n"},

    {"simulate",    0, 0, 'S', "Simulate the transition's execution to find invalid graphs\n"},
    {"show-scores", 0, 0, 's', "Display resource allocation scores"},
    {"show-utilization", 0, 0, 'U', "Display utilization information"},
    {"all-actions", 0, 0, 'a', "Display all possible actions - even ones not part of the transition graph"},

    {"live-check",  0, 0, 'L', "Connect to the CIB and use the current contents as input"},
    {"xml-text",    1, 0, 'X', "Retrieve XML from the supplied string"},
    {"xml-file",    1, 0, 'x', "Retrieve XML from the named file"},
    /* {"xml-pipe",    0, 0, 'p', "Retrieve XML from stdin\n"}, */
    
    {"save-input",  1, 0, 'I', "\tSave the input to the named file"},
    {"save-graph",  1, 0, 'G', "\tSave the transition graph (XML format) to the named file"},
    {"save-dotfile",1, 0, 'D', "Save the transition graph (DOT format) to the named file\n"},
    
    {0, 0, 0, 0}
};
/* *INDENT-ON* */

int
main(int argc, char **argv)
{
    GListPtr lpc = NULL;
    gboolean process = TRUE;
    gboolean all_good = TRUE;
    enum transition_status graph_rc = -1;
    crm_graph_t *transition = NULL;
    ha_time_t *a_date = NULL;
    cib_t *cib_conn = NULL;

    xmlNode *cib_object = NULL;
    int argerr = 0;
    int flag;

    char *msg_buffer = NULL;
    gboolean optional = FALSE;
    pe_working_set_t data_set;

    const char *source = NULL;
    const char *xml_file = NULL;
    const char *dot_file = NULL;
    const char *graph_file = NULL;
    const char *input_file = NULL;
    const char *input_xml = NULL;

    /* disable glib's fancy allocators that can't be free'd */
    GMemVTable vtable;

    vtable.malloc = malloc;
    vtable.realloc = realloc;
    vtable.free = free;
    vtable.calloc = calloc;
    vtable.try_malloc = malloc;
    vtable.try_realloc = realloc;

    g_mem_set_vtable(&vtable);

    crm_log_cli_init("ptest");
    crm_set_options(NULL, "[-?Vv] -[Xxp] {other options}", long_options,
                    "Calculate the cluster's response to the supplied cluster state\n"
                    "\nSuperceeded by crm_simulate and likely to be removed in a future release\n\n");

    while (1) {
        int option_index = 0;

        flag = crm_get_option(argc, argv, &option_index);
        if (flag == -1)
            break;

        switch (flag) {
            case 'S':
                do_simulation = TRUE;
                break;
            case 'a':
                all_actions = TRUE;
                break;
            case 'w':
                inhibit_exit = TRUE;
                break;
            case 'X':
                /*use_stdin = TRUE;*/
                input_xml = optarg;
                break;
            case 's':
                show_scores = TRUE;
                break;
            case 'U':
                show_utilization = TRUE;
                break;
            case 'x':
                xml_file = optarg;
                break;
            case 'd':
                use_date = optarg;
                break;
            case 'D':
                dot_file = optarg;
                break;
            case 'G':
                graph_file = optarg;
                break;
            case 'I':
                input_file = optarg;
                break;
            case 'V':
                crm_bump_log_level();
                break;
            case 'L':
                USE_LIVE_CIB = TRUE;
                break;
            case '$':
            case '?':
                crm_help(flag, 0);
                break;
            default:
                fprintf(stderr, "Option -%c is not yet supported\n", flag);
                ++argerr;
                break;
        }
    }

    if (optind < argc) {
        printf("non-option ARGV-elements: ");
        while (optind < argc) {
            printf("%s ", argv[optind++]);
        }
        printf("\n");
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        crm_err("%d errors in option parsing", argerr);
        crm_help('?', 1);
    }

    if (USE_LIVE_CIB) {
        int rc = pcmk_ok;

        source = "live cib";
        cib_conn = cib_new();
        rc = cib_conn->cmds->signon(cib_conn, "ptest", cib_command);

        if (rc == pcmk_ok) {
            crm_info("Reading XML from: live cluster");
            cib_object = get_cib_copy(cib_conn);

        } else {
            fprintf(stderr, "Live CIB query failed: %s\n", pcmk_strerror(rc));
            return 3;
        }
        if (cib_object == NULL) {
            fprintf(stderr, "Live CIB query failed: empty result\n");
            return 3;
        }

    } else if (xml_file != NULL) {
        source = xml_file;
        cib_object = filename2xml(xml_file);

    } else if (use_stdin) {
        source = "stdin";
        cib_object = filename2xml(NULL);
    } else if (input_xml) {
        source = "input string";
        cib_object = string2xml(input_xml);
    }

    if (cib_object == NULL && source) {
        fprintf(stderr, "Could not parse configuration input from: %s\n", source);
        return 4;

    } else if (cib_object == NULL) {
        fprintf(stderr, "No configuration specified\n");
        crm_help('?', 1);
    }

    if (get_object_root(XML_CIB_TAG_STATUS, cib_object) == NULL) {
        create_xml_node(cib_object, XML_CIB_TAG_STATUS);
    }

    if (cli_config_update(&cib_object, NULL, FALSE) == FALSE) {
        free_xml(cib_object);
        return -ENOKEY;
    }

    if (validate_xml(cib_object, NULL, FALSE) != TRUE) {
        free_xml(cib_object);
        return -pcmk_err_dtd_validation;
    }

    if (input_file != NULL) {
        FILE *input_strm = fopen(input_file, "w");

        if (input_strm == NULL) {
            crm_perror(LOG_ERR, "Could not open %s for writing", input_file);
        } else {
            msg_buffer = dump_xml_formatted(cib_object);
            if (fprintf(input_strm, "%s\n", msg_buffer) < 0) {
                crm_perror(LOG_ERR, "Write to %s failed", input_file);
            }
            fflush(input_strm);
            fclose(input_strm);
            free(msg_buffer);
        }
    }

    if (use_date != NULL) {
        a_date = parse_date(&use_date);
        log_date(LOG_WARNING, "Set fake 'now' to", a_date, ha_log_date | ha_log_time);
        log_date(LOG_WARNING, "Set fake 'now' to (localtime)",
                 a_date, ha_log_date | ha_log_time | ha_log_local);
    }

    set_working_set_defaults(&data_set);
    if (process) {
        if (show_scores && show_utilization) {
            fprintf(stdout, "Allocation scores and utilization information:\n");
        } else if (show_scores) {
            fprintf(stdout, "Allocation scores:\n");
        } else if (show_utilization) {
            fprintf(stdout, "Utilization information:\n");
        }
        do_calculations(&data_set, cib_object, a_date);
    }

    msg_buffer = dump_xml_formatted(data_set.graph);
    if (safe_str_eq(graph_file, "-")) {
        fprintf(stdout, "%s\n", msg_buffer);
        fflush(stdout);
    } else if (graph_file != NULL) {
        FILE *graph_strm = fopen(graph_file, "w");

        if (graph_strm == NULL) {
            crm_perror(LOG_ERR, "Could not open %s for writing", graph_file);
        } else {
            if (fprintf(graph_strm, "%s\n\n", msg_buffer) < 0) {
                crm_perror(LOG_ERR, "Write to %s failed", graph_file);
            }
            fflush(graph_strm);
            fclose(graph_strm);
        }
    }
    free(msg_buffer);

    if (dot_file != NULL) {
        dot_strm = fopen(dot_file, "w");
        if (dot_strm == NULL) {
            crm_perror(LOG_ERR, "Could not open %s for writing", dot_file);
        }
    }

    if (dot_strm == NULL) {
        goto simulate;
    }

    init_dotfile();
    for (lpc = data_set.actions; lpc != NULL; lpc = lpc->next) {
        action_t *action = (action_t *) lpc->data;
        const char *style = "filled";
        const char *font = "black";
        const char *color = "black";
        const char *fill = NULL;
        char *action_name = create_action_name(action);

        crm_trace("Action %d: %p", action->id, action);

        if (is_set(action->flags, pe_action_pseudo)) {
            font = "orange";
        }

        style = "dashed";
        if (is_set(action->flags, pe_action_dumped)) {
            style = "bold";
            color = "green";

        } else if (action->rsc != NULL && is_not_set(action->rsc->flags, pe_rsc_managed)) {
            color = "purple";
            if (all_actions == FALSE) {
                goto dont_write;
            }

        } else if (is_set(action->flags, pe_action_optional)) {
            color = "blue";
            if (all_actions == FALSE) {
                goto dont_write;
            }

        } else {
            color = "red";
            CRM_CHECK(is_set(action->flags, pe_action_runnable) == FALSE,;
                );
        }

        set_bit(action->flags, pe_action_dumped);
        dot_write("\"%s\" [ style=%s color=\"%s\" fontcolor=\"%s\"  %s%s]",
                  action_name, style, color, font, fill ? "fillcolor=" : "", fill ? fill : "");
  dont_write:
        free(action_name);
    }

    for (lpc = data_set.actions; lpc != NULL; lpc = lpc->next) {
        action_t *action = (action_t *) lpc->data;

        GListPtr lpc2 = NULL;

        for (lpc2 = action->actions_before; lpc2 != NULL; lpc2 = lpc2->next) {
            action_wrapper_t *before = (action_wrapper_t *) lpc2->data;

            char *before_name = NULL;
            char *after_name = NULL;
            const char *style = "dashed";

            optional = TRUE;
            if (before->state == pe_link_dumped) {
                optional = FALSE;
                style = "bold";
            } else if (is_set(action->flags, pe_action_pseudo)
                       && (before->type & pe_order_stonith_stop)) {
                continue;
            } else if (before->state == pe_link_dup) {
                continue;
            } else if (before->type == pe_order_none) {
                continue;
            } else if (is_set(before->action->flags, pe_action_dumped)
                       && is_set(action->flags, pe_action_dumped)) {
                optional = FALSE;
            }

            if (all_actions || optional == FALSE) {
                before_name = create_action_name(before->action);
                after_name = create_action_name(action);
                dot_write("\"%s\" -> \"%s\" [ style = %s]", before_name, after_name, style);
                free(before_name);
                free(after_name);
            }
        }
    }
    dot_write("}");
    if (dot_strm != NULL) {
        fflush(dot_strm);
        fclose(dot_strm);
    }

  simulate:

    if (do_simulation == FALSE) {
        goto cleanup;
    }

    transition = unpack_graph(data_set.graph, "ptest");
    print_graph(LOG_DEBUG, transition);

    do {
        graph_rc = run_graph(transition);

    } while (graph_rc == transition_active);

    if (graph_rc != transition_complete) {
        crm_crit("Transition failed: %s", transition_status(graph_rc));
        print_graph(LOG_ERR, transition);
    }
    destroy_graph(transition);
    CRM_CHECK(graph_rc == transition_complete, all_good = FALSE;
              crm_err("An invalid transition was produced"));

  cleanup:
    cleanup_alloc_calculations(&data_set);
    crm_log_deinit();

    /* required for MallocDebug.app */
    if (inhibit_exit) {
        GMainLoop *mainloop = g_main_new(FALSE);

        g_main_run(mainloop);
    }

    if (all_good) {
        return 0;
    }
    return graph_rc;
}
