/*
 * Copyright 2019-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <crm/crm.h>
#include <crm/common/output.h>
#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>   // stonith__history_description()
#include <crm/pengine/internal.h>
#include <glib.h>
#include <pacemaker-internal.h>

#include "crm_mon.h"

#if PCMK__ENABLE_CURSES

typedef struct curses_list_data_s {
    unsigned int len;
    char *singular_noun;
    char *plural_noun;
} curses_list_data_t;

typedef struct private_data_s {
    GQueue *parent_q;
} private_data_t;

static void
free_list_data(gpointer data) {
    curses_list_data_t *list_data = data;

    free(list_data->singular_noun);
    free(list_data->plural_noun);
    free(list_data);
}

static void
curses_free_priv(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    if (out == NULL || out->priv == NULL) {
        return;
    }

    priv = out->priv;

    g_queue_free_full(priv->parent_q, free_list_data);
    free(priv);
    out->priv = NULL;
}

static bool
curses_init(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    pcmk__assert(out != NULL);

    /* If curses_init was previously called on this output struct, just return. */
    if (out->priv != NULL) {
        return true;
    } else {
        out->priv = calloc(1, sizeof(private_data_t));
        if (out->priv == NULL) {
            return false;
        }

        priv = out->priv;
    }

    priv->parent_q = g_queue_new();

    initscr();
    cbreak();
    noecho();

    return true;
}

static void
curses_finish(pcmk__output_t *out, crm_exit_t exit_status, bool print, void **copy_dest) {
    pcmk__assert(out != NULL);

    echo();
    nocbreak();
    endwin();
}

static void
curses_reset(pcmk__output_t *out) {
    pcmk__assert(out != NULL);

    curses_free_priv(out);
    curses_init(out);
}

static void
curses_subprocess_output(pcmk__output_t *out, int exit_status,
                         const char *proc_stdout, const char *proc_stderr) {
    pcmk__assert(out != NULL);

    if (proc_stdout != NULL) {
        printw("%s\n", proc_stdout);
    }

    if (proc_stderr != NULL) {
        printw("%s\n", proc_stderr);
    }

    clrtoeol();
    refresh();
}

/* curses_version is defined in curses.h, so we can't use that name here.
 * This function is empty because we create a text object instead of a console
 * object if version is requested, so this is never called.
 */
static void
curses_ver(pcmk__output_t *out)
{
    pcmk__assert(out != NULL);
}

G_GNUC_PRINTF(2, 3)
static void
curses_error(pcmk__output_t *out, const char *format, ...) {
    va_list ap;

    pcmk__assert(out != NULL);

    /* Informational output does not get indented, to separate it from other
     * potentially indented list output.
     */
    va_start(ap, format);
    vw_printw(stdscr, format, ap);
    va_end(ap);

    /* Add a newline. */
    addch('\n');

    clrtoeol();
    refresh();
    sleep(2);
}

G_GNUC_PRINTF(2, 3)
static int
curses_info(pcmk__output_t *out, const char *format, ...) {
    va_list ap;

    pcmk__assert(out != NULL);

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    /* Informational output does not get indented, to separate it from other
     * potentially indented list output.
     */
    va_start(ap, format);
    vw_printw(stdscr, format, ap);
    va_end(ap);

    /* Add a newline. */
    addch('\n');

    clrtoeol();
    refresh();
    return pcmk_rc_ok;
}

static void
curses_output_xml(pcmk__output_t *out, const char *name, const char *buf) {
    pcmk__assert(out != NULL);
    curses_indented_printf(out, "%s", buf);
}

G_GNUC_PRINTF(4, 5)
static void
curses_begin_list(pcmk__output_t *out, const char *singular_noun, const char *plural_noun,
                  const char *format, ...) {
    private_data_t *priv = NULL;
    curses_list_data_t *new_list = NULL;
    va_list ap;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    /* Empty formats can be used to create a new level of indentation, but without
     * displaying some sort of list header.  In that case we need to not do any of
     * this stuff. vw_printw will act weird if told to print a NULL.
     */
    if (format != NULL) {
        va_start(ap, format);

        curses_indented_vprintf(out, format, ap);
        printw(":\n");

        va_end(ap);
    }

    new_list = pcmk__assert_alloc(1, sizeof(curses_list_data_t));
    new_list->len = 0;
    new_list->singular_noun = pcmk__str_copy(singular_noun);
    new_list->plural_noun = pcmk__str_copy(plural_noun);

    g_queue_push_tail(priv->parent_q, new_list);
}

G_GNUC_PRINTF(3, 4)
static void
curses_list_item(pcmk__output_t *out, const char *id, const char *format, ...) {
    va_list ap;

    pcmk__assert(out != NULL);

    va_start(ap, format);

    if (id != NULL) {
        curses_indented_printf(out, "%s: ", id);
        vw_printw(stdscr, format, ap);
    } else {
        curses_indented_vprintf(out, format, ap);
    }

    addch('\n');
    va_end(ap);

    out->increment_list(out);
}

static void
curses_increment_list(pcmk__output_t *out) {
    private_data_t *priv = NULL;
    gpointer tail;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    tail = g_queue_peek_tail(priv->parent_q);
    pcmk__assert(tail != NULL);
    ((curses_list_data_t *) tail)->len++;
}

static void
curses_end_list(pcmk__output_t *out) {
    private_data_t *priv = NULL;
    curses_list_data_t *node = NULL;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    node = g_queue_pop_tail(priv->parent_q);

    if (node->singular_noun != NULL && node->plural_noun != NULL) {
        if (node->len == 1) {
            curses_indented_printf(out, "%d %s found\n", node->len, node->singular_noun);
        } else {
            curses_indented_printf(out, "%d %s found\n", node->len, node->plural_noun);
        }
    }

    free_list_data(node);
}

static bool
curses_is_quiet(pcmk__output_t *out) {
    pcmk__assert(out != NULL);
    return out->quiet;
}

static void
curses_spacer(pcmk__output_t *out) {
    pcmk__assert(out != NULL);
    addch('\n');
}

static void
curses_progress(pcmk__output_t *out, bool end) {
    pcmk__assert(out != NULL);

    if (end) {
        printw(".\n");
    } else {
        addch('.');
    }
}

static void
curses_prompt(const char *prompt, bool do_echo, char **dest)
{
    int rc = OK;

    pcmk__assert((prompt != NULL) && (dest != NULL));

    /* This is backwards from the text version of this function on purpose.  We
     * disable echo by default in curses_init, so we need to enable it here if
     * asked for.
     */
    if (do_echo) {
        rc = echo();
    }

    if (rc == OK) {
        printw("%s: ", prompt);

        if (*dest != NULL) {
            free(*dest);
        }

        *dest = pcmk__assert_alloc(1024, sizeof(char));
        /* On older systems, scanw is defined as taking a char * for its first argument,
         * while newer systems rightly want a const char *.  Accomodate both here due
         * to building with -Werror.
         */
        rc = scanw((NCURSES_CONST char *) "%1023s", *dest);
        addch('\n');
    }

    if (rc < 1) {
        free(*dest);
        *dest = NULL;
    }

    if (do_echo) {
        noecho();
    }
}

void
crm_mon_output_setup_curses(pcmk__output_t *out)
{
    out->fmt_name = "console";

    out->init = curses_init;
    out->free_priv = curses_free_priv;
    out->finish = curses_finish;
    out->reset = curses_reset;

    out->subprocess_output = curses_subprocess_output;
    out->version = curses_ver;
    out->err = curses_error;
    out->info = curses_info;
    out->transient = curses_info;
    out->output_xml = curses_output_xml;

    out->begin_list = curses_begin_list;
    out->list_item = curses_list_item;
    out->increment_list = curses_increment_list;
    out->end_list = curses_end_list;

    out->is_quiet = curses_is_quiet;
    out->spacer = curses_spacer;
    out->progress = curses_progress;
    out->prompt = curses_prompt;
}

G_GNUC_PRINTF(2, 0)
void
curses_formatted_vprintf(pcmk__output_t *out, const char *format, va_list args) {
    vw_printw(stdscr, format, args);

    clrtoeol();
    refresh();
}

G_GNUC_PRINTF(2, 3)
void
curses_formatted_printf(pcmk__output_t *out, const char *format, ...) {
    va_list ap;

    va_start(ap, format);
    curses_formatted_vprintf(out, format, ap);
    va_end(ap);
}

G_GNUC_PRINTF(2, 0)
void
curses_indented_vprintf(pcmk__output_t *out, const char *format, va_list args) {
    int level = 0;
    private_data_t *priv = NULL;

    pcmk__assert((out != NULL) && (out->priv != NULL));

    priv = out->priv;

    level = g_queue_get_length(priv->parent_q);

    for (int i = 0; i < level; i++) {
        printw("  ");
    }

    if (level > 0) {
        printw("* ");
    }

    curses_formatted_vprintf(out, format, args);
}

G_GNUC_PRINTF(2, 3)
void
curses_indented_printf(pcmk__output_t *out, const char *format, ...) {
    va_list ap;

    va_start(ap, format);
    curses_indented_vprintf(out, format, ap);
    va_end(ap);
}

PCMK__OUTPUT_ARGS("maint-mode", "uint64_t")
static int
cluster_maint_mode_console(pcmk__output_t *out, va_list args) {
    uint64_t flags = va_arg(args, uint64_t);

    if (pcmk__is_set(flags, pcmk__sched_in_maintenance)) {
        curses_formatted_printf(out, "\n              *** Resource management is DISABLED ***\n");
        curses_formatted_printf(out, "  The cluster will not attempt to start, stop or recover services\n");
        return pcmk_rc_ok;
    } else if (pcmk__is_set(flags, pcmk__sched_stop_all)) {
        curses_formatted_printf(out, "\n    *** Resource management is DISABLED ***\n");
        curses_formatted_printf(out, "  The cluster will keep all resources stopped\n");
        return pcmk_rc_ok;
    } else {
        return pcmk_rc_no_output;
    }
}

PCMK__OUTPUT_ARGS("cluster-status", "pcmk_scheduler_t *",
                  "enum pcmk_pacemakerd_state", "crm_exit_t",
                  "stonith_history_t *", "enum pcmk__fence_history", "uint32_t",
                  "uint32_t", "const char *", "GList *", "GList *")
static int
cluster_status_console(pcmk__output_t *out, va_list args) {
    int rc = pcmk_rc_no_output;

    clear();
    rc = pcmk__cluster_status_text(out, args);
    refresh();
    return rc;
}

PCMK__OUTPUT_ARGS("stonith-event", "stonith_history_t *", "bool", "bool",
                  "const char *", "uint32_t")
static int
stonith_event_console(pcmk__output_t *out, va_list args)
{
    stonith_history_t *event = va_arg(args, stonith_history_t *);
    bool full_history = va_arg(args, int);
    bool completed_only G_GNUC_UNUSED = va_arg(args, int);
    const char *succeeded = va_arg(args, const char *);
    uint32_t show_opts = va_arg(args, uint32_t);

    gchar *desc = stonith__history_description(event, full_history, succeeded,
                                               show_opts);


    curses_indented_printf(out, "%s\n", desc);
    g_free(desc);
    return pcmk_rc_ok;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "cluster-status", "console", cluster_status_console },
    { "maint-mode", "console", cluster_maint_mode_console },
    { "stonith-event", "console", stonith_event_console },

    { NULL, NULL, NULL }
};

#endif

void
crm_mon_register_messages(pcmk__output_t *out) {
#if PCMK__ENABLE_CURSES
    pcmk__register_messages(out, fmt_functions);
#endif
}
