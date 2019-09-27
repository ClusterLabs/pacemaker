/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <stdarg.h>
#include <stdlib.h>
#include <crm/crm.h>
#include <crm/common/curses_internal.h>
#include <crm/common/output.h>
#include <glib.h>

#include "crm_mon.h"

#if CURSES_ENABLED

GOptionEntry crm_mon_curses_output_entries[] = {
    { NULL }
};

typedef struct curses_list_data_s {
    unsigned int len;
    char *singular_noun;
    char *plural_noun;
} curses_list_data_t;

typedef struct private_data_s {
    GQueue *parent_q;
} private_data_t;

static void
curses_free_priv(pcmk__output_t *out) {
    private_data_t *priv = out->priv;

    if (priv == NULL) {
        return;
    }

    g_queue_free(priv->parent_q);
    free(priv);
}

static bool
curses_init(pcmk__output_t *out) {
    private_data_t *priv = NULL;

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

    return true;
}

static void
curses_finish(pcmk__output_t *out, crm_exit_t exit_status, bool print, void **copy_dest) {
}

static void
curses_reset(pcmk__output_t *out) {
    CRM_ASSERT(out->priv != NULL);

    curses_free_priv(out);
    curses_init(out);
}

static void
curses_subprocess_output(pcmk__output_t *out, int exit_status,
                         const char *proc_stdout, const char *proc_stderr) {
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
 * Note that this function prints out via text, not with curses.
 */
static void
curses_ver(pcmk__output_t *out, bool extended) {
    if (extended) {
        printf("Pacemaker %s (Build: %s): %s\n", PACEMAKER_VERSION, BUILD_VERSION, CRM_FEATURES);
    } else {
        printf("Pacemaker %s\n", PACEMAKER_VERSION);
        printf("Written by Andrew Beekhof\n");
    }
}

G_GNUC_PRINTF(2, 3)
static void
curses_err_info(pcmk__output_t *out, const char *format, ...) {
    va_list ap;

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
}

static void
curses_output_xml(pcmk__output_t *out, const char *name, const char *buf) {
    private_data_t *priv = out->priv;

    CRM_ASSERT(priv != NULL);
    curses_indented_printf(out, "%s", buf);
}

G_GNUC_PRINTF(4, 5)
static void
curses_begin_list(pcmk__output_t *out, const char *singular_noun, const char *plural_noun,
                  const char *format, ...) {
    private_data_t *priv = out->priv;
    curses_list_data_t *new_list = NULL;
    va_list ap;

    CRM_ASSERT(priv != NULL);

    va_start(ap, format);

    curses_indented_vprintf(out, format, ap);
    printw(":\n");

    va_end(ap);

    new_list = calloc(1, sizeof(curses_list_data_t));
    new_list->len = 0;
    new_list->singular_noun = singular_noun == NULL ? NULL : strdup(singular_noun);
    new_list->plural_noun = plural_noun == NULL ? NULL : strdup(plural_noun);

    g_queue_push_tail(priv->parent_q, new_list);
}

G_GNUC_PRINTF(3, 4)
static void
curses_list_item(pcmk__output_t *out, const char *id, const char *format, ...) {
    private_data_t *priv = out->priv;
    va_list ap;

    CRM_ASSERT(priv != NULL);

    va_start(ap, format);

    if (id != NULL) {
        curses_indented_printf(out, "%s: ", id);
        vw_printw(stdscr, format, ap);
    } else {
        curses_indented_vprintf(out, format, ap);
    }

    addch('\n');
    va_end(ap);

    ((curses_list_data_t *) g_queue_peek_tail(priv->parent_q))->len++;
}

static void
curses_end_list(pcmk__output_t *out) {
    private_data_t *priv = out->priv;
    curses_list_data_t *node = NULL;

    CRM_ASSERT(priv != NULL);
    node = g_queue_pop_tail(priv->parent_q);

    if (node->singular_noun != NULL && node->plural_noun != NULL) {
        if (node->len == 1) {
            curses_indented_printf(out, "%d %s found\n", node->len, node->singular_noun);
        } else {
            curses_indented_printf(out, "%d %s found\n", node->len, node->plural_noun);
        }
    }

    free(node);
}

pcmk__output_t *
crm_mon_mk_curses_output(char **argv) {
    pcmk__output_t *retval = calloc(1, sizeof(pcmk__output_t));

    if (retval == NULL) {
        return NULL;
    }

    retval->fmt_name = "console";
    retval->request = g_strjoinv(" ", argv);
    retval->supports_quiet = true;

    retval->init = curses_init;
    retval->free_priv = curses_free_priv;
    retval->finish = curses_finish;
    retval->reset = curses_reset;

    retval->register_message = pcmk__register_message;
    retval->message = pcmk__call_message;

    retval->subprocess_output = curses_subprocess_output;
    retval->version = curses_ver;
    retval->err = curses_err_info;
    retval->info = curses_err_info;
    retval->output_xml = curses_output_xml;

    retval->begin_list = curses_begin_list;
    retval->list_item = curses_list_item;
    retval->end_list = curses_end_list;

    return retval;
}

G_GNUC_PRINTF(2, 0)
void
curses_indented_vprintf(pcmk__output_t *out, const char *format, va_list args) {
    int level = 0;
    private_data_t *priv = out->priv;

    CRM_ASSERT(priv != NULL);

    level = g_queue_get_length(priv->parent_q);

    for (int i = 0; i < level; i++) {
        addch('\t');
    }

    if (level > 0) {
        printw("* ");
    }

    vw_printw(stdscr, format, args);

    clrtoeol();
    refresh();
}

G_GNUC_PRINTF(2, 3)
void
curses_indented_printf(pcmk__output_t *out, const char *format, ...) {
    va_list ap;

    va_start(ap, format);
    curses_indented_vprintf(out, format, ap);
    va_end(ap);
}
#else

pcmk__output_t *
crm_mon_mk_curses_output(char **argv) {
    /* curses was disabled in the build, so fall back to text. */
    return pcmk__mk_text_output(argv);
}

G_GNUC_PRINTF(2, 0)
void
curses_indented_vprintf(pcmk__output_t *out, const char *format, va_list args) {
    return;
}

G_GNUC_PRINTF(2, 3)
void
curses_indented_printf(pcmk__output_t *out, const char *format, va_list args) {
    return;
}

#endif
