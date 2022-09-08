/*
 * Copyright 2019-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/cmdline_internal.h>

#include <stdarg.h>
#include <stdlib.h>
#include <glib.h>
#include <termios.h>

static gboolean fancy = FALSE;

GOptionEntry pcmk__text_output_entries[] = {
    { "text-fancy", 0, 0, G_OPTION_ARG_NONE, &fancy,
      "Use more highly formatted output (requires --output-as=text)",
      NULL },

    { NULL }
};

typedef struct text_list_data_s {
    unsigned int len;
    char *singular_noun;
    char *plural_noun;
} text_list_data_t;

typedef struct private_data_s {
    GQueue *parent_q;
} private_data_t;

static void
text_free_priv(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    if (out == NULL || out->priv == NULL) {
        return;
    }

    priv = out->priv;

    g_queue_free(priv->parent_q);
    free(priv);
    out->priv = NULL;
}

static bool
text_init(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    CRM_ASSERT(out != NULL);

    /* If text_init was previously called on this output struct, just return. */
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
text_finish(pcmk__output_t *out, crm_exit_t exit_status, bool print, void **copy_dest) {
    CRM_ASSERT(out != NULL && out->dest != NULL);
    fflush(out->dest);
}

static void
text_reset(pcmk__output_t *out) {
    CRM_ASSERT(out != NULL);

    if (out->dest != stdout) {
        out->dest = freopen(NULL, "w", out->dest);
    }

    CRM_ASSERT(out->dest != NULL);

    text_free_priv(out);
    text_init(out);
}

static void
text_subprocess_output(pcmk__output_t *out, int exit_status,
                       const char *proc_stdout, const char *proc_stderr) {
    CRM_ASSERT(out != NULL);

    if (proc_stdout != NULL) {
        fprintf(out->dest, "%s\n", proc_stdout);
    }

    if (proc_stderr != NULL) {
        fprintf(out->dest, "%s\n", proc_stderr);
    }
}

static void
text_version(pcmk__output_t *out, bool extended) {
    CRM_ASSERT(out != NULL && out->dest != NULL);

    if (extended) {
        fprintf(out->dest, "Pacemaker %s (Build: %s): %s\n", PACEMAKER_VERSION, BUILD_VERSION, CRM_FEATURES);
    } else {
        fprintf(out->dest, "Pacemaker %s\n", PACEMAKER_VERSION);
        fprintf(out->dest, "Written by Andrew Beekhof and "
                           "the Pacemaker project contributors\n");
    }
}

G_GNUC_PRINTF(2, 3)
static void
text_err(pcmk__output_t *out, const char *format, ...) {
    va_list ap;
    int len = 0;

    CRM_ASSERT(out != NULL);

    va_start(ap, format);

    /* Informational output does not get indented, to separate it from other
     * potentially indented list output.
     */
    len = vfprintf(stderr, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    /* Add a newline. */
    fprintf(stderr, "\n");
}

G_GNUC_PRINTF(2, 3)
static int
text_info(pcmk__output_t *out, const char *format, ...) {
    va_list ap;
    int len = 0;

    CRM_ASSERT(out != NULL);

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    va_start(ap, format);

    /* Informational output does not get indented, to separate it from other
     * potentially indented list output.
     */
    len = vfprintf(out->dest, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    /* Add a newline. */
    fprintf(out->dest, "\n");
    return pcmk_rc_ok;
}

static void
text_output_xml(pcmk__output_t *out, const char *name, const char *buf) {
    CRM_ASSERT(out != NULL);
    pcmk__indented_printf(out, "%s", buf);
}

G_GNUC_PRINTF(4, 5)
static void
text_begin_list(pcmk__output_t *out, const char *singular_noun, const char *plural_noun,
                const char *format, ...) {
    private_data_t *priv = NULL;
    text_list_data_t *new_list = NULL;
    va_list ap;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    priv = out->priv;

    va_start(ap, format);

    if (fancy && format) {
        pcmk__indented_vprintf(out, format, ap);
        fprintf(out->dest, ":\n");
    }

    va_end(ap);

    new_list = calloc(1, sizeof(text_list_data_t));
    new_list->len = 0;
    pcmk__str_update(&new_list->singular_noun, singular_noun);
    pcmk__str_update(&new_list->plural_noun, plural_noun);

    g_queue_push_tail(priv->parent_q, new_list);
}

G_GNUC_PRINTF(3, 4)
static void
text_list_item(pcmk__output_t *out, const char *id, const char *format, ...) {
    va_list ap;

    CRM_ASSERT(out != NULL);

    va_start(ap, format);

    if (fancy) {
        if (id != NULL) {
            /* Not really a good way to do this all in one call, so make it two.
             * The first handles the indentation and list styling.  The second
             * just prints right after that one.
             */
            pcmk__indented_printf(out, "%s: ", id);
            vfprintf(out->dest, format, ap);
        } else {
            pcmk__indented_vprintf(out, format, ap);
        }
    } else {
        pcmk__indented_vprintf(out, format, ap);
    }

    fputc('\n', out->dest);
    fflush(out->dest);
    va_end(ap);

    out->increment_list(out);
}

static void
text_increment_list(pcmk__output_t *out) {
    private_data_t *priv = NULL;
    gpointer tail;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    priv = out->priv;

    tail = g_queue_peek_tail(priv->parent_q);
    CRM_ASSERT(tail != NULL);
    ((text_list_data_t *) tail)->len++;
}

static void
text_end_list(pcmk__output_t *out) {
    private_data_t *priv = NULL;
    text_list_data_t *node = NULL;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    priv = out->priv;

    node = g_queue_pop_tail(priv->parent_q);

    if (node->singular_noun != NULL && node->plural_noun != NULL) {
        if (node->len == 1) {
            pcmk__indented_printf(out, "%d %s found\n", node->len, node->singular_noun);
        } else {
            pcmk__indented_printf(out, "%d %s found\n", node->len, node->plural_noun);
        }
    }

    free(node);
}

static bool
text_is_quiet(pcmk__output_t *out) {
    CRM_ASSERT(out != NULL);
    return out->quiet;
}

static void
text_spacer(pcmk__output_t *out) {
    CRM_ASSERT(out != NULL);
    fprintf(out->dest, "\n");
}

static void
text_progress(pcmk__output_t *out, bool end) {
    CRM_ASSERT(out != NULL);

    if (out->dest == stdout) {
        fprintf(out->dest, ".");

        if (end) {
            fprintf(out->dest, "\n");
        }
    }
}

pcmk__output_t *
pcmk__mk_text_output(char **argv) {
    pcmk__output_t *retval = calloc(1, sizeof(pcmk__output_t));

    if (retval == NULL) {
        return NULL;
    }

    retval->fmt_name = "text";
    retval->request = pcmk__quote_cmdline(argv);

    retval->init = text_init;
    retval->free_priv = text_free_priv;
    retval->finish = text_finish;
    retval->reset = text_reset;

    retval->register_message = pcmk__register_message;
    retval->message = pcmk__call_message;

    retval->subprocess_output = text_subprocess_output;
    retval->version = text_version;
    retval->info = text_info;
    retval->err = text_err;
    retval->output_xml = text_output_xml;

    retval->begin_list = text_begin_list;
    retval->list_item = text_list_item;
    retval->increment_list = text_increment_list;
    retval->end_list = text_end_list;

    retval->is_quiet = text_is_quiet;
    retval->spacer = text_spacer;
    retval->progress = text_progress;
    retval->prompt = pcmk__text_prompt;

    return retval;
}

G_GNUC_PRINTF(2, 0)
void
pcmk__formatted_vprintf(pcmk__output_t *out, const char *format, va_list args) {
    int len = 0;

    CRM_ASSERT(out != NULL);
    CRM_CHECK(pcmk__str_eq(out->fmt_name, "text", pcmk__str_none), return);

    len = vfprintf(out->dest, format, args);
    CRM_ASSERT(len >= 0);
}

G_GNUC_PRINTF(2, 3)
void
pcmk__formatted_printf(pcmk__output_t *out, const char *format, ...) {
    va_list ap;

    CRM_ASSERT(out != NULL);

    va_start(ap, format);
    pcmk__formatted_vprintf(out, format, ap);
    va_end(ap);
}

G_GNUC_PRINTF(2, 0)
void
pcmk__indented_vprintf(pcmk__output_t *out, const char *format, va_list args) {
    CRM_ASSERT(out != NULL);
    CRM_CHECK(pcmk__str_eq(out->fmt_name, "text", pcmk__str_none), return);

    if (fancy) {
        int level = 0;
        private_data_t *priv = out->priv;

        CRM_ASSERT(priv != NULL);

        level = g_queue_get_length(priv->parent_q);

        for (int i = 0; i < level; i++) {
            fprintf(out->dest, "  ");
        }

        if (level > 0) {
            fprintf(out->dest, "* ");
        }
    }

    pcmk__formatted_vprintf(out, format, args);
}

G_GNUC_PRINTF(2, 3)
void
pcmk__indented_printf(pcmk__output_t *out, const char *format, ...) {
    va_list ap;

    CRM_ASSERT(out != NULL);

    va_start(ap, format);
    pcmk__indented_vprintf(out, format, ap);
    va_end(ap);
}

void
pcmk__text_prompt(const char *prompt, bool echo, char **dest)
{
    int rc = 0;
    struct termios settings;
    tcflag_t orig_c_lflag = 0;

    CRM_ASSERT(prompt != NULL);
    CRM_ASSERT(dest != NULL);

    if (!echo) {
        rc = tcgetattr(0, &settings);
        if (rc == 0) {
            orig_c_lflag = settings.c_lflag;
            settings.c_lflag &= ~ECHO;
            rc = tcsetattr(0, TCSANOW, &settings);
        }
    }

    if (rc == 0) {
        fprintf(stderr, "%s: ", prompt);

        if (*dest != NULL) {
            free(*dest);
            *dest = NULL;
        }

#if HAVE_SSCANF_M
        rc = scanf("%ms", dest);
#else
        *dest = calloc(1, 1024);
        rc = scanf("%1023s", *dest);
#endif
        fprintf(stderr, "\n");
    }

    if (rc < 1) {
        free(*dest);
        *dest = NULL;
    }

    if (orig_c_lflag != 0) {
        settings.c_lflag = orig_c_lflag;
        /* rc = */ tcsetattr(0, TCSANOW, &settings);
    }
}
