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
#include <stdlib.h>
#include <glib.h>
#include <termios.h>

#include "crmcommon_private.h"

typedef struct text_list_data_s {
    unsigned int len;
    char *singular_noun;
    char *plural_noun;
} text_list_data_t;

typedef struct private_data_s {
    GQueue *parent_q;
    bool fancy;
} private_data_t;

static void
free_list_data(gpointer data) {
    text_list_data_t *list_data = data;

    free(list_data->singular_noun);
    free(list_data->plural_noun);
    free(list_data);
}

static void
text_free_priv(pcmk__output_t *out) {
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
text_init(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    pcmk__assert(out != NULL);

    /* If text_init was previously called on this output struct, just return. */
    if (out->priv != NULL) {
        return true;
    }

    out->priv = calloc(1, sizeof(private_data_t));
    if (out->priv == NULL) {
        return false;
    }

    priv = out->priv;
    priv->parent_q = g_queue_new();
    return true;
}

static void
text_finish(pcmk__output_t *out, crm_exit_t exit_status, bool print, void **copy_dest)
{
    pcmk__assert((out != NULL) && (out->dest != NULL));
    fflush(out->dest);
}

static void
text_reset(pcmk__output_t *out) {
    private_data_t *priv = NULL;
    bool old_fancy = false;

    pcmk__assert(out != NULL);

    if (out->dest != stdout) {
        out->dest = freopen(NULL, "w", out->dest);
    }

    pcmk__assert(out->dest != NULL);

    // Save priv->fancy before free/init sequence overwrites it
    priv = out->priv;
    old_fancy = priv->fancy;

    text_free_priv(out);
    text_init(out);

    priv = out->priv;
    priv->fancy = old_fancy;
}

static void
text_subprocess_output(pcmk__output_t *out, int exit_status,
                       const char *proc_stdout, const char *proc_stderr) {
    pcmk__assert(out != NULL);

    if (proc_stdout != NULL) {
        fprintf(out->dest, "%s\n", proc_stdout);
    }

    if (proc_stderr != NULL) {
        fprintf(out->dest, "%s\n", proc_stderr);
    }
}

static void
text_version(pcmk__output_t *out)
{
    pcmk__assert((out != NULL) && (out->dest != NULL));

    fprintf(out->dest,
            "Pacemaker " PACEMAKER_VERSION "\n"
            "Written by Andrew Beekhof and the Pacemaker project "
            "contributors\n");
}

G_GNUC_PRINTF(2, 3)
static void
text_err(pcmk__output_t *out, const char *format, ...) {
    va_list ap;

    pcmk__assert(out != NULL);

    va_start(ap, format);

    /* Informational output does not get indented, to separate it from other
     * potentially indented list output.
     */
    vfprintf(stderr, format, ap);
    va_end(ap);

    /* Add a newline. */
    fprintf(stderr, "\n");
}

G_GNUC_PRINTF(2, 3)
static int
text_info(pcmk__output_t *out, const char *format, ...) {
    va_list ap;

    pcmk__assert(out != NULL);

    if (out->is_quiet(out)) {
        return pcmk_rc_no_output;
    }

    va_start(ap, format);

    /* Informational output does not get indented, to separate it from other
     * potentially indented list output.
     */
    vfprintf(out->dest, format, ap);
    va_end(ap);

    /* Add a newline. */
    fprintf(out->dest, "\n");
    return pcmk_rc_ok;
}

G_GNUC_PRINTF(2, 3)
static int
text_transient(pcmk__output_t *out, const char *format, ...)
{
    return pcmk_rc_no_output;
}

static void
text_output_xml(pcmk__output_t *out, const char *name, const char *buf) {
    pcmk__assert(out != NULL);
    pcmk__indented_printf(out, "%s", buf);
}

G_GNUC_PRINTF(4, 5)
static void
text_begin_list(pcmk__output_t *out, const char *singular_noun, const char *plural_noun,
                const char *format, ...) {
    private_data_t *priv = NULL;
    text_list_data_t *new_list = NULL;
    va_list ap;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    va_start(ap, format);

    if (priv->fancy && (format != NULL)) {
        pcmk__indented_vprintf(out, format, ap);
        fprintf(out->dest, ":\n");
    }

    va_end(ap);

    new_list = pcmk__assert_alloc(1, sizeof(text_list_data_t));
    new_list->len = 0;
    new_list->singular_noun = pcmk__str_copy(singular_noun);
    new_list->plural_noun = pcmk__str_copy(plural_noun);

    g_queue_push_tail(priv->parent_q, new_list);
}

G_GNUC_PRINTF(3, 4)
static void
text_list_item(pcmk__output_t *out, const char *id, const char *format, ...) {
    private_data_t *priv = NULL;
    va_list ap;

    pcmk__assert(out != NULL);

    priv = out->priv;
    va_start(ap, format);

    if (priv->fancy) {
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

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    tail = g_queue_peek_tail(priv->parent_q);
    pcmk__assert(tail != NULL);
    ((text_list_data_t *) tail)->len++;
}

static void
text_end_list(pcmk__output_t *out) {
    private_data_t *priv = NULL;
    text_list_data_t *node = NULL;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    node = g_queue_pop_tail(priv->parent_q);

    if (node->singular_noun != NULL && node->plural_noun != NULL) {
        if (node->len == 1) {
            pcmk__indented_printf(out, "%d %s found\n", node->len, node->singular_noun);
        } else {
            pcmk__indented_printf(out, "%d %s found\n", node->len, node->plural_noun);
        }
    }

    free_list_data(node);
}

static bool
text_is_quiet(pcmk__output_t *out) {
    pcmk__assert(out != NULL);
    return out->quiet;
}

static void
text_spacer(pcmk__output_t *out) {
    pcmk__assert(out != NULL);
    fprintf(out->dest, "\n");
}

static void
text_progress(pcmk__output_t *out, bool end) {
    pcmk__assert(out != NULL);

    if (out->dest == stdout) {
        fprintf(out->dest, ".");

        if (end) {
            fprintf(out->dest, "\n");
        }
    }
}

void
pcmk__output_setup_text(pcmk__output_t *out)
{
    out->fmt_name = "text";

    out->init = text_init;
    out->free_priv = text_free_priv;
    out->finish = text_finish;
    out->reset = text_reset;

    out->subprocess_output = text_subprocess_output;
    out->version = text_version;
    out->info = text_info;
    out->transient = text_transient;
    out->err = text_err;
    out->output_xml = text_output_xml;

    out->begin_list = text_begin_list;
    out->list_item = text_list_item;
    out->increment_list = text_increment_list;
    out->end_list = text_end_list;

    out->is_quiet = text_is_quiet;
    out->spacer = text_spacer;
    out->progress = text_progress;
    out->prompt = pcmk__text_prompt;
}

/*!
 * \internal
 * \brief Check whether fancy output is enabled for a text output object
 *
 * This returns \c false if the output object is not of text format.
 *
 * \param[in] out  Output object
 *
 * \return \c true if \p out has fancy output enabled, or \c false otherwise
 */
bool
pcmk__output_text_get_fancy(pcmk__output_t *out)
{
    pcmk__assert(out != NULL);

    if (pcmk__str_eq(out->fmt_name, "text", pcmk__str_none)) {
        private_data_t *priv = out->priv;

        pcmk__assert(priv != NULL);
        return priv->fancy;
    }
    return false;
}

/*!
 * \internal
 * \brief Enable or disable fancy output for a text output object
 *
 * This does nothing if the output object is not of text format.
 *
 * \param[in,out] out      Output object
 * \param[in]     enabled  Whether fancy output should be enabled for \p out
 */
void
pcmk__output_text_set_fancy(pcmk__output_t *out, bool enabled)
{
    pcmk__assert(out != NULL);

    if (pcmk__str_eq(out->fmt_name, "text", pcmk__str_none)) {
        private_data_t *priv = out->priv;

        pcmk__assert(priv != NULL);
        priv->fancy = enabled;
    }
}

G_GNUC_PRINTF(2, 0)
void
pcmk__formatted_vprintf(pcmk__output_t *out, const char *format, va_list args) {
    pcmk__assert(out != NULL);
    CRM_CHECK(pcmk__str_eq(out->fmt_name, "text", pcmk__str_none), return);
    vfprintf(out->dest, format, args);
}

G_GNUC_PRINTF(2, 3)
void
pcmk__formatted_printf(pcmk__output_t *out, const char *format, ...) {
    va_list ap;

    pcmk__assert(out != NULL);

    va_start(ap, format);
    pcmk__formatted_vprintf(out, format, ap);
    va_end(ap);
}

G_GNUC_PRINTF(2, 0)
void
pcmk__indented_vprintf(pcmk__output_t *out, const char *format, va_list args) {
    private_data_t *priv = NULL;

    pcmk__assert(out != NULL);
    CRM_CHECK(pcmk__str_eq(out->fmt_name, "text", pcmk__str_none), return);

    priv = out->priv;

    if (priv->fancy) {
        int level = 0;
        private_data_t *priv = out->priv;

        pcmk__assert(priv != NULL);

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

    pcmk__assert(out != NULL);

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

    pcmk__assert((prompt != NULL) && (dest != NULL));

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
        *dest = pcmk__assert_alloc(1024, sizeof(char));
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
