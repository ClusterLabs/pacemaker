/*
 * Copyright 2019-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/cmdline_internal.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

GOptionEntry pcmk__log_output_entries[] = {
    { NULL }
};

typedef struct private_data_s {
    /* gathered in log_begin_list */
    GQueue/*<char*>*/ *prefixes;
    int log_level;
} private_data_t;

static void
log_subprocess_output(pcmk__output_t *out, int exit_status,
                      const char *proc_stdout, const char *proc_stderr) {
    /* This function intentionally left blank */
}

static void
log_free_priv(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    if (out == NULL || out->priv == NULL) {
        return;
    }

    priv = out->priv;

    g_queue_free(priv->prefixes);
    free(priv);
    out->priv = NULL;
}

static bool
log_init(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    CRM_ASSERT(out != NULL);

    /* If log_init was previously called on this output struct, just return. */
    if (out->priv != NULL) {
        return true;
    }

    out->priv = calloc(1, sizeof(private_data_t));
    if (out->priv == NULL) {
         return false;
    }

    priv = out->priv;

    priv->prefixes = g_queue_new();
    priv->log_level = LOG_INFO;

    return true;
}

static void
log_finish(pcmk__output_t *out, crm_exit_t exit_status, bool print, void **copy_dest) {
    /* This function intentionally left blank */
}

static void
log_reset(pcmk__output_t *out) {
    CRM_ASSERT(out != NULL);

    out->dest = freopen(NULL, "w", out->dest);
    CRM_ASSERT(out->dest != NULL);

    log_free_priv(out);
    log_init(out);
}

static void
log_version(pcmk__output_t *out, bool extended) {
    private_data_t *priv = NULL;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    priv = out->priv;

    if (extended) {
        do_crm_log(priv->log_level, "Pacemaker %s (Build: %s): %s",
                   PACEMAKER_VERSION, BUILD_VERSION, CRM_FEATURES);
    } else {
        do_crm_log(priv->log_level, "Pacemaker %s", PACEMAKER_VERSION);
        do_crm_log(priv->log_level, "Written by Andrew Beekhof and"
                                    "the Pacemaker project contributors");
    }
}

G_GNUC_PRINTF(2, 3)
static void
log_err(pcmk__output_t *out, const char *format, ...) {
    va_list ap;
    char* buffer = NULL;
    int len = 0;

    CRM_ASSERT(out != NULL);

    va_start(ap, format);
    /* Informational output does not get indented, to separate it from other
     * potentially indented list output.
     */
    len = vasprintf(&buffer, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    crm_err("%s", buffer);

    free(buffer);
}

static void
log_output_xml(pcmk__output_t *out, const char *name, const char *buf) {
    xmlNodePtr node = NULL;
    private_data_t *priv = NULL;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    priv = out->priv;

    node = create_xml_node(NULL, name);
    xmlNodeSetContent(node, (pcmkXmlStr) buf);
    do_crm_log_xml(priv->log_level, name, node);
    free(node);
}

G_GNUC_PRINTF(4, 5)
static void
log_begin_list(pcmk__output_t *out, const char *singular_noun, const char *plural_noun,
               const char *format, ...) {
    int len = 0;
    va_list ap;
    char* buffer = NULL;
    private_data_t *priv = NULL;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    priv = out->priv;

    va_start(ap, format);
    len = vasprintf(&buffer, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    /* Don't skip empty prefixes,
     * otherwise there will be mismatch
     * in the log_end_list */
    if(strcmp(buffer, "") == 0) {
        /* nothing */
    }

    g_queue_push_tail(priv->prefixes, buffer);
}

G_GNUC_PRINTF(3, 4)
static void
log_list_item(pcmk__output_t *out, const char *name, const char *format, ...) {
    int len = 0;
    va_list ap;
    private_data_t *priv = NULL;
    char prefix[LINE_MAX] = { 0 };
    int offset = 0;
    char* buffer = NULL;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    priv = out->priv;

    for (GList* gIter = priv->prefixes->head; gIter; gIter = gIter->next) {
        if (strcmp(prefix, "") != 0) {
            offset += snprintf(prefix + offset, LINE_MAX - offset, ": %s", (char *)gIter->data);
        } else {
            offset = snprintf(prefix, LINE_MAX, "%s", (char *)gIter->data);
        }
    }

    va_start(ap, format);
    len = vasprintf(&buffer, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    if (strcmp(buffer, "") != 0) { /* We don't want empty messages */
        if ((name != NULL) && (strcmp(name, "") != 0)) {
            if (strcmp(prefix, "") != 0) {
                do_crm_log(priv->log_level, "%s: %s: %s", prefix, name, buffer);
            } else {
                do_crm_log(priv->log_level, "%s: %s", name, buffer);
            }
        } else {
            if (strcmp(prefix, "") != 0) {
                do_crm_log(priv->log_level, "%s: %s", prefix, buffer);
            } else {
                do_crm_log(priv->log_level, "%s", buffer);
            }
        }
    }
    free(buffer);
}

static void
log_end_list(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    priv = out->priv;

    if (priv->prefixes == NULL) {
      return;
    }
    CRM_ASSERT(priv->prefixes->tail != NULL);

    free((char *)priv->prefixes->tail->data);
    g_queue_pop_tail(priv->prefixes);
}

G_GNUC_PRINTF(2, 3)
static int
log_info(pcmk__output_t *out, const char *format, ...) {
    private_data_t *priv = NULL;
    int len = 0;
    va_list ap;
    char* buffer = NULL;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    priv = out->priv;

    va_start(ap, format);
    len = vasprintf(&buffer, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    do_crm_log(priv->log_level, "%s", buffer);

    free(buffer);
    return pcmk_rc_ok;
}

G_GNUC_PRINTF(2, 3)
static int
log_transient(pcmk__output_t *out, const char *format, ...)
{
    private_data_t *priv = NULL;
    int len = 0;
    va_list ap;
    char *buffer = NULL;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    priv = out->priv;

    va_start(ap, format);
    len = vasprintf(&buffer, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    do_crm_log(QB_MAX(priv->log_level, LOG_DEBUG), "%s", buffer);

    free(buffer);
    return pcmk_rc_ok;
}

static bool
log_is_quiet(pcmk__output_t *out) {
    return false;
}

static void
log_spacer(pcmk__output_t *out) {
    /* This function intentionally left blank */
}

static void
log_progress(pcmk__output_t *out, bool end) {
    /* This function intentionally left blank */
}

static void
log_prompt(const char *prompt, bool echo, char **dest) {
    /* This function intentionally left blank */
}

pcmk__output_t *
pcmk__mk_log_output(char **argv) {
    pcmk__output_t *retval = calloc(1, sizeof(pcmk__output_t));

    if (retval == NULL) {
        return NULL;
    }

    retval->fmt_name = "log";
    retval->request = pcmk__quote_cmdline(argv);

    retval->init = log_init;
    retval->free_priv = log_free_priv;
    retval->finish = log_finish;
    retval->reset = log_reset;

    retval->register_message = pcmk__register_message;
    retval->message = pcmk__call_message;

    retval->subprocess_output = log_subprocess_output;
    retval->version = log_version;
    retval->info = log_info;
    retval->transient = log_transient;
    retval->err = log_err;
    retval->output_xml = log_output_xml;

    retval->begin_list = log_begin_list;
    retval->list_item = log_list_item;
    retval->end_list = log_end_list;

    retval->is_quiet = log_is_quiet;
    retval->spacer = log_spacer;
    retval->progress = log_progress;
    retval->prompt = log_prompt;

    return retval;
}

int
pcmk__output_get_log_level(const pcmk__output_t *out)
{
    private_data_t *priv = NULL;

    CRM_ASSERT((out != NULL) && (out->priv != NULL));
    CRM_CHECK(pcmk__str_eq(out->fmt_name, "log", pcmk__str_none), return 0);

    priv = out->priv;
    return priv->log_level;
}

void
pcmk__output_set_log_level(pcmk__output_t *out, int log_level) {
    private_data_t *priv = NULL;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    CRM_CHECK(pcmk__str_eq(out->fmt_name, "log", pcmk__str_none), return);

    priv = out->priv;
    priv->log_level = log_level;
}
