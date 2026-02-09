/*
 * Copyright 2019-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct {
    /* gathered in log_begin_list */
    GQueue/*<char*>*/ *prefixes;
    uint8_t log_level;
    const char *function;
    const char *file;
    uint32_t line;
    uint32_t tags;
} private_data_t;

/*!
 * \internal
 * \brief Log a message using output object's log level and filters
 *
 * \param[in] priv    Output object's private_data_t
 * \param[in] fmt     printf(3)-style format string
 * \param[in] args... Format string arguments
 */
#define logger(priv, fmt, args...) do {                                     \
        qb_log_from_external_source(pcmk__s((priv)->function, __func__),    \
            pcmk__s((priv)->file, __FILE__), fmt, (priv)->log_level,        \
            (((priv)->line == 0)? __LINE__ : (priv)->line), (priv)->tags,   \
            ##args);                                                        \
    } while (0);

/*!
 * \internal
 * \brief Log a message using an explicit log level and output object's filters
 *
 * \param[in] priv    Output object's private_data_t
 * \param[in] level   Log level
 * \param[in] fmt     printf(3)-style format string
 * \param[in] ap      Variadic arguments
 */
#define logger_va(priv, level, fmt, ap) do {                                \
        qb_log_from_external_source_va(pcmk__s((priv)->function, __func__), \
            pcmk__s((priv)->file, __FILE__), fmt, level,                    \
            (((priv)->line == 0)? __LINE__ : (priv)->line), (priv)->tags,   \
            ap);                                                            \
    } while (0);

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

    pcmk__assert(out != NULL);

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
    pcmk__assert(out != NULL);

    out->dest = freopen(NULL, "w", out->dest);
    pcmk__assert(out->dest != NULL);

    log_free_priv(out);
    log_init(out);
}

static void
log_version(pcmk__output_t *out)
{
    private_data_t *priv = NULL;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    logger(priv, "Pacemaker " PACEMAKER_VERSION);
    logger(priv,
           "Written by Andrew Beekhof and the Pacemaker project contributors");
}

G_GNUC_PRINTF(2, 3)
static void
log_err(pcmk__output_t *out, const char *format, ...)
{
    va_list ap;
    private_data_t *priv = NULL;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    /* Error output does not get indented, to separate it from other
     * potentially indented list output.
     */
    va_start(ap, format);
    logger_va(priv, LOG_ERR, format, ap);
    va_end(ap);
}

static void
log_output_xml(pcmk__output_t *out, const char *name, const char *buf) {
    xmlNodePtr node = NULL;
    private_data_t *priv = NULL;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    node = pcmk__xe_create(NULL, name);
    pcmk__xe_set_content(node, "%s", buf);
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

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    va_start(ap, format);
    len = vasprintf(&buffer, format, ap);
    pcmk__assert(len >= 0);
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
log_list_item(pcmk__output_t *out, const char *name, const char *format, ...)
{
    gsize old_len = 0;
    va_list ap;
    private_data_t *priv = NULL;
    GString *buffer = g_string_sized_new(128);

    pcmk__assert((out != NULL) && (out->priv != NULL) && (format != NULL));
    priv = out->priv;

    // Message format: [<prefix1>[: <prefix2>...]: ]][<name>: ]<body>

    for (const GList *iter = priv->prefixes->head; iter != NULL;
         iter = iter->next) {

        pcmk__g_strcat(buffer, (const char *) iter->data, ": ", NULL);
    }

    if (!pcmk__str_empty(name)) {
        pcmk__g_strcat(buffer, name, ": ", NULL);
    }

    old_len = buffer->len;
    va_start(ap, format);
    g_string_append_vprintf(buffer, format, ap);
    va_end(ap);

    if (buffer->len > old_len) {
        // Don't log a message with an empty body
        logger(priv, "%s", buffer->str);
    }

    g_string_free(buffer, TRUE);
}

static void
log_end_list(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    if (priv->prefixes == NULL) {
      return;
    }
    pcmk__assert(priv->prefixes->tail != NULL);

    free((char *)priv->prefixes->tail->data);
    g_queue_pop_tail(priv->prefixes);
}

G_GNUC_PRINTF(2, 3)
static int
log_info(pcmk__output_t *out, const char *format, ...)
{
    va_list ap;
    private_data_t *priv = NULL;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    /* Informational output does not get indented, to separate it from other
     * potentially indented list output.
     */
    va_start(ap, format);
    logger_va(priv, priv->log_level, format, ap);
    va_end(ap);

    return pcmk_rc_ok;
}

G_GNUC_PRINTF(2, 3)
static int
log_transient(pcmk__output_t *out, const char *format, ...)
{
    va_list ap;
    private_data_t *priv = NULL;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    va_start(ap, format);
    logger_va(priv, QB_MAX(priv->log_level, LOG_DEBUG), format, ap);
    va_end(ap);

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

/*!
 * \internal
 * \brief Get the log level for a log output object
 *
 * This returns 0 if the output object is not of log format.
 *
 * \param[in] out  Output object
 *
 * \return Current log level for \p out
 */
uint8_t
pcmk__output_get_log_level(const pcmk__output_t *out)
{
    pcmk__assert(out != NULL);

    if (pcmk__str_eq(out->fmt_name, "log", pcmk__str_none)) {
        private_data_t *priv = out->priv;

        pcmk__assert(priv != NULL);
        return priv->log_level;
    }
    return 0;
}

/*!
 * \internal
 * \brief Set the log level for a log output object
 *
 * This does nothing if the output object is not of log format.
 *
 * \param[in,out] out        Output object
 * \param[in]     log_level  Log level constant (\c LOG_ERR, etc.) to use
 *
 * \note \c LOG_INFO is used by default for new \c pcmk__output_t objects.
 * \note Almost all formatted output messages respect this setting. However,
 *       <tt>out->err</tt> always logs at \c LOG_ERR.
 */
void
pcmk__output_set_log_level(pcmk__output_t *out, uint8_t log_level)
{
    pcmk__assert(out != NULL);

    if (pcmk__str_eq(out->fmt_name, "log", pcmk__str_none)) {
        private_data_t *priv = out->priv;

        pcmk__assert(priv != NULL);
        priv->log_level = log_level;
    }
}

/*!
 * \internal
 * \brief Set the file, function, line, and tags used to filter log output
 *
 * This does nothing if the output object is not of log format.
 *
 * \param[in,out] out       Output object
 * \param[in]     file      File name to filter with (or NULL for default)
 * \param[in]     function  Function name to filter with (or NULL for default)
 * \param[in]     line      Line number to filter with (or 0 for default)
 * \param[in]     tags      Tags to filter with (or 0 for none)
 *
 * \note Custom filters should generally be used only in short areas of a single
 *       function. When done, callers should call this function again with
 *       NULL/0 arguments to reset the filters.
 */
void
pcmk__output_set_log_filter(pcmk__output_t *out, const char *file,
                            const char *function, uint32_t line, uint32_t tags)
{
    pcmk__assert(out != NULL);

    if (pcmk__str_eq(out->fmt_name, "log", pcmk__str_none)) {
        private_data_t *priv = out->priv;

        pcmk__assert(priv != NULL);
        priv->file = file;
        priv->function = function;
        priv->line = line;
        priv->tags = tags;
    }
}
