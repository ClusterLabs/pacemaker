/*
 * Copyright 2019-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/common/util.h>
#include <crm/common/xml.h>
#include <libxml/tree.h>

#include "crmcommon_private.h"

static GHashTable *formatters = NULL;

#if defined(PCMK__UNIT_TESTING)
// LCOV_EXCL_START
GHashTable *
pcmk__output_formatters(void) {
    return formatters;
}

void
pcmk__set_output_formatters(GHashTable *value)
{
    formatters = value;
}
// LCOV_EXCL_STOP
#endif

void
pcmk__output_free(pcmk__output_t *out) {
    if (out == NULL) {
        return;
    }

    out->free_priv(out);

    if (out->messages != NULL) {
        g_hash_table_destroy(out->messages);
    }

    g_free(out->request);
    free(out);
}

/*!
 * \internal
 * \brief Call a formatting function for a previously registered message
 *
 * \param[in,out] out         Output object
 * \param[in]     message_id  Message to handle
 * \param[in]     ...         Arguments to be passed to the registered function
 *
 * \note This function is for implementing custom formatters. It should not
 *       be called directly. Instead, call <tt>out->message</tt>.
 *
 * \return Return value of the formatting function, or \c EINVAL if no
 *         formatting function is found
 */
static int
call_message(pcmk__output_t *out, const char *message_id, ...)
{
    va_list args;
    int rc = pcmk_rc_ok;
    pcmk__message_fn_t fn;

    pcmk__assert((out != NULL) && !pcmk__str_empty(message_id));

    fn = g_hash_table_lookup(out->messages, message_id);
    if (fn == NULL) {
        pcmk__debug("Called unknown output message '%s' for format '%s'",
                    message_id, out->fmt_name);
        return EINVAL;
    }

    va_start(args, message_id);
    rc = fn(out, args);
    va_end(args);

    return rc;
}

/*!
 * \internal
 * \brief Create a new \p pcmk__output_t structure
 *
 * This function does not register any message functions with the newly created
 * object.
 *
 * \param[in,out] out       Where to store the new output object
 * \param[in]     fmt_name  How to format output
 * \param[in]     filename  Where to write formatted output. This can be a
 *                          filename (the file will be overwritten if it already
 *                          exists), or \p NULL or \p "-" for stdout. For no
 *                          output, pass a filename of \p "/dev/null".
 * \param[in]     argv      List of command line arguments
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__bare_output_new(pcmk__output_t **out, const char *fmt_name,
                      const char *filename, char **argv)
{
    pcmk__output_setup_fn_t setup_fn = NULL;

    pcmk__assert((formatters != NULL) && (out != NULL));

    /* If no name was given, just try "text".  It's up to each tool to register
     * what it supports so this also may not be valid.
     */
    if (fmt_name == NULL) {
        setup_fn = g_hash_table_lookup(formatters, "text");
    } else {
        setup_fn = g_hash_table_lookup(formatters, fmt_name);
    }

    if (setup_fn == NULL) {
        return pcmk_rc_unknown_format;
    }

    *out = calloc(1, sizeof(pcmk__output_t));
    if (*out == NULL) {
        return ENOMEM;
    }

    setup_fn(*out);

    (*out)->request = pcmk__quote_cmdline(argv);
    (*out)->message = call_message;

    if (pcmk__str_eq(filename, "-", pcmk__str_null_matches)) {
        (*out)->dest = stdout;
    } else {
        (*out)->dest = fopen(filename, "w");
        if ((*out)->dest == NULL) {
            pcmk__output_free(*out);
            *out = NULL;
            return errno;
        }
    }

    (*out)->quiet = false;
    (*out)->messages = pcmk__strkey_table(free, NULL);

    if ((*out)->init(*out) == false) {
        pcmk__output_free(*out);
        return ENOMEM;
    }

    setenv("OCF_OUTPUT_FORMAT", (*out)->fmt_name, 1);

    return pcmk_rc_ok;
}

int
pcmk__output_new(pcmk__output_t **out, const char *fmt_name,
                 const char *filename, char **argv)
{
    int rc = pcmk__bare_output_new(out, fmt_name, filename, argv);

    if (rc == pcmk_rc_ok) {
        // Register libcrmcommon messages
        pcmk__register_option_messages(*out);
        pcmk__register_patchset_messages(*out);
    }
    return rc;
}

int
pcmk__register_format(GOptionGroup *group, const char *name,
                      pcmk__output_setup_fn_t setup_fn,
                      const GOptionEntry *options)
{
    char *name_copy = NULL;

    pcmk__assert((setup_fn != NULL) && !pcmk__str_empty(name));

    // cppcheck doesn't understand the above pcmk__assert line
    // cppcheck-suppress ctunullpointer
    name_copy = strdup(name);
    if (name_copy == NULL) {
        return ENOMEM;
    }

    if (formatters == NULL) {
        formatters = pcmk__strkey_table(free, NULL);
    }

    if (options != NULL && group != NULL) {
        g_option_group_add_entries(group, options);
    }

    g_hash_table_insert(formatters, name_copy, setup_fn);
    return pcmk_rc_ok;
}

void
pcmk__register_formats(GOptionGroup *group,
                       const pcmk__supported_format_t *formats)
{
    if (formats == NULL) {
        return;
    }

    for (const pcmk__supported_format_t *entry = formats; entry->name != NULL;
         entry++) {

        pcmk__register_format(group, entry->name, entry->setup_fn,
                              entry->options);
    }
}

void
pcmk__unregister_formats(void) {
    if (formatters != NULL) {
        g_hash_table_destroy(formatters);
        formatters = NULL;
    }
}

/*!
 * \internal
 * \brief Register a function to handle a custom message
 *
 * \param[in,out] out         Output object
 * \param[in]     message_id  Message to handle
 * \param[in]     fn          Format function to call for \p message_id
 */
void
pcmk__register_message(pcmk__output_t *out, const char *message_id,
                       pcmk__message_fn_t fn)
{
    pcmk__assert((out != NULL) && !pcmk__str_empty(message_id) && (fn != NULL));
    g_hash_table_replace(out->messages, pcmk__str_copy(message_id), fn);
}

void
pcmk__register_messages(pcmk__output_t *out, const pcmk__message_entry_t *table)
{
    for (const pcmk__message_entry_t *entry = table; entry->message_id != NULL;
         entry++) {
        if (pcmk__strcase_any_of(entry->fmt_name, "default", out->fmt_name, NULL)) {
            pcmk__register_message(out, entry->message_id, entry->fn);
        }
    }
}

void
pcmk__output_and_clear_error(GError **error, pcmk__output_t *out)
{
    if (error == NULL || *error == NULL) {
        return;
    }

    if (out != NULL) {
        out->err(out, "%s: %s", g_get_prgname(), (*error)->message);
    } else {
        fprintf(stderr, "%s: %s\n", g_get_prgname(), (*error)->message);
    }

    g_clear_error(error);
}

/*!
 * \internal
 * \brief Create an XML-only output object
 *
 * Create an output object that supports only the XML format, and free
 * existing XML if supplied (particularly useful for libpacemaker public API
 * functions that want to free any previous result supplied by the caller).
 *
 * \param[out]     out  Where to put newly created output object
 * \param[in,out]  xml  If \c *xml is non-NULL, this will be freed
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__xml_output_new(pcmk__output_t **out, xmlNodePtr *xml) {
    pcmk__supported_format_t xml_format[] = {
        PCMK__SUPPORTED_FORMAT_XML,
        { NULL, NULL, NULL }
    };

    if (xml == NULL) {
        return EINVAL;
    }

    if (*xml != NULL) {
        pcmk__xml_free(*xml);
        *xml = NULL;
    }
    pcmk__register_formats(NULL, xml_format);
    return pcmk__output_new(out, "xml", NULL, NULL);
}

/*!
 * \internal
 * \brief  Finish and free an XML-only output object
 *
 * \param[in,out] out         Output object to free
 * \param[in]     exit_status The exit value of the whole program
 * \param[out]    xml         If not NULL, where to store XML output
 */
void
pcmk__xml_output_finish(pcmk__output_t *out, crm_exit_t exit_status,
                        xmlNodePtr *xml)
{
    if (out == NULL) {
        return;
    }

    out->finish(out, exit_status, FALSE, (void **) xml);
    pcmk__output_free(out);
}

/*!
 * \internal
 * \brief Create a new output object using the "log" format
 *
 * \param[out] out  Where to store newly allocated output object
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__log_output_new(pcmk__output_t **out)
{
    int rc = pcmk_rc_ok;
    const char* argv[] = { "", NULL };
    pcmk__supported_format_t formats[] = {
        PCMK__SUPPORTED_FORMAT_LOG,
        { NULL, NULL, NULL }
    };

    pcmk__register_formats(NULL, formats);
    rc = pcmk__output_new(out, "log", NULL, (char **) argv);
    if ((rc != pcmk_rc_ok) || (*out == NULL)) {
        pcmk__err("Can't log certain messages due to internal error: %s",
                  pcmk_rc_str(rc));
        return rc;
    }
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Create a new output object using the "text" format
 *
 * \param[out] out       Where to store newly allocated output object
 * \param[in]  filename  Name of output destination file
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__text_output_new(pcmk__output_t **out, const char *filename)
{
    int rc = pcmk_rc_ok;
    const char* argv[] = { "", NULL };
    pcmk__supported_format_t formats[] = {
        PCMK__SUPPORTED_FORMAT_TEXT,
        { NULL, NULL, NULL }
    };

    pcmk__register_formats(NULL, formats);
    rc = pcmk__output_new(out, "text", filename, (char **) argv);
    if ((rc != pcmk_rc_ok) || (*out == NULL)) {
        pcmk__err("Can't create text output object to internal error: %s",
                  pcmk_rc_str(rc));
        return rc;
    }
    return pcmk_rc_ok;
}
