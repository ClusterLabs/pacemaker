/*
 * Copyright 2019-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <output_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_OUTPUT_INTERNAL__H
#define PCMK__CRM_COMMON_OUTPUT_INTERNAL__H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <libxml/tree.h>
#include <libxml/HTMLtree.h>

#include <glib.h>
#include <crm/common/results.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Formatted output for pacemaker tools
 */

#if defined(PCMK__WITH_ATTRIBUTE_OUTPUT_ARGS)
#define PCMK__OUTPUT_ARGS(ARGS...) __attribute__((output_args(ARGS)))
#else
#define PCMK__OUTPUT_ARGS(ARGS...)
#endif

typedef struct pcmk__output_s pcmk__output_t;

/*!
 * \internal
 * \brief The type of a function that creates a ::pcmk__output_t.
 *
 * Instances of this type are passed to pcmk__register_format(), stored in an
 * internal data structure, and later accessed by pcmk__output_new().  For 
 * examples, see pcmk__mk_xml_output() and pcmk__mk_text_output().
 *
 * \param[in] argv The list of command line arguments.
 */
typedef pcmk__output_t * (*pcmk__output_factory_t)(char **argv);

/*!
 * \internal
 * \brief The type of a custom message formatting function.
 *
 * These functions are defined by various libraries to support formatting of
 * types aside from the basic types provided by a ::pcmk__output_t.
 *
 * The meaning of the return value will be different for each message.
 * In general, however, 0 should be returned on success and a positive value
 * on error.
 *
 * \param[in,out] out   Output object to use to display message
 * \param[in,out] args  Message-specific arguments needed
 *
 * \note These functions must not call va_start or va_end - that is done
 *       automatically before the custom formatting function is called.
 */
typedef int (*pcmk__message_fn_t)(pcmk__output_t *out, va_list args);

/*!
 * \internal
 * \brief Internal type for tracking custom messages.
 *
 * Each library can register functions that format custom message types.  These
 * are commonly used to handle some library-specific type.  Registration is
 * done by first defining a table of ::pcmk__message_entry_t structures and
 * then passing that table to pcmk__register_messages().  Separate handlers
 * can be defined for the same message, but for different formats (xml vs.
 * text).  Unknown formats will be ignored.
 *
 * Additionally, a "default" value for fmt_table can be used.  In this case,
 * fn will be registered for all supported formats.  It is also possible to
 * register a default and then override that registration with a format-specific
 * function if necessary.
 *
 * \note The ::pcmk__message_entry_t table is processed in one pass, in order,
 * from top to bottom.  This means later entries with the same message_id will
 * override previous ones.  Thus, any default entry must come before any
 * format-specific entries for the same message_id.
 */
typedef struct pcmk__message_entry_s {
    /*!
     * \brief The message to be handled.
     *
     * This must be the same ID that is passed to the message function of
     * a ::pcmk__output_t.  Unknown message IDs will be ignored.
     */
    const char *message_id;

    /*!
     * \brief The format type this handler is for.
     *
     * This name must match the fmt_name of the currently active formatter in
     * order for the registered function to be called.  It is valid to have
     * multiple entries for the same message_id but with different fmt_name
     * values.
     */
    const char *fmt_name;

    /*!
     * \brief The function to be called for message_id given a match on
     *        fmt_name.  See comments on ::pcmk__message_fn_t.
     */
    pcmk__message_fn_t fn;
} pcmk__message_entry_t;

/*!
 * \internal
 * \brief This structure contains everything needed to add support for a
 *        single output formatter to a command line program.
 */
typedef struct pcmk__supported_format_s {
    /*!
     * \brief The name of this output formatter, which should match the
     *        fmt_name parameter in some ::pcmk__output_t structure.
     */
    const char *name;

    /*!
     * \brief A function that creates a ::pcmk__output_t.
     */
    pcmk__output_factory_t create;

    /*!
     * \brief Format-specific command line options.  This can be NULL if
     *        no command line options should be supported.
     */
    GOptionEntry *options;
} pcmk__supported_format_t;

/* The following three blocks need to be updated each time a new base formatter
 * is added.
 */

extern GOptionEntry pcmk__html_output_entries[];

pcmk__output_t *pcmk__mk_html_output(char **argv);
pcmk__output_t *pcmk__mk_log_output(char **argv);
pcmk__output_t *pcmk__mk_none_output(char **argv);
pcmk__output_t *pcmk__mk_text_output(char **argv);
pcmk__output_t *pcmk__mk_xml_output(char **argv);

#define PCMK__SUPPORTED_FORMAT_HTML { "html", pcmk__mk_html_output, pcmk__html_output_entries }
#define PCMK__SUPPORTED_FORMAT_LOG  { "log", pcmk__mk_log_output, NULL }
#define PCMK__SUPPORTED_FORMAT_NONE { PCMK_VALUE_NONE, pcmk__mk_none_output, NULL }
#define PCMK__SUPPORTED_FORMAT_TEXT { "text", pcmk__mk_text_output, NULL }
#define PCMK__SUPPORTED_FORMAT_XML  { "xml", pcmk__mk_xml_output, NULL }

/*!
 * \brief This structure contains everything that makes up a single output
 *        formatter.
 *
 * Instances of this structure may be created by calling pcmk__output_new()
 * with the name of the desired formatter.  They should later be freed with
 * pcmk__output_free().
 */
struct pcmk__output_s {
    /*!
     * \brief The name of this output formatter.
     */
    const char *fmt_name;

    /*!
     * \brief Should this formatter supress most output?
     *
     * \note This setting is not respected by all formatters.  In general,
     *       machine-readable output formats will not support this while
     *       user-oriented formats will.  Callers should use is_quiet()
     *       to test whether to print or not.
     */
    bool quiet;

    /*!
     * \brief A copy of the request that generated this output.
     *
     * In the case of command line usage, this would be the command line
     * arguments.  For other use cases, it could be different.
     */
    gchar *request;

    /*!
     * \brief Where output should be written.
     *
     * This could be a file handle, or stdout or stderr.  This is really only
     * useful internally.
     */
    FILE *dest;

    /*!
     * \brief Custom messages that are currently registered on this formatter.
     *
     * Keys are the string message IDs, values are ::pcmk__message_fn_t function
     * pointers.
     */
    GHashTable *messages;

    /*!
     * \brief Implementation-specific private data.
     *
     * Each individual formatter may have some private data useful in its
     * implementation.  This points to that data.  Callers should not rely on
     * its contents or structure.
     */
    void *priv;

    /*!
     * \internal
     * \brief Take whatever actions are necessary to prepare out for use.  This is
     *        called by pcmk__output_new().  End users should not need to call this.
     *
     * \note For formatted output implementers - This function should be written in
     *       such a way that it can be called repeatedly on an already initialized
     *       object without causing problems, or on a previously finished object
     *       without crashing.
     *
     * \param[in,out] out The output functions structure.
     *
     * \return true on success, false on error.
     */
    bool (*init) (pcmk__output_t *out);

    /*!
     * \internal
     * \brief Free the private formatter-specific data.
     *
     * This is called from pcmk__output_free() and does not typically need to be
     * called directly.
     *
     * \param[in,out] out The output functions structure.
     */
    void (*free_priv) (pcmk__output_t *out);

    /*!
     * \internal
     * \brief Take whatever actions are necessary to end formatted output.
     *
     * This could include flushing output to a file, but does not include freeing
     * anything.  The finish method can potentially be fairly complicated, adding
     * additional information to the internal data structures or doing whatever
     * else.  It is therefore suggested that finish only be called once.
     *
     * \note The print parameter will only affect those formatters that do all
     *       their output at the end.  Console-oriented formatters typically print
     *       a line at a time as they go, so this parameter will not affect them.
     *       Structured formatters will honor it, however.
     *
     * \note The copy_dest parameter does not apply to all formatters.  Console-
     *       oriented formatters do not build up a structure as they go, and thus
     *       do not have anything to return.  Structured formatters will honor it,
     *       however.  Note that each type of formatter will return a different
     *       type of value in this parameter.  To use this parameter, call this
     *       function like so:
     *
     * \code
     * xmlNode *dest = NULL;
     * out->finish(out, exit_code, false, (void **) &dest);
     * \endcode
     *
     * \param[in,out] out         The output functions structure.
     * \param[in]     exit_status The exit value of the whole program.
     * \param[in]     print       Whether this function should write any output.
     * \param[out]    copy_dest   A destination to store a copy of the internal
     *                            data structure for this output, or NULL if no
     *                            copy is required.  The caller should free this
     *                            memory when done with it.
     */
    void (*finish) (pcmk__output_t *out, crm_exit_t exit_status, bool print,
                    void **copy_dest);

    /*!
     * \internal
     * \brief Finalize output and then immediately set back up to start a new set
     *        of output.
     *
     * This is conceptually the same as calling finish and then init, though in
     * practice more be happening behind the scenes.
     *
     * \note This function differs from finish in that no exit_status is added.
     *       The idea is that the program is not shutting down, so there is not
     *       yet a final exit code.  Call finish on the last time through if this
     *       is needed.
     *
     * \param[in,out] out The output functions structure.
     */
    void (*reset) (pcmk__output_t *out);

    /*!
     * \internal
     * \brief Register a custom message.
     *
     * \param[in,out] out        The output functions structure.
     * \param[in]     message_id The name of the message to register.  This name
     *                           will be used as the message_id parameter to the
     *                           message function in order to call the custom
     *                           format function.
     * \param[in]     fn         The custom format function to call for message_id.
     */
    void (*register_message) (pcmk__output_t *out, const char *message_id,
                              pcmk__message_fn_t fn);

    /*!
     * \internal
     * \brief Call a previously registered custom message.
     *
     * \param[in,out] out        The output functions structure.
     * \param[in]     message_id The name of the message to call.  This name must
     *                           be the same as the message_id parameter of some
     *                           previous call to register_message.
     * \param[in] ...            Arguments to be passed to the registered function.
     *
     * \return A standard Pacemaker return code.  Generally: 0 if a function was
     *         registered for the message, that function was called, and returned
     *         successfully; EINVAL if no function was registered; or pcmk_rc_no_output
     *         if a function was called but produced no output.
     */
    int (*message) (pcmk__output_t *out, const char *message_id, ...);

    /*!
     * \internal
     * \brief Format the output of a completed subprocess.
     *
     * \param[in,out] out         The output functions structure.
     * \param[in]     exit_status The exit value of the subprocess.
     * \param[in]     proc_stdout stdout from the completed subprocess.
     * \param[in]     proc_stderr stderr from the completed subprocess.
     */
    void (*subprocess_output) (pcmk__output_t *out, int exit_status,
                               const char *proc_stdout, const char *proc_stderr);

    /*!
     * \internal
     * \brief Format version information.  This is useful for the --version
     *        argument of command line tools.
     *
     * \param[in,out] out  The output functions structure.
     */
    void (*version)(pcmk__output_t *out);

    /*!
     * \internal
     * \brief Format an informational message that should be shown to
     *        to an interactive user.  Not all formatters will do this.
     *
     * \note A newline will automatically be added to the end of the format
     *       string, so callers should not include a newline.
     *
     * \note It is possible for a formatter that supports this method to
     *       still not print anything out if is_quiet returns true.
     *
     * \param[in,out] out The output functions structure.
     * \param[in]     buf The message to be printed.
     * \param[in]     ... Arguments to be formatted.
     *
     * \return A standard Pacemaker return code.  Generally: pcmk_rc_ok
     *         if output was produced and pcmk_rc_no_output if it was not.
     *         As not all formatters implement this function, those that
     *         do not will always just return pcmk_rc_no_output.
     */
    int (*info) (pcmk__output_t *out, const char *format, ...) G_GNUC_PRINTF(2, 3);

    /*!
     * \internal
     * \brief Like \p info() but for messages that should appear only
     *        transiently. Not all formatters will do this.
     *
     * The originally envisioned use case is for console output, where a
     * transient status-related message may be quickly overwritten by a refresh.
     *
     * \param[in,out] out     The output functions structure.
     * \param[in]     format  The format string of the message to be printed.
     * \param[in]     ...     Arguments to be formatted.
     *
     * \return A standard Pacemaker return code. Generally: \p pcmk_rc_ok if
     *         output was produced and \p pcmk_rc_no_output if it was not. As
     *         not all formatters implement this function, those that do not
     *         will always just return \p pcmk_rc_no_output.
     */
    int (*transient) (pcmk__output_t *out, const char *format, ...)
        G_GNUC_PRINTF(2, 3);

    /*!
     * \internal
     * \brief Format an error message that should be shown to an interactive
     *        user.  Not all formatters will do this.
     *
     * \note A newline will automatically be added to the end of the format
     *       string, so callers should not include a newline.
     *
     * \note Formatters that support this method should always generate output,
     *       even if is_quiet returns true.
     *
     * \param[in,out] out The output functions structure.
     * \param[in]     buf The message to be printed.
     * \param[in]     ... Arguments to be formatted.
     */
    void (*err) (pcmk__output_t *out, const char *format, ...) G_GNUC_PRINTF(2, 3);

    /*!
     * \internal
     * \brief Format already formatted XML.
     *
     * \param[in,out] out  The output functions structure.
     * \param[in]     name A name to associate with the XML.
     * \param[in]     buf  The XML in a string.
     */
    void (*output_xml) (pcmk__output_t *out, const char *name, const char *buf);

    /*!
     * \internal
     * \brief Start a new list of items.
     *
     * \note For text output, this corresponds to another level of indentation.  For
     *       XML output, this corresponds to wrapping any following output in another
     *       layer of tags.
     *
     * \note If singular_noun and plural_noun are non-NULL, calling end_list will
     *       result in a summary being added.
     *
     * \param[in,out] out           The output functions structure.
     * \param[in]     singular_noun When outputting the summary for a list with
     *                              one item, the noun to use.
     * \param[in]     plural_noun   When outputting the summary for a list with
     *                              more than one item, the noun to use.
     * \param[in]     format        The format string.
     * \param[in]     ...           Arguments to be formatted.
     */
    void (*begin_list) (pcmk__output_t *out, const char *singular_noun,
                        const char *plural_noun, const char *format, ...)
                        G_GNUC_PRINTF(4, 5);

    /*!
     * \internal
     * \brief Format a single item in a list.
     *
     * \param[in,out] out     The output functions structure.
     * \param[in]     name    A name to associate with this item.
     * \param[in]     format  The format string.
     * \param[in]     ...     Arguments to be formatted.
     */
    void (*list_item) (pcmk__output_t *out, const char *name, const char *format, ...)
                      G_GNUC_PRINTF(3, 4);

    /*!
     * \internal
     * \brief Increment the internal counter of the current list's length.
     *
     * Typically, this counter is maintained behind the scenes as a side effect
     * of calling list_item().  However, custom functions that maintain lists
     * some other way will need to manage this counter manually.  This is
     * useful for implementing custom message functions and should not be
     * needed otherwise.
     *
     * \param[in,out] out The output functions structure.
     */
    void (*increment_list) (pcmk__output_t *out);

    /*!
     * \internal
     * \brief Conclude a list.
     *
     * \note If begin_list was called with non-NULL for both the singular_noun
     *       and plural_noun arguments, this function will output a summary.
     *       Otherwise, no summary will be added.
     *
     * \param[in,out] out The output functions structure.
     */
    void (*end_list) (pcmk__output_t *out);

    /*!
     * \internal
     * \brief Should anything be printed to the user?
     *
     * \note This takes into account both the \p quiet value as well as the
     *       current formatter.
     *
     * \param[in,out] out The output functions structure.
     *
     * \return true if output should be supressed, false otherwise.
     */
    bool (*is_quiet) (pcmk__output_t *out);

    /*!
     * \internal
     * \brief Output a spacer.  Not all formatters will do this.
     *
     * \param[in,out] out The output functions structure.
     */
    void (*spacer) (pcmk__output_t *out);

    /*!
     * \internal
     * \brief Output a progress indicator.  This is likely only useful for
     *        plain text, console based formatters.
     *
     * \param[in,out] out  The output functions structure
     * \param[in]     end  If true, output a newline afterwards (this should
     *                     only be used the last time this function is called)
     *
     */
    void (*progress) (pcmk__output_t *out, bool end);

    /*!
     * \internal
     * \brief Prompt the user for input.  Not all formatters will do this.
     *
     * \note This function is part of pcmk__output_t, but unlike all other
     *       function it does not take that as an argument.  In general, a
     *       prompt will go directly to the screen and therefore bypass any
     *       need to use the formatted output code to decide where and how
     *       to display.
     *
     * \param[in]  prompt The prompt to display.  This is required.
     * \param[in]  echo   If true, echo the user's input to the screen.  Set
     *                    to false for password entry.
     * \param[out] dest   Where to store the user's response.  This is
     *                    required.
     */
    void (*prompt) (const char *prompt, bool echo, char **dest);
};

/*!
 * \internal
 * \brief Call a formatting function for a previously registered message.
 *
 * \note This function is for implementing custom formatters.  It should not
 *       be called directly.  Instead, call out->message.
 *
 * \param[in,out] out        The output functions structure.
 * \param[in]     message_id The message to be handled.  Unknown messages
 *                           will be ignored.
 * \param[in]     ...        Arguments to be passed to the registered function.
 */
int
pcmk__call_message(pcmk__output_t *out, const char *message_id, ...);

/*!
 * \internal
 * \brief Free a ::pcmk__output_t structure that was previously created by
 *        pcmk__output_new().
 *
 * \note While the create and finish functions are designed in such a way that
 *       they can be called repeatedly, this function will completely free the
 *       memory of the object.  Once this function has been called, producing
 *       more output requires starting over from pcmk__output_new().
 *
 * \param[in,out] out         The output structure.
 */
void pcmk__output_free(pcmk__output_t *out);

/*!
 * \internal
 * \brief Create a new ::pcmk__output_t structure.
 *
 * This also registers message functions from libcrmcommon.
 *
 * \param[in,out] out      The destination of the new ::pcmk__output_t.
 * \param[in]     fmt_name How should output be formatted?
 * \param[in]     filename Where should formatted output be written to?  This
 *                         can be a filename (which will be overwritten if it
 *                         already exists), or NULL or "-" for stdout.  For no
 *                         output, pass a filename of "/dev/null".
 * \param[in]     argv     The list of command line arguments.
 *
 * \return Standard Pacemaker return code
 */
int pcmk__output_new(pcmk__output_t **out, const char *fmt_name,
                     const char *filename, char **argv);

/*!
 * \internal
 * \brief Register a new output formatter, making it available for use
 *        the same as a base formatter.
 *
 * \param[in,out] group   A ::GOptionGroup that formatted output related command
 *                        line arguments should be added to.  This can be NULL
 *                        for use outside of command line programs.
 * \param[in]     name    The name of the format.  This will be used to select a
 *                        format from command line options and for displaying help.
 * \param[in]     create  A function that creates a ::pcmk__output_t.
 * \param[in]     options Format-specific command line options.  These will be
 *                        added to the context.  This argument can also be NULL.
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__register_format(GOptionGroup *group, const char *name,
                      pcmk__output_factory_t create,
                      const GOptionEntry *options);

/*!
 * \internal
 * \brief Register an entire table of output formatters at once.
 *
 * \param[in,out] group A ::GOptionGroup that formatted output related command
 *                      line arguments should be added to.  This can be NULL
 *                      for use outside of command line programs.
 * \param[in]     table An array of ::pcmk__supported_format_t which should
 *                      all be registered.  This array must be NULL-terminated.
 *
 */
void
pcmk__register_formats(GOptionGroup *group,
                       const pcmk__supported_format_t *table);

/*!
 * \internal
 * \brief Unregister a previously registered table of custom formatting
 *        functions and destroy the internal data structures associated with them.
 */
void
pcmk__unregister_formats(void);

/*!
 * \internal
 * \brief Register a function to handle a custom message.
 *
 * \note This function is for implementing custom formatters.  It should not
 *       be called directly.  Instead, call out->register_message.
 *
 * \param[in,out] out        The output functions structure.
 * \param[in]     message_id The message to be handled.
 * \param[in]     fn         The custom format function to call for message_id.
 */
void
pcmk__register_message(pcmk__output_t *out, const char *message_id,
                       pcmk__message_fn_t fn);

/*!
 * \internal
 * \brief Register an entire table of custom formatting functions at once.
 *
 * This table can contain multiple formatting functions for the same message ID
 * if they are for different format types.
 *
 * \param[in,out] out   The output functions structure.
 * \param[in]     table An array of ::pcmk__message_entry_t values which should
 *                      all be registered.  This array must be NULL-terminated.
 */
void
pcmk__register_messages(pcmk__output_t *out,
                        const pcmk__message_entry_t *table);

/* Functions that are useful for implementing custom message formatters */

void pcmk__output_text_set_fancy(pcmk__output_t *out, bool enabled);

/*!
 * \internal
 * \brief A printf-like function.
 *
 * This function writes to out->dest and indents the text to the current level
 * of the text formatter's nesting.  This function should be used when implementing
 * custom message functions for the text output format.  It should not be used
 * for any other purpose.
 *
 * Typically, this function should be used instead of printf.
 *
 * \param[in,out] out    The output functions structure.
 * \param[in]     format The format string.
 * \param[in]     ...    Arguments to be passed to the format string.
 */
void
pcmk__indented_printf(pcmk__output_t *out, const char *format, ...) G_GNUC_PRINTF(2, 3);

/*!
 * \internal
 * \brief A vprintf-like function.
 *
 * This function is like pcmk__indented_printf(), except it takes a va_list instead
 * of a list of arguments.  This function should be used when implementing custom
 * functions for the text output format.  It should not be used for any other purpose.
 *
 * Typically, this function should be used instead of vprintf.
 *
 * \param[in,out] out    The output functions structure.
 * \param[in]     format The format string.
 * \param[in]     args   A list of arguments to apply to the format string.
 */
void
pcmk__indented_vprintf(pcmk__output_t *out, const char *format, va_list args) G_GNUC_PRINTF(2, 0);


/*!
 * \internal
 * \brief A printf-like function.
 *
 * This function writes to out->dest without indenting the text.  This function
 * should be used when implementing custom message functions for the text output
 * format.  It should not be used for any other purpose.
 *
 * \param[in,out] out    The output functions structure.
 * \param[in]     format The format string.
 * \param[in]     ...    Arguments to be passed to the format string.
 */
void
pcmk__formatted_printf(pcmk__output_t *out, const char *format, ...) G_GNUC_PRINTF(2, 3);

/*!
 * \internal
 * \brief A vprintf-like function.
 *
 * This function is like pcmk__formatted_printf(), except it takes a va_list instead
 * of a list of arguments.  This function should be used when implementing custom
 * message functions for the text output format.  It should not be used for any
 * other purpose.
 *
 * \param[in,out] out    The output functions structure.
 * \param[in]     format The format string.
 * \param[in]     args   A list of arguments to apply to the format string.
 */
void
pcmk__formatted_vprintf(pcmk__output_t *out, const char *format, va_list args) G_GNUC_PRINTF(2, 0);

/*!
 * \internal
 * \brief Prompt the user for input.
 *
 * \param[in]  prompt The prompt to display
 * \param[in]  echo   If true, echo the user's input to the screen.  Set
 *                    to false for password entry.
 * \param[out] dest   Where to store the user's response.
 */
void
pcmk__text_prompt(const char *prompt, bool echo, char **dest);

uint8_t
pcmk__output_get_log_level(const pcmk__output_t *out);

void
pcmk__output_set_log_level(pcmk__output_t *out, uint8_t log_level);

void pcmk__output_set_log_filter(pcmk__output_t *out, const char *file,
                                 const char *function, uint32_t line,
                                 uint32_t tags);


/*!
 * \internal
 * \brief Create and return a new XML node with the given name, as a child of the
 *        current list parent.  The new node is then added as the new list parent,
 *        meaning all subsequent nodes will be its children.  This is used when
 *        implementing custom functions.
 *
 * \param[in,out] out  The output functions structure.
 * \param[in]     name The name of the node to be created.
 */
xmlNode *
pcmk__output_xml_create_parent(pcmk__output_t *out, const char *name);

/*!
 * \internal
 * \brief Add a copy of the given node as a child of the current list parent.
 *        This is used when implementing custom message functions.
 *
 * \param[in,out] out  The output functions structure.
 * \param[in]     node An XML node to copy as a child.
 */
void
pcmk__output_xml_add_node_copy(pcmk__output_t *out, xmlNodePtr node);

/*!
 * \internal
 * \brief Create and return a new XML node with the given name, as a child of the
 *        current list parent.  This is used when implementing custom functions.
 *
 * \param[in,out] out  The output functions structure.
 * \param[in]     name The name of the node to be created.
 * \param[in]     ...     Name/value pairs to set as XML properties.
 */
xmlNodePtr
pcmk__output_create_xml_node(pcmk__output_t *out, const char *name, ...)
G_GNUC_NULL_TERMINATED;

/*!
 * \internal
 * \brief Like pcmk__output_create_xml_node(), but add the given text content to the
 *        new node.
 *
 * \param[in,out] out     The output functions structure.
 * \param[in]     name    The name of the node to be created.
 * \param[in]     content The text content of the node.
 */
xmlNodePtr
pcmk__output_create_xml_text_node(pcmk__output_t *out, const char *name, const char *content);

/*!
 * \internal
 * \brief Push a parent XML node onto the stack.  This is used when implementing
 *        custom message functions.
 *
 * The XML output formatter maintains an internal stack to keep track of which nodes
 * are parents in order to build up the tree structure.  This function can be used
 * to temporarily push a new node onto the stack.  After calling this function, any
 * other formatting functions will have their nodes added as children of this new
 * parent.
 *
 * \param[in,out] out     The output functions structure
 * \param[in]     parent  XML node to add
 */
void
pcmk__output_xml_push_parent(pcmk__output_t *out, xmlNodePtr parent);

/*!
 * \internal
 * \brief Pop a parent XML node onto the stack.  This is used when implementing
 *        custom message functions.
 *
 * This function removes a parent node from the stack.  See pcmk__xml_push_parent()
 * for more details.
 *
 * \note Little checking is done with this function.  Be sure you only pop parents
 * that were previously pushed.  In general, it is best to keep the code between
 * push and pop simple.
 *
 * \param[in,out] out The output functions structure.
 */
void
pcmk__output_xml_pop_parent(pcmk__output_t *out);

/*!
 * \internal
 * \brief Peek a parent XML node onto the stack.  This is used when implementing
 *        custom message functions.
 *
 * This function peeks a parent node on stack.  See pcmk__xml_push_parent()
 * for more details. It has no side-effect and can be called for an empty stack.
 *
 * \note Little checking is done with this function.
 *
 * \param[in,out] out The output functions structure.
 *
 * \return NULL if stack is empty, otherwise the parent of the stack.
 */
xmlNodePtr
pcmk__output_xml_peek_parent(pcmk__output_t *out);

/*!
 * \internal
 * \brief Create a new XML node consisting of the provided text inside an HTML
 *        element node of the given name.
 *
 * \param[in,out] out          The output functions structure.
 * \param[in]     element_name The name of the new HTML element.
 * \param[in]     id           The CSS ID selector to apply to this element.
 *                             If NULL, no ID is added.
 * \param[in]     class_name   The CSS class selector to apply to this element.
 *                             If NULL, no class is added.
 * \param[in]     text         The text content of the node.
 */
xmlNodePtr
pcmk__output_create_html_node(pcmk__output_t *out, const char *element_name, const char *id,
                              const char *class_name, const char *text);

xmlNode *pcmk__html_create(xmlNode *parent, const char *name, const char *id,
                           const char *class_name);

void pcmk__html_set_title(const char *name);

/*!
 * \internal
 * \brief Add an HTML tag to the <head> section.
 *
 * The arguments after name are a NULL-terminated list of keys and values,
 * all of which will be added as attributes to the given tag.  For instance,
 * the following code would generate the tag
 * "<meta http-equiv='refresh' content='19'>":
 *
 * \code
 * pcmk__html_add_header(PCMK__XE_META,
 *                       PCMK__XA_HTTP_EQUIV, PCMK__VALUE_REFRESH,
 *                       PCMK__XA_CONTENT, "19",
 *                       NULL);
 * \endcode
 *
 * \param[in]     name   The HTML tag for the new node.
 * \param[in]     ...    A NULL-terminated key/value list of attributes.
 */
void
pcmk__html_add_header(const char *name, ...)
G_GNUC_NULL_TERMINATED;

/*!
 * \internal
 * \brief Handle end-of-program error reporting
 *
 * \param[in,out] error A GError object potentially containing some error.
 *                      If NULL, do nothing.
 * \param[in,out] out   The output functions structure.  If NULL, any errors
 *                      will simply be printed to stderr.
 */
void pcmk__output_and_clear_error(GError **error, pcmk__output_t *out);

int pcmk__xml_output_new(pcmk__output_t **out, xmlNodePtr *xml);
void pcmk__xml_output_finish(pcmk__output_t *out, crm_exit_t exit_status, xmlNodePtr *xml);
int pcmk__log_output_new(pcmk__output_t **out);
int pcmk__text_output_new(pcmk__output_t **out, const char *filename);

/*!
 * \internal
 * \brief Check whether older style XML output is enabled
 *
 * The legacy flag should be used sparingly. Its meaning depends on the context
 * in which it's used.
 *
 * \param[in] out  Output object
 *
 * \return \c true if the \c legacy_xml flag is enabled for \p out, or \c false
 *         otherwise
 */
// @COMPAT This can be removed when `crm_mon -X` and daemon metadata are removed
bool pcmk__output_get_legacy_xml(pcmk__output_t *out);

/*!
 * \internal
 * \brief Enable older style XML output
 *
 * The legacy flag should be used sparingly. Its meaning depends on the context
 * in which it's used.
 *
 * \param[in,out] out  Output object
 */
// @COMPAT This can be removed when `crm_mon -X` and daemon metadata are removed
void pcmk__output_set_legacy_xml(pcmk__output_t *out);

/*!
 * \internal
 * \brief Enable using the <list> element for lists
 *
 * \note This function is only used in limited places and should not be
 * used anywhere new.  We are trying to discourage and ultimately remove
 * uses of this style of list.
 *
 * @COMPAT This can be removed when the stonith_admin and crm_resource
 * schemas can be changed
 */
void pcmk__output_enable_list_element(pcmk__output_t *out);

/*!
 * \internal
 * \brief Select an updated return code for an operation on a \p pcmk__output_t
 *
 * This function helps to keep an up-to-date record of the most relevant return
 * code from a series of operations on a \p pcmk__output_t object. For example,
 * suppose the object has already produced some output, and we've saved a
 * \p pcmk_rc_ok return code. A new operation did not produce any output and
 * returned \p pcmk_rc_no_output. We can ignore the new \p pcmk_rc_no_output
 * return code and keep the previous \p pcmk_rc_ok return code.
 *
 * It prioritizes return codes as follows (from highest to lowest priority):
 * 1. Other return codes (unexpected errors)
 * 2. \p pcmk_rc_ok
 * 3. \p pcmk_rc_no_output
 *
 * \param[in] old_rc  Saved return code from \p pcmk__output_t operations
 * \param[in] new_rc  New return code from a \p pcmk__output_t operation
 *
 * \retval \p old_rc  \p new_rc is \p pcmk_rc_no_output, or \p new_rc is
 *                    \p pcmk_rc_ok and \p old_rc is not \p pcmk_rc_no_output
 * \retval \p new_rc  Otherwise
 */
static inline int
pcmk__output_select_rc(int old_rc, int new_rc)
{
    switch (new_rc) {
        case pcmk_rc_no_output:
            return old_rc;
        case pcmk_rc_ok:
            switch (old_rc) {
                case pcmk_rc_no_output:
                    return new_rc;
                default:
                    return old_rc;
            }
        default:
            return new_rc;
    }
}

#if defined(PCMK__UNIT_TESTING)
/* If we are building libcrmcommon_test.a, add this accessor function so we can
 * inspect the internal formatters hash table.
 */
GHashTable *pcmk__output_formatters(void);
#endif

#define PCMK__OUTPUT_SPACER_IF(out_obj, cond)   \
    if (cond) {                                 \
        out->spacer(out);                       \
    }

#define PCMK__OUTPUT_LIST_HEADER(out_obj, cond, retcode, title...)  \
    if (retcode == pcmk_rc_no_output) {                             \
        PCMK__OUTPUT_SPACER_IF(out_obj, cond);                      \
        retcode = pcmk_rc_ok;                                       \
        out_obj->begin_list(out_obj, NULL, NULL, title);            \
    }

#define PCMK__OUTPUT_LIST_FOOTER(out_obj, retcode)  \
    if (retcode == pcmk_rc_ok) {                    \
        out_obj->end_list(out_obj);                 \
    }

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_OUTPUT_INTERNAL__H
