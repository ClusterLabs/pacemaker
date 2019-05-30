/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRM_OUTPUT__H
#  define CRM_OUTPUT__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Formatted output for pacemaker tools
 */

#  include <stdbool.h>
#  include <stdio.h>
#  include <libxml/tree.h>

#  include <glib.h>
#  include <crm/common/results.h>

#  define PCMK__API_VERSION "1.0"

/* Add to the long_options block in each tool to get the formatted output
 * command line options added.  Then call pcmk__parse_output_args to handle
 * them.
 */
#  define PCMK__OUTPUT_OPTIONS(fmts) \
    {   "output-as", required_argument, NULL, 0, \
        "Specify the format for output, one of: " fmts \
    }, \
    {   "output-to", required_argument, NULL, 0, \
        "Specify the destination for formatted output, \"-\" for stdout or a filename" \
    }

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

/* Basic formatters everything supports.  This block needs to be updated every
 * time a new base formatter is added.
 */
pcmk__output_t *pcmk__mk_text_output(char **argv);
pcmk__output_t *pcmk__mk_xml_output(char **argv);

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
    char *fmt_name;

    /*!
     * \brief A copy of the request that generated this output.
     *
     * In the case of command line usage, this would be the command line
     * arguments.  For other use cases, it could be different.
     */
    char *request;

    /*!
     * \brief Does this formatter support a special quiet mode?
     *
     * In this mode, most output can be supressed but some information is still
     * displayed to an interactive user.  In general, machine-readable output
     * formats will not support this while user-oriented formats will.
     */
    bool supports_quiet;

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
    void (*free_priv)(pcmk__output_t *out);

    /*!
     * \internal
     * \brief Take whatever actions are necessary to end formatted output.
     *
     * This could include flushing output to a file, but does not include freeing
     * anything.  Note that pcmk__output_free() will automatically call this
     * function, so there is typically no need to do so manually.
     *
     * \note For formatted output implementers - This function should be written in
     *       such a way that it can be called repeatedly on a previously finished
     *       object without crashing.
     *
     * \param[in,out] out         The output functions structure.
     * \param[in]     exit_status The exit value of the whole program.
     */
    void (*finish) (pcmk__output_t *out, crm_exit_t exit_status);

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
     * \return 0 if a function was registered for the message, that function was
     *         called, and returned successfully.  A negative value is returned if
     *         no function was registered.  A positive value is returned if the
     *         function was called but encountered an error.
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
     * \brief Format an informational message that should be shown to
     *        to an interactive user.  Not all formatters will do this.
     *
     * \note A newline will automatically be added to the end of the format
     *       string, so callers should not include a newline.
     *
     * \param[in,out] out The output functions structure.
     * \param[in]     buf The message to be printed.
     * \param[in]     ... Arguments to be formatted.
     */
    void (*info) (pcmk__output_t *out, const char *format, ...) G_GNUC_PRINTF(2, 3);

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
     * \param[in]     name          A descriptive, user-facing name for this list.
     * \param[in]     singular_noun When outputting the summary for a list with
     *                              one item, the noun to use.
     * \param[in]     plural_noun   When outputting the summary for a list with
     *                              more than one item, the noun to use.
     */
    void (*begin_list) (pcmk__output_t *out, const char *name,
                        const char *singular_noun, const char *plural_noun);

    /*!
     * \internal
     * \brief Format a single item in a list.
     *
     * \param[in,out] out     The output functions structure.
     * \param[in]     name    A name to associate with this item.
     * \param[in]     content The item to be formatted.
     */
    void (*list_item) (pcmk__output_t *out, const char *name, const char *content);

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
 *        pcmk__output_new().  This will first call the finish function.
 *
 * \note While the create and finish functions are designed in such a way that
 *       they can be called repeatedly, this function will completely free the
 *       memory of the object.  Once this function has been called, producing
 *       more output requires starting over from pcmk__output_new().
 *
 * \param[in,out] out         The output structure.
 * \param[in]     exit_status The exit value of the whole program.
 */
void pcmk__output_free(pcmk__output_t *out, crm_exit_t exit_status);

/*!
 * \internal
 * \brief Create a new ::pcmk__output_t structure.
 *
 * \param[in,out] out      The destination of the new ::pcmk__output_t.
 * \param[in]     fmt_name How should output be formatted?
 * \param[in]     filename Where should formatted output be written to?  This
 *                         can be a filename (which will be overwritten if it
 *                         already exists), or NULL or "-" for stdout.  For no
 *                         output, pass a filename of "/dev/null".
 * \param[in]     argv     The list of command line arguments.
 *
 * \return 0 on success or an error code on error.
 */
int pcmk__output_new(pcmk__output_t **out, const char *fmt_name,
                     const char *filename, char **argv);

/*!
 * \internal
 * \brief Process formatted output related command line options.  This should
 *        be called wherever other long options are handled.
 *
 * \param[in]  argname      The long command line argument to process.
 * \param[in]  argvalue     The value of the command line argument.
 * \param[out] output_ty   How should output be formatted? ("text", "xml", etc.)
 * \param[out] output_dest Where should formatted output be written to?  This is
 *                         typically a filename, but could be NULL or "-".
 *
 * \return true if longname was handled, false otherwise.
 */
bool
pcmk__parse_output_args(const char *argname, char *argvalue, char **output_ty,
                        char **output_dest);

/*!
 * \internal
 * \brief Register a new output formatter, making it available for use
 *        the same as a base formatter.
 *
 * \param[in] fmt The new output formatter to register.
 *
 * \return 0 on success or an error code on error.
 */
int
pcmk__register_format(const char *fmt_name, pcmk__output_factory_t create);


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
pcmk__register_messages(pcmk__output_t *out, pcmk__message_entry_t *table);

/* Functions that are useful for implementing custom message formatters */

/*!
 * \internal
 * \brief A printf-like function.
 *
 * This function writes to out->dest and indents the text to the current level
 * of the text formatter's nesting.  This should be used when implementing
 * custom message functions instead of printf.
 *
 * \param[in,out] out The output functions structure.
 */
void
pcmk__indented_printf(pcmk__output_t *out, const char *format, ...) G_GNUC_PRINTF(2, 3);

/*!
 * \internal
 * \brief Add the given node as a child of the current list parent.  This is
 *        used when implementing custom message functions.
 *
 * \param[in,out] out  The output functions structure.
 * \param[in]     node An XML node to be added as a child.
 */
void
pcmk__xml_add_node(pcmk__output_t *out, xmlNodePtr node);

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
 * \param[in,out] out  The output functions structure.
 * \param[in]     node The node to be added/
 */
void
pcmk__xml_push_parent(pcmk__output_t *out, xmlNodePtr node);

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
pcmk__xml_pop_parent(pcmk__output_t *out);

#ifdef __cplusplus
}
#endif

#endif
