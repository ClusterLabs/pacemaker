/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <bzlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlIO.h>               // xmlOutputBuffer*
#include <libxml/xmlstring.h>           // xmlChar

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/common/xml_io.h>
#include "crmcommon_private.h"

/*!
 * \internal
 * \brief Decompress a <tt>bzip2</tt>-compressed file into a string buffer
 *
 * \param[in] filename  Name of file to decompress
 *
 * \return Newly allocated string with the decompressed contents of \p filename,
 *         or \c NULL on error.
 *
 * \note The caller is responsible for freeing the return value using \c free().
 */
static char *
decompress_file(const char *filename)
{
    char *buffer = NULL;
    int rc = pcmk_rc_ok;
    size_t length = 0;
    BZFILE *bz_file = NULL;
    FILE *input = fopen(filename, "r");

    if (input == NULL) {
        pcmk__err("Could not open %s for reading: %s", filename,
                  strerror(errno));
        return NULL;
    }

    bz_file = BZ2_bzReadOpen(&rc, input, 0, 0, NULL, 0);
    rc = pcmk__bzlib2rc(rc);
    if (rc != pcmk_rc_ok) {
        pcmk__err("Could not prepare to read compressed %s: %s " QB_XS " rc=%d",
                  filename, pcmk_rc_str(rc), rc);
        goto done;
    }

    do {
        int read_len = 0;

        buffer = pcmk__realloc(buffer, length + PCMK__BUFFER_SIZE + 1);
        read_len = BZ2_bzRead(&rc, bz_file, buffer + length, PCMK__BUFFER_SIZE);

        if ((rc == BZ_OK) || (rc == BZ_STREAM_END)) {
            pcmk__trace("Read %ld bytes from file: %d", (long) read_len, rc);
            length += read_len;
        }
    } while (rc == BZ_OK);

    rc = pcmk__bzlib2rc(rc);
    if (rc != pcmk_rc_ok) {
        rc = pcmk__bzlib2rc(rc);
        pcmk__err("Could not read compressed %s: %s " QB_XS " rc=%d", filename,
                  pcmk_rc_str(rc), rc);
        free(buffer);
        buffer = NULL;
    } else {
        buffer[length] = '\0';
    }

done:
    BZ2_bzReadClose(&rc, bz_file);
    fclose(input);
    return buffer;
}

/*!
 * \internal
 * \brief Parse XML from a file
 *
 * \param[in] filename  Name of file containing XML (\c NULL or \c "-" for
 *                      \c stdin); if \p filename ends in \c ".bz2", the file
 *                      will be decompressed using \c bzip2
 *
 * \return XML tree parsed from the given file on success, otherwise \c NULL
 */
xmlNode *
pcmk__xml_read(const char *filename)
{
    bool use_stdin = pcmk__str_eq(filename, "-", pcmk__str_null_matches);
    xmlNode *xml = NULL;
    xmlDoc *output = NULL;
    xmlParserCtxt *ctxt = NULL;
    const xmlError *last_error = NULL;

    // Create a parser context
    ctxt = xmlNewParserCtxt();
    CRM_CHECK(ctxt != NULL, return NULL);

    xmlCtxtResetLastError(ctxt);
    xmlSetGenericErrorFunc(ctxt, pcmk__log_xmllib_err);

    if (use_stdin) {
        output = xmlCtxtReadFd(ctxt, STDIN_FILENO, NULL, NULL,
                               XML_PARSE_NOBLANKS);

    } else if (g_str_has_suffix(filename, ".bz2")) {
        char *input = decompress_file(filename);

        if (input != NULL) {
            output = xmlCtxtReadDoc(ctxt, (const xmlChar *) input, NULL, NULL,
                                    XML_PARSE_NOBLANKS);
            free(input);
        }

    } else {
        output = xmlCtxtReadFile(ctxt, filename, NULL, XML_PARSE_NOBLANKS);
    }

    if (output != NULL) {
        pcmk__xml_new_private_data((xmlNode *) output);
        xml = xmlDocGetRootElement(output);
        if (xml != NULL) {
            /* @TODO Should we really be stripping out text? This seems like an
             * overly broad way to get rid of whitespace, if that's the goal.
             * Text nodes may be invalid in most or all Pacemaker inputs, but
             * stripping them in a generic "parse XML from file" function may
             * not be the best way to ignore them.
             */
            pcmk__strip_xml_text(xml);
        }
    }

    last_error = xmlCtxtGetLastError(ctxt);
    if ((last_error != NULL) && (xml != NULL)) {
        pcmk__log_xml_debug(xml, "partial");
        pcmk__xml_free(xml);
        xml = NULL;
    }

    xmlFreeParserCtxt(ctxt);
    return xml;
}

/*!
 * \internal
 * \brief Parse XML from a string
 *
 * \param[in] input  String to parse
 *
 * \return XML tree parsed from the given string on success, otherwise \c NULL
 */
xmlNode *
pcmk__xml_parse(const char *input)
{
    xmlNode *xml = NULL;
    xmlDoc *output = NULL;
    xmlParserCtxt *ctxt = NULL;
    const xmlError *last_error = NULL;

    if (input == NULL) {
        return NULL;
    }

    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        return NULL;
    }

    xmlCtxtResetLastError(ctxt);
    xmlSetGenericErrorFunc(ctxt, pcmk__log_xmllib_err);

    output = xmlCtxtReadDoc(ctxt, (const xmlChar *) input, NULL, NULL,
                            XML_PARSE_NOBLANKS);
    if (output != NULL) {
        pcmk__xml_new_private_data((xmlNode *) output);
        xml = xmlDocGetRootElement(output);
    }

    last_error = xmlCtxtGetLastError(ctxt);
    if ((last_error != NULL) && (xml != NULL)) {
        pcmk__log_xml_debug(xml, "partial");
        pcmk__xml_free(xml);
        xml = NULL;
    }

    xmlFreeParserCtxt(ctxt);
    return xml;
}

/*!
 * \internal
 * \brief Append an XML attribute to a buffer if it's not filterable
 *
 * \param[in]     attr       XML attribute
 * \param[in,out] user_data  Buffer (<tt>GString *</tt>)
 *
 * \return \c true (to continue iterating)
 *
 * \note This is compatible with \c pcmk__xe_foreach_const_attr().
 */
static bool
dump_xa_if_not_filterable(const xmlAttr *attr, void *user_data)
{
    if (!pcmk__xa_filterable((const char *) attr->name)) {
        pcmk__dump_xml_attr(attr, user_data);
    }

    return true;
}

/*!
 * \internal
 * \brief Append a string representation of an XML element to a buffer
 *
 * \param[in]     data     XML whose representation to append
 * \param[in]     options  Group of \p pcmk__xml_fmt_options flags
 * \param[in,out] buffer   Where to append the content (must not be \p NULL)
 * \param[in]     depth    Current indentation level
 */
static void
dump_xml_element(const xmlNode *data, uint32_t options, GString *buffer,
                 int depth)
{
    const bool pretty = pcmk__is_set(options, pcmk__xml_fmt_pretty);
    const bool filtered = pcmk__is_set(options, pcmk__xml_fmt_filtered);
    const int spaces = pretty? (2 * depth) : 0;

    for (int i = 0; i < spaces; i++) {
        g_string_append_c(buffer, ' ');
    }

    pcmk__g_strcat(buffer, "<", data->name, NULL);

    if (!filtered) {
        pcmk__xe_foreach_const_attr(data, pcmk__dump_xml_attr, buffer);

    } else {
        pcmk__xe_foreach_const_attr(data, dump_xa_if_not_filterable, buffer);
    }

    if (data->children == NULL) {
        g_string_append(buffer, "/>");

    } else {
        g_string_append_c(buffer, '>');
    }

    if (pretty) {
        g_string_append_c(buffer, '\n');
    }

    if (data->children) {
        for (const xmlNode *child = data->children; child != NULL;
             child = child->next) {
            pcmk__xml_string(child, options, buffer, depth + 1);
        }

        for (int lpc = 0; lpc < spaces; lpc++) {
            g_string_append_c(buffer, ' ');
        }

        pcmk__g_strcat(buffer, "</", data->name, ">", NULL);

        if (pretty) {
            g_string_append_c(buffer, '\n');
        }
    }
}

/*!
 * \internal
 * \brief Append XML text content to a buffer
 *
 * \param[in]     data     XML whose content to append
 * \param[in]     options  Group of <tt>enum pcmk__xml_fmt_options</tt>
 * \param[in,out] buffer   Where to append the content (must not be \p NULL)
 * \param[in]     depth    Current indentation level
 */
static void
dump_xml_text(const xmlNode *data, uint32_t options, GString *buffer,
              int depth)
{
    const bool pretty = pcmk__is_set(options, pcmk__xml_fmt_pretty);
    const int spaces = pretty? (2 * depth) : 0;
    const char *content = (const char *) data->content;
    gchar *content_esc = pcmk__xml_escape(content, pcmk__xml_escape_text);

    for (int lpc = 0; lpc < spaces; lpc++) {
        g_string_append_c(buffer, ' ');
    }

    g_string_append(buffer, content_esc);

    if (pretty) {
        g_string_append_c(buffer, '\n');
    }
    g_free(content_esc);
}

/*!
 * \internal
 * \brief Append XML CDATA content to a buffer
 *
 * \param[in]     data     XML whose content to append
 * \param[in]     options  Group of \p pcmk__xml_fmt_options flags
 * \param[in,out] buffer   Where to append the content (must not be \p NULL)
 * \param[in]     depth    Current indentation level
 */
static void
dump_xml_cdata(const xmlNode *data, uint32_t options, GString *buffer,
               int depth)
{
    const bool pretty = pcmk__is_set(options, pcmk__xml_fmt_pretty);
    const int spaces = pretty? (2 * depth) : 0;

    for (int lpc = 0; lpc < spaces; lpc++) {
        g_string_append_c(buffer, ' ');
    }

    pcmk__g_strcat(buffer, "<![CDATA[", (const char *) data->content, "]]>",
                   NULL);

    if (pretty) {
        g_string_append_c(buffer, '\n');
    }
}

/*!
 * \internal
 * \brief Append an XML comment to a buffer
 *
 * \param[in]     data     XML whose content to append
 * \param[in]     options  Group of \p pcmk__xml_fmt_options flags
 * \param[in,out] buffer   Where to append the content (must not be \p NULL)
 * \param[in]     depth    Current indentation level
 */
static void
dump_xml_comment(const xmlNode *data, uint32_t options, GString *buffer,
                 int depth)
{
    const bool pretty = pcmk__is_set(options, pcmk__xml_fmt_pretty);
    const int spaces = pretty? (2 * depth) : 0;

    for (int lpc = 0; lpc < spaces; lpc++) {
        g_string_append_c(buffer, ' ');
    }

    pcmk__g_strcat(buffer, "<!--", (const char *) data->content, "-->", NULL);

    if (pretty) {
        g_string_append_c(buffer, '\n');
    }
}

/*!
 * \internal
 * \brief Create a string representation of an XML object
 *
 * libxml2's \c xmlNodeDumpOutput() doesn't allow filtering, doesn't escape
 * special characters thoroughly, and doesn't allow a const argument.
 *
 * \param[in]     data     XML to convert
 * \param[in]     options  Group of \p pcmk__xml_fmt_options flags
 * \param[in,out] buffer   Where to store the text (must not be \p NULL)
 * \param[in]     depth    Current indentation level
 *
 * \todo Create a wrapper that doesn't require \p depth. Only used with
 *       recursive calls currently.
 */
void
pcmk__xml_string(const xmlNode *data, uint32_t options, GString *buffer,
                 int depth)
{
    if (data == NULL) {
        pcmk__trace("Nothing to dump");
        return;
    }

    pcmk__assert(buffer != NULL);
    CRM_CHECK(depth >= 0, depth = 0);

    switch(data->type) {
        case XML_ELEMENT_NODE:
            /* Handle below */
            dump_xml_element(data, options, buffer, depth);
            break;
        case XML_TEXT_NODE:
            if (pcmk__is_set(options, pcmk__xml_fmt_text)) {
                dump_xml_text(data, options, buffer, depth);
            }
            break;
        case XML_COMMENT_NODE:
            dump_xml_comment(data, options, buffer, depth);
            break;
        case XML_CDATA_SECTION_NODE:
            dump_xml_cdata(data, options, buffer, depth);
            break;
        default:
            pcmk__warn("Cannot convert XML %s node to text " QB_XS " type=%d",
                       pcmk__xml_element_type_text(data->type), data->type);
            break;
    }
}

/*!
 * \internal
 * \brief Write a string to a file stream, compressed using \c bzip2
 *
 * \param[in]     text       String to write
 * \param[in]     filename   Name of file being written (for logging only)
 * \param[in,out] stream     Open file stream to write to
 * \param[out]    bytes_out  Number of bytes written (valid only on success)
 *
 * \return Standard Pacemaker return code
 */
static int
write_compressed_stream(char *text, const char *filename, FILE *stream,
                        unsigned int *bytes_out)
{
    unsigned int bytes_in = 0;
    int rc = pcmk_rc_ok;

    // (5, 0, 0): (intermediate block size, silent, default workFactor)
    BZFILE *bz_file = BZ2_bzWriteOpen(&rc, stream, 5, 0, 0);

    rc = pcmk__bzlib2rc(rc);
    if (rc != pcmk_rc_ok) {
        pcmk__warn("Not compressing %s: could not prepare file stream: %s "
                   QB_XS " rc=%d",
                   filename, pcmk_rc_str(rc), rc);
        goto done;
    }

    BZ2_bzWrite(&rc, bz_file, text, strlen(text));
    rc = pcmk__bzlib2rc(rc);
    if (rc != pcmk_rc_ok) {
        pcmk__warn("Not compressing %s: could not compress data: %s "
                   QB_XS " rc=%d errno=%d",
                   filename, pcmk_rc_str(rc), rc, errno);
        goto done;
    }

    BZ2_bzWriteClose(&rc, bz_file, 0, &bytes_in, bytes_out);
    bz_file = NULL;
    rc = pcmk__bzlib2rc(rc);
    if (rc != pcmk_rc_ok) {
        pcmk__warn("Not compressing %s: could not write compressed data: %s "
                   QB_XS " rc=%d errno=%d",
                   filename, pcmk_rc_str(rc), rc, errno);
        goto done;
    }

    pcmk__trace("Compressed XML for %s from %u bytes to %u", filename, bytes_in,
                *bytes_out);

done:
    if (bz_file != NULL) {
        BZ2_bzWriteClose(&rc, bz_file, 0, NULL, NULL);
    }
    return rc;
}

/*!
 * \internal
 * \brief Write XML to a file stream
 *
 * \param[in]     xml       XML to write
 * \param[in]     filename  Name of file being written (for logging only)
 * \param[in,out] stream    Open file stream corresponding to filename (closed
 *                          when this function returns)
 * \param[in]     compress  Whether to compress XML before writing
 *
 * \return Standard Pacemaker return code
 */
static int
write_xml_stream(const xmlNode *xml, const char *filename, FILE *stream,
                 bool compress)
{
    GString *buffer = g_string_sized_new(1024);
    unsigned int bytes_out = 0;
    int rc = pcmk_rc_ok;

    pcmk__xml_string(xml, pcmk__xml_fmt_pretty, buffer, 0);
    CRM_CHECK(!pcmk__str_empty(buffer->str),
              pcmk__log_xml_info(xml, "dump-failed");
              rc = pcmk_rc_error;
              goto done);

    pcmk__log_xml_trace(xml, "writing");

    if (compress
        && (write_compressed_stream(buffer->str, filename, stream,
                                    &bytes_out) == pcmk_rc_ok)) {
        goto done;
    }

    rc = fprintf(stream, "%s", buffer->str);
    if (rc < 0) {
        rc = EIO;
        pcmk__err("Error writing %s", filename);
        goto done;
    }
    bytes_out = (unsigned int) rc;
    rc = pcmk_rc_ok;

done:
    if (fflush(stream) != 0) {
        rc = errno;
        pcmk__err("Error flushing %s: %s", filename, strerror(errno));
    }

    // Don't report error if the file does not support synchronization
    if ((fsync(fileno(stream)) < 0) && (errno != EROFS) && (errno != EINVAL)) {
        rc = errno;
        pcmk__err("Error synchronizing %s: %s", filename, strerror(errno));
    }

    fclose(stream);
    pcmk__trace("Saved %u bytes to %s as XML", bytes_out, filename);

    g_string_free(buffer, TRUE);
    return rc;
}

/*!
 * \internal
 * \brief Write XML to a file descriptor
 *
 * \param[in]  xml       XML to write
 * \param[in]  filename  Name of file being written (for logging only)
 * \param[in]  fd        Open file descriptor corresponding to \p filename
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__xml_write_fd(const xmlNode *xml, const char *filename, int fd)
{
    FILE *stream = NULL;

    CRM_CHECK((xml != NULL) && (fd > 0), return EINVAL);
    stream = fdopen(fd, "w");
    if (stream == NULL) {
        return errno;
    }

    return write_xml_stream(xml, pcmk__s(filename, "unnamed file"), stream,
                            false);
}

/*!
 * \internal
 * \brief Write XML to a file
 *
 * \param[in]  xml       XML to write
 * \param[in]  filename  Name of file to write
 * \param[in]  compress  If \c true, compress XML before writing
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__xml_write_file(const xmlNode *xml, const char *filename, bool compress)
{
    FILE *stream = NULL;

    CRM_CHECK((xml != NULL) && (filename != NULL), return EINVAL);
    stream = fopen(filename, "w");
    if (stream == NULL) {
        return errno;
    }

    return write_xml_stream(xml, filename, stream, compress);
}

/*!
 * \internal
 * \brief Serialize XML (using libxml) into provided descriptor
 *
 * \param[in] fd  File descriptor to (piece-wise) write to
 * \param[in] cur XML subtree to proceed
 *
 * \return a standard Pacemaker return code
 */
int
pcmk__xml2fd(int fd, xmlNode *cur)
{
    bool success;

    xmlOutputBuffer *fd_out = xmlOutputBufferCreateFd(fd, NULL);
    pcmk__mem_assert(fd_out);
    xmlNodeDumpOutput(fd_out, cur->doc, cur, 0, pcmk__xml_fmt_pretty, NULL);

    success = xmlOutputBufferWrite(fd_out, sizeof("\n") - 1, "\n") != -1;

    success = xmlOutputBufferClose(fd_out) != -1 && success;

    if (!success) {
        return EIO;
    }

    fsync(fd);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Write XML to a file in a temporary directory
 *
 * \param[in] xml       XML to write
 * \param[in] desc      Description of \p xml
 * \param[in] filename  Base name of file to write (\c NULL to create a name
 *                      based on a generated UUID)
 */
void
pcmk__xml_write_temp_file(const xmlNode *xml, const char *desc,
                          const char *filename)
{
    char *path = NULL;
    char *uuid = NULL;

    CRM_CHECK((xml != NULL) && (desc != NULL), return);

    if (filename == NULL) {
        uuid = pcmk__generate_uuid();
        filename = uuid;
    }
    path = pcmk__assert_asprintf("%s/%s", pcmk__get_tmpdir(), filename);

    pcmk__info("Saving %s to %s", desc, path);
    pcmk__xml_write_file(xml, filename, false);

    free(path);
    free(uuid);
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/common/xml_io_compat.h>

void
save_xml_to_file(const xmlNode *xml, const char *desc, const char *filename)
{
    char *f = NULL;

    if (filename == NULL) {
        char *uuid = pcmk__generate_uuid();

        f = pcmk__assert_asprintf("%s/%s", pcmk__get_tmpdir(), uuid);
        filename = f;
        free(uuid);
    }

    pcmk__info("Saving %s to %s", desc, filename);
    pcmk__xml_write_file(xml, filename, false);
    free(f);
}

// LCOV_EXCL_STOP
// End deprecated API
