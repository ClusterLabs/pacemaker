/*
 * Copyright 2015-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <glib.h>               // GString, etc.

#include <crm/crm.h>
#include <crm/common/xml.h>
#include "crmcommon_private.h"

#define BEST_EFFORT_STATUS 0

/*
 * Pacemaker uses digests (MD5 hashes) of stringified XML to detect changes in
 * the CIB as a whole, a particular resource's agent parameters, and the device
 * parameters last used to unfence a particular node.
 *
 * "v2" digests hash pcmk__xml_string() directly, while less efficient "v1"
 * digests do the same with a prefixed space, suffixed newline, and optional
 * pre-sorting.
 *
 * On-disk CIB digests use v1 without sorting.
 *
 * Operation digests use v1 with sorting, and are stored in a resource's
 * operation history in the CIB status section. They come in three flavors:
 * - a digest of (nearly) all resource parameters and options, used to detect
 *   any resource configuration change;
 * - a digest of resource parameters marked as nonreloadable, used to decide
 *   whether a reload or full restart is needed after a configuration change;
 * - and a digest of resource parameters not marked as private, used in
 *   simulations where private parameters have been removed from the input.
 *
 * Unfencing digests are set as node attributes, and are used to require
 * that nodes be unfenced again after a device's configuration changes.
 */

/*!
 * \internal
 * \brief Dump XML in a format used with v1 digests
 *
 * \param[in] xml  Root of XML to dump
 *
 * \return Newly allocated buffer containing dumped XML
 */
static GString *
dump_xml_for_digest(const xmlNode *xml)
{
    GString *buffer = g_string_sized_new(1024);

    /* for compatibility with the old result which is used for v1 digests */
    g_string_append_c(buffer, ' ');
    pcmk__xml_string(xml, 0, buffer, 0);
    g_string_append_c(buffer, '\n');

    return buffer;
}

/*!
 * \internal
 * \brief Compute an MD5 checksum for a given input string
 *
 * \param[in] input  Input string (can be \c NULL)
 *
 * \return Newly allocated string containing MD5 checksum for \p input, or
 *         \c NULL on error or if \p input is \c NULL
 *
 * \note The caller is responsible for freeing the return value using \c free().
 */
char *
pcmk__md5sum(const char *input)
{
    char *checksum = NULL;
    gchar *checksum_g = NULL;

    if (input == NULL) {
        return NULL;
    }

    /* g_compute_checksum_for_string() returns NULL if the input string is
     * empty. There are instances where we may want to hash an empty, but
     * non-NULL, string, so here we just hardcode the result.
     */
    if (pcmk__str_empty(input)) {
        return pcmk__str_copy("d41d8cd98f00b204e9800998ecf8427e");
    }

    checksum_g = g_compute_checksum_for_string(G_CHECKSUM_MD5, input, -1);
    if (checksum_g == NULL) {
        pcmk__err("Failed to compute MD5 checksum for %s", input);
        return NULL;
    }

    // Make a copy just so that callers can use free() instead of g_free()
    checksum = pcmk__str_copy(checksum_g);
    g_free(checksum_g);
    return checksum;
}

/*!
 * \internal
 * \brief Calculate and return v1 digest of XML tree
 *
 * \param[in] input  Root of XML to digest
 *
 * \return Newly allocated string containing digest
 *
 * \note Example return value: "c048eae664dba840e1d2060f00299e9d"
 */
static char *
calculate_xml_digest_v1(const xmlNode *input)
{
    GString *buffer = dump_xml_for_digest(input);
    char *digest = NULL;

    // buffer->len > 2 for initial space and trailing newline
    CRM_CHECK(buffer->len > 2,
              g_string_free(buffer, TRUE);
              return NULL);

    digest = pcmk__md5sum(buffer->str);

    g_string_free(buffer, TRUE);
    return digest;
}

/*!
 * \internal
 * \brief Calculate and return the digest of a CIB, suitable for storing on disk
 *
 * \param[in] input  Root of XML to digest
 *
 * \return Newly allocated string containing digest
 */
char *
pcmk__digest_on_disk_cib(const xmlNode *input)
{
    /* Always use the v1 format for on-disk digests.
     * * Switching to v2 affects even full-restart upgrades, so it would be a
     *   compatibility nightmare.
     * * We only use this once at startup. All other invocations are in a
     *   separate child process.
     */
    return calculate_xml_digest_v1(input);
}

/*!
 * \internal
 * \brief Calculate and return digest of a \c PCMK_XE_PARAMETERS element
 *
 * This is intended for parameters of a resource operation (also known as
 * resource action). A \c PCMK_XE_PARAMETERS element from a different source
 * (for example, resource agent metadata) may have child elements, which are not
 * allowed here.
 *
 * The digest is invariant to changes in the order of XML attributes.
 *
 * \param[in] input  XML element to digest (must have no children)
 *
 * \return Newly allocated string containing digest
 */
char *
pcmk__digest_op_params(const xmlNode *input)
{
    /* Switching to v2 digests would likely cause restarts during rolling
     * upgrades.
     *
     * @TODO Confirm this. Switch to v2 if safe, or drop this TODO otherwise.
     */
    char *digest = NULL;
    xmlNode *sorted = NULL;

    pcmk__assert(input->children == NULL);

    sorted = pcmk__xe_create(NULL, (const char *) input->name);
    pcmk__xe_copy_attrs(sorted, input, pcmk__xaf_none);
    pcmk__xe_sort_attrs(sorted);

    digest = calculate_xml_digest_v1(sorted);

    pcmk__xml_free(sorted);
    return digest;
}

/*!
 * \internal
 * \brief Calculate and return the digest of an XML tree
 *
 * \param[in] xml     XML tree to digest
 * \param[in] filter  Whether to filter certain XML attributes
 *
 * \return Newly allocated string containing digest
 */
char *
pcmk__digest_xml(const xmlNode *xml, bool filter)
{
    /* @TODO Filtering accounts for significant CPU usage. Consider removing if
     * possible.
     */
    char *digest = NULL;
    GString *buf = g_string_sized_new(1024);

    pcmk__xml_string(xml, (filter? pcmk__xml_fmt_filtered : 0), buf, 0);
    digest = pcmk__md5sum(buf->str);
    if (digest == NULL) {
        goto done;
    }

    pcmk__if_tracing(
        {
            char *trace_file = pcmk__assert_asprintf("digest-%s", digest);

            pcmk__trace("Saving %s.%s.%s to %s",
                        pcmk__xe_get(xml, PCMK_XA_ADMIN_EPOCH),
                        pcmk__xe_get(xml, PCMK_XA_EPOCH),
                        pcmk__xe_get(xml, PCMK_XA_NUM_UPDATES), trace_file);
            pcmk__xml_write_temp_file(xml, "digest input", trace_file);
            free(trace_file);
        },
        {}
    );

done:
    g_string_free(buf, TRUE);
    return digest;
}

/*!
 * \internal
 * \brief Check whether calculated digest of given XML matches expected digest
 *
 * \param[in] input     Root of XML tree to digest
 * \param[in] expected  Expected digest in on-disk format
 *
 * \return true if digests match, false on mismatch or error
 */
bool
pcmk__verify_digest(const xmlNode *input, const char *expected)
{
    char *calculated = NULL;
    bool passed;

    if (input != NULL) {
        calculated = pcmk__digest_on_disk_cib(input);
        if (calculated == NULL) {
            pcmk__err("Could not calculate digest for comparison");
            return false;
        }
    }
    passed = pcmk__str_eq(expected, calculated, pcmk__str_casei);
    if (passed) {
        pcmk__trace("Digest comparison passed: %s", calculated);
    } else {
        pcmk__err("Digest comparison failed: expected %s, calculated %s",
                  expected, calculated);
    }
    free(calculated);
    return passed;
}

/*!
 * \internal
 * \brief Check whether an XML attribute should be excluded from CIB digests
 *
 * \param[in] name  XML attribute name
 *
 * \return true if XML attribute should be excluded from CIB digest calculation
 */
bool
pcmk__xa_filterable(const char *name)
{
    static const char *filter[] = {
        PCMK_XA_CRM_DEBUG_ORIGIN,
        PCMK_XA_CIB_LAST_WRITTEN,
        PCMK_XA_UPDATE_ORIGIN,
        PCMK_XA_UPDATE_CLIENT,
        PCMK_XA_UPDATE_USER,
    };

    for (int i = 0; i < PCMK__NELEM(filter); i++) {
        if (strcmp(name, filter[i]) == 0) {
            return true;
        }
    }
    return false;
}

// Return true if a is an attribute that should be filtered
static bool
should_filter_for_digest(const xmlAttr *a, void *user_data)
{
    if (g_str_has_prefix((const char *) a->name, CRM_META "_")) {
        return true;
    }

    return pcmk__str_any_of((const char *) a->name,
                            PCMK_XA_ID,
                            PCMK_XA_CRM_FEATURE_SET,
                            PCMK__XA_OP_DIGEST,
                            PCMK__META_ON_NODE,
                            PCMK__META_ON_NODE_UUID,
                            "pcmk_external_ip",
                            NULL);
}

/*!
 * \internal
 * \brief Remove XML attributes not needed for operation digest
 *
 * \param[in,out] param_set  XML with operation parameters
 */
void
pcmk__filter_op_for_digest(xmlNode *param_set)
{
    char *key = NULL;
    char *timeout = NULL;
    guint interval_ms = 0;

    if (param_set == NULL) {
        return;
    }

    /* Timeout is useful for recurring operation digests, so grab it before
     * removing meta-attributes
     */
    key = crm_meta_name(PCMK_META_INTERVAL);
    pcmk__xe_get_guint(param_set, key, &interval_ms);
    free(key);
    key = NULL;
    if (interval_ms != 0) {
        key = crm_meta_name(PCMK_META_TIMEOUT);
        timeout = pcmk__xe_get_copy(param_set, key);
    }

    // Remove all CRM_meta_* attributes and certain other attributes
    pcmk__xe_remove_matching_attrs(param_set, false, should_filter_for_digest,
                                   NULL);

    // Add timeout back for recurring operation digests
    if (timeout != NULL) {
        pcmk__xe_set(param_set, key, timeout);
    }
    free(timeout);
    free(key);
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/common/util_compat.h>         // crm_md5sum()
#include <crm/common/xml_compat.h>
#include <crm/common/xml_element_compat.h>

char *
calculate_on_disk_digest(xmlNode *input)
{
    return calculate_xml_digest_v1(input);
}

char *
calculate_operation_digest(xmlNode *input, const char *version)
{
    xmlNode *sorted = sorted_xml(input, NULL, true);
    char *digest = calculate_xml_digest_v1(sorted);

    pcmk__xml_free(sorted);
    return digest;
}

char *
calculate_xml_versioned_digest(xmlNode *input, gboolean sort,
                               gboolean do_filter, const char *version)
{
    if ((version == NULL) || (pcmk__compare_versions("3.0.5", version) > 0)) {
        xmlNode *sorted = NULL;
        char *digest = NULL;

        if (sort) {
            xmlNode *sorted = sorted_xml(input, NULL, true);

            input = sorted;
        }

        pcmk__trace("Using v1 digest algorithm for %s",
                    pcmk__s(version, "unknown feature set"));

        digest = calculate_xml_digest_v1(input);

        pcmk__xml_free(sorted);
        return digest;
    }
    pcmk__trace("Using v2 digest algorithm for %s", version);
    return pcmk__digest_xml(input, do_filter);
}

char *
crm_md5sum(const char *buffer)
{
    char *digest = NULL;
    gchar *raw_digest = NULL;

    /* g_compute_checksum_for_string returns NULL if the input string is empty.
     * There are instances where we may want to hash an empty, but non-NULL,
     * string so here we just hardcode the result.
     */
    if (buffer == NULL) {
        return NULL;
    } else if (pcmk__str_empty(buffer)) {
        return pcmk__str_copy("d41d8cd98f00b204e9800998ecf8427e");
    }

    raw_digest = g_compute_checksum_for_string(G_CHECKSUM_MD5, buffer, -1);

    if (raw_digest == NULL) {
        pcmk__err("Failed to calculate hash");
        return NULL;
    }

    digest = pcmk__str_copy(raw_digest);
    g_free(raw_digest);

    pcmk__trace("Digest %s.", digest);
    return digest;
}

// LCOV_EXCL_STOP
// End deprecated API
