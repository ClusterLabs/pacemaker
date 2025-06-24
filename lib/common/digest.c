/*
 * Copyright 2015-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <glib.h>               // GString, etc.
#include <gnutls/crypto.h>      // gnutls_hash_fast(), gnutls_hash_get_len()
#include <gnutls/gnutls.h>      // gnutls_strerror()

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
dump_xml_for_digest(xmlNodePtr xml)
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
 * \brief Calculate and return v1 digest of XML tree
 *
 * \param[in] input  Root of XML to digest
 *
 * \return Newly allocated string containing digest
 *
 * \note Example return value: "c048eae664dba840e1d2060f00299e9d"
 */
static char *
calculate_xml_digest_v1(xmlNode *input)
{
    GString *buffer = dump_xml_for_digest(input);
    char *digest = NULL;

    // buffer->len > 2 for initial space and trailing newline
    CRM_CHECK(buffer->len > 2,
              g_string_free(buffer, TRUE);
              return NULL);

    digest = crm_md5sum((const char *) buffer->str);
    crm_log_xml_trace(input, "digest:source");

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
pcmk__digest_on_disk_cib(xmlNode *input)
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
 * \brief Calculate and return digest of an operation XML element
 *
 * The digest is invariant to changes in the order of XML attributes, provided
 * that \p input has no children.
 *
 * \param[in] input  Root of XML to digest
 *
 * \return Newly allocated string containing digest
 */
char *
pcmk__digest_operation(xmlNode *input)
{
    /* Switching to v2 digests would likely cause restarts during rolling
     * upgrades.
     *
     * @TODO Confirm this. Switch to v2 if safe, or drop this TODO otherwise.
     */
    xmlNode *sorted = pcmk__xml_copy(NULL, input);
    char *digest = NULL;

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
    digest = crm_md5sum(buf->str);

    pcmk__if_tracing(
        {
            char *trace_file = crm_strdup_printf("%s/digest-%s",
                                                 pcmk__get_tmpdir(), digest);

            crm_trace("Saving %s.%s.%s to %s",
                      crm_element_value(xml, PCMK_XA_ADMIN_EPOCH),
                      crm_element_value(xml, PCMK_XA_EPOCH),
                      crm_element_value(xml, PCMK_XA_NUM_UPDATES),
                      trace_file);
            save_xml_to_file(xml, "digest input", trace_file);
            free(trace_file);
        },
        {}
    );
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
pcmk__verify_digest(xmlNode *input, const char *expected)
{
    char *calculated = NULL;
    bool passed;

    if (input != NULL) {
        calculated = pcmk__digest_on_disk_cib(input);
        if (calculated == NULL) {
            crm_perror(LOG_ERR, "Could not calculate digest for comparison");
            return false;
        }
    }
    passed = pcmk__str_eq(expected, calculated, pcmk__str_casei);
    if (passed) {
        crm_trace("Digest comparison passed: %s", calculated);
    } else {
        crm_err("Digest comparison failed: expected %s, calculated %s",
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

char *
crm_md5sum(const char *buffer)
{
    char *digest = NULL;
    gchar *raw_digest = NULL;

    if (buffer == NULL) {
        return NULL;
    }

    raw_digest = g_compute_checksum_for_string(G_CHECKSUM_MD5, buffer, -1);

    if (raw_digest == NULL) {
        crm_err("Failed to calculate hash");
        return NULL;
    }

    digest = pcmk__str_copy(raw_digest);
    g_free(raw_digest);

    crm_trace("Digest %s.", digest);
    return digest;
}

// Return true if a is an attribute that should be filtered
static bool
should_filter_for_digest(xmlAttrPtr a, void *user_data)
{
    if (strncmp((const char *) a->name, CRM_META "_",
                sizeof(CRM_META " ") - 1) == 0) {
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
    if (crm_element_value_ms(param_set, key, &interval_ms) != pcmk_ok) {
        interval_ms = 0;
    }
    free(key);
    key = NULL;
    if (interval_ms != 0) {
        key = crm_meta_name(PCMK_META_TIMEOUT);
        timeout = crm_element_value_copy(param_set, key);
    }

    // Remove all CRM_meta_* attributes and certain other attributes
    pcmk__xe_remove_matching_attrs(param_set, false, should_filter_for_digest,
                                   NULL);

    // Add timeout back for recurring operation digests
    if (timeout != NULL) {
        crm_xml_add(param_set, key, timeout);
    }
    free(timeout);
    free(key);
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

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
    if ((version == NULL) || (compare_version("3.0.5", version) > 0)) {
        xmlNode *sorted = NULL;
        char *digest = NULL;

        if (sort) {
            xmlNode *sorted = sorted_xml(input, NULL, true);

            input = sorted;
        }

        crm_trace("Using v1 digest algorithm for %s",
                  pcmk__s(version, "unknown feature set"));

        digest = calculate_xml_digest_v1(input);

        pcmk__xml_free(sorted);
        return digest;
    }
    crm_trace("Using v2 digest algorithm for %s", version);
    return pcmk__digest_xml(input, do_filter);
}

// LCOV_EXCL_STOP
// End deprecated API
