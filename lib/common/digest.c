/*
 * Copyright 2015-2024 the Pacemaker project contributors
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
#include <md5.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include "crmcommon_private.h"

#define BEST_EFFORT_STATUS 0

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

    digest = crm_md5sum((const char *) buffer->str);
    crm_log_xml_trace(input, "digest:source");

    g_string_free(buffer, TRUE);
    return digest;
}

/*!
 * \internal
 * \brief Calculate and return v2 digest of XML tree
 *
 * \param[in] source  Root of XML to digest
 * \param[in] filter  Whether to filter certain XML attributes
 *
 * \return Newly allocated string containing digest
 */
static char *
calculate_xml_digest_v2(const xmlNode *source, bool filter)
{
    char *digest = NULL;
    GString *buf = g_string_sized_new(1024);

    crm_trace("Begin digest %s", filter? "filtered" : "");

    pcmk__xml_string(source, (filter? pcmk__xml_fmt_filtered : 0), buf, 0);
    digest = crm_md5sum(buf->str);

    pcmk__if_tracing(
        {
            char *trace_file = crm_strdup_printf("%s/digest-%s",
                                                 pcmk__get_tmpdir(), digest);

            crm_trace("Saving %s.%s.%s to %s",
                      crm_element_value(source, PCMK_XA_ADMIN_EPOCH),
                      crm_element_value(source, PCMK_XA_EPOCH),
                      crm_element_value(source, PCMK_XA_NUM_UPDATES),
                      trace_file);
            save_xml_to_file(source, "digest input", trace_file);
            free(trace_file);
        },
        {}
    );
    crm_trace("End digest");
    g_string_free(buf, TRUE);
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
     * * Switching to v2 is a compatibility nightmare.
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
 * \param[in] input    Root of XML to digest
 * \param[in] filter   Whether to filter certain XML attributes (ignored if
 *                     version is less than or equal to "3.0.5")
 * \param[in] version  CRM feature set version (used to select v1/v2 digest)
 *
 * \return Newly allocated string containing digest
 */
char *
pcmk__digest_xml(const xmlNode *input, bool filter, const char *version)
{
    /* @COMPAT Digests (on-disk or in diffs/patchsets) created <1.1.4 (commit
     * 3032878) were always v1. Removing this affects even full-restart upgrades
     * from old versions.
     *
     * The sorting associated with v1 digest creation accounted for 23% of
     * the CIB manager's CPU usage on the server. v2 drops this.
     *
     * The filtering accounts for an additional 2.5% and we may want to
     * remove it in future.
     */
    if ((version == NULL) || (compare_version("3.0.5", version) > 0)) {
        crm_trace("Using v1 digest algorithm for %s",
                  pcmk__s(version, "unknown feature set"));
        return calculate_xml_digest_v1(input);
    }
    crm_trace("Using v2 digest algorithm for %s", version);
    return calculate_xml_digest_v2(input, filter);
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
    int lpc = 0, len = 0;
    char *digest = NULL;
    unsigned char raw_digest[MD5_DIGEST_SIZE];

    if (buffer == NULL) {
        buffer = "";
    }
    len = strlen(buffer);

    crm_trace("Beginning digest of %d bytes", len);
    digest = malloc(2 * MD5_DIGEST_SIZE + 1);
    if (digest) {
        md5_buffer(buffer, len, raw_digest);
        for (lpc = 0; lpc < MD5_DIGEST_SIZE; lpc++) {
            sprintf(digest + (2 * lpc), "%02x", raw_digest[lpc]);
        }
        digest[(2 * MD5_DIGEST_SIZE)] = 0;
        crm_trace("Digest %s.", digest);

    } else {
        crm_err("Could not create digest");
    }
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
    pcmk__xe_remove_matching_attrs(param_set, should_filter_for_digest, NULL);

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

        calculate_xml_digest_v1(input);

        pcmk__xml_free(sorted);
        return digest;
    }
    crm_trace("Using v2 digest algorithm for %s", version);
    return calculate_xml_digest_v2(input, do_filter);
}

// LCOV_EXCL_STOP
// End deprecated API
