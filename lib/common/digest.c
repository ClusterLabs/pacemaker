/*
 * Copyright 2015-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <md5.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include "crmcommon_private.h"

#define BEST_EFFORT_STATUS 0

/*!
 * \brief Dump XML in a format used with v1 digests
 *
 * \param[in] an_xml_node Root of XML to dump
 *
 * \return Newly allocated buffer containing dumped XML
 */
static char *
dump_xml_for_digest(xmlNode * an_xml_node)
{
    char *buffer = NULL;
    int offset = 0, max = 0;

    /* for compatibility with the old result which is used for v1 digests */
    pcmk__buffer_add_char(&buffer, &offset, &max, ' ');
    pcmk__xml2text(an_xml_node, 0, &buffer, &offset, &max, 0);
    pcmk__buffer_add_char(&buffer, &offset, &max, '\n');

    return buffer;
}

/*!
 * \brief Calculate and return v1 digest of XML tree
 *
 * \param[in] input Root of XML to digest
 * \param[in] sort Whether to sort the XML before calculating digest
 * \param[in] ignored Not used
 *
 * \return Newly allocated string containing digest
 * \note Example return value: "c048eae664dba840e1d2060f00299e9d"
 */
static char *
calculate_xml_digest_v1(xmlNode * input, gboolean sort, gboolean ignored)
{
    char *digest = NULL;
    char *buffer = NULL;
    xmlNode *copy = NULL;

    if (sort) {
        crm_trace("Sorting xml...");
        copy = sorted_xml(input, NULL, TRUE);
        crm_trace("Done");
        input = copy;
    }

    buffer = dump_xml_for_digest(input);
    CRM_CHECK(buffer != NULL && strlen(buffer) > 0, free_xml(copy);
              free(buffer);
              return NULL);

    digest = crm_md5sum(buffer);
    crm_log_xml_trace(input, "digest:source");

    free(buffer);
    free_xml(copy);
    return digest;
}

/*!
 * \brief Calculate and return v2 digest of XML tree
 *
 * \param[in] source Root of XML to digest
 * \param[in] do_filter Whether to filter certain XML attributes
 *
 * \return Newly allocated string containing digest
 */
static char *
calculate_xml_digest_v2(xmlNode * source, gboolean do_filter)
{
    char *digest = NULL;
    char *buffer = NULL;
    int offset, max;

    static struct qb_log_callsite *digest_cs = NULL;

    crm_trace("Begin digest %s", do_filter?"filtered":"");
    pcmk__xml2text(source, (do_filter? xml_log_option_filtered : 0), &buffer,
                   &offset, &max, 0);

    CRM_ASSERT(buffer != NULL);
    digest = crm_md5sum(buffer);

    if (digest_cs == NULL) {
        digest_cs = qb_log_callsite_get(__func__, __FILE__, "cib-digest", LOG_TRACE, __LINE__,
                                        crm_trace_nonlog);
    }
    if (digest_cs && digest_cs->targets) {
        char *trace_file = crm_strdup_printf("%s/digest-%s",
                                             pcmk__get_tmpdir(), digest);

        crm_trace("Saving %s.%s.%s to %s",
                  crm_element_value(source, XML_ATTR_GENERATION_ADMIN),
                  crm_element_value(source, XML_ATTR_GENERATION),
                  crm_element_value(source, XML_ATTR_NUMUPDATES), trace_file);
        save_xml_to_file(source, "digest input", trace_file);
        free(trace_file);
    }

    free(buffer);
    crm_trace("End digest");
    return digest;
}

/*!
 * \brief Calculate and return digest of XML tree, suitable for storing on disk
 *
 * \param[in] input Root of XML to digest
 *
 * \return Newly allocated string containing digest
 */
char *
calculate_on_disk_digest(xmlNode * input)
{
    /* Always use the v1 format for on-disk digests
     * a) it's a compatibility nightmare
     * b) we only use this once at startup, all other
     *    invocations are in a separate child process
     */
    return calculate_xml_digest_v1(input, FALSE, FALSE);
}

/*!
 * \brief Calculate and return digest of XML operation
 *
 * \param[in] input Root of XML to digest
 * \param[in] version Not used
 *
 * \return Newly allocated string containing digest
 */
char *
calculate_operation_digest(xmlNode *input, const char *version)
{
    /* We still need the sorting for operation digests */
    return calculate_xml_digest_v1(input, TRUE, FALSE);
}

/*!
 * \brief Calculate and return digest of XML tree
 *
 * \param[in] input Root of XML to digest
 * \param[in] sort Whether to sort XML before calculating digest
 * \param[in] do_filter Whether to filter certain XML attributes
 * \param[in] version CRM feature set version (used to select v1/v2 digest)
 *
 * \return Newly allocated string containing digest
 */
char *
calculate_xml_versioned_digest(xmlNode * input, gboolean sort, gboolean do_filter,
                               const char *version)
{
    /*
     * @COMPAT digests (on-disk or in diffs/patchsets) created <1.1.4;
     * removing this affects even full-restart upgrades from old versions
     *
     * The sorting associated with v1 digest creation accounted for 23% of
     * the CIB manager's CPU usage on the server. v2 drops this.
     *
     * The filtering accounts for an additional 2.5% and we may want to
     * remove it in future.
     *
     * v2 also uses the xmlBuffer contents directly to avoid additional copying
     */
    if (version == NULL || compare_version("3.0.5", version) > 0) {
        crm_trace("Using v1 digest algorithm for %s",
                  pcmk__s(version, "unknown feature set"));
        return calculate_xml_digest_v1(input, sort, do_filter);
    }
    crm_trace("Using v2 digest algorithm for %s",
              pcmk__s(version, "unknown feature set"));
    return calculate_xml_digest_v2(input, do_filter);
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
        calculated = calculate_on_disk_digest(input);
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
        XML_ATTR_ORIGIN,
        XML_CIB_ATTR_WRITTEN,
        XML_ATTR_UPDATE_ORIG,
        XML_ATTR_UPDATE_CLIENT,
        XML_ATTR_UPDATE_USER,
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
