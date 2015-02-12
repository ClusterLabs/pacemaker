/*
 * Copyright (C) 2015 Andrew Beekhof <andrew@beekhof.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#define BEST_EFFORT_STATUS 0

static char *
dump_xml_for_digest(xmlNode * an_xml_node)
{
    char *buffer = NULL;
    int offset = 0, max = 0;

    /* for compatability with the old result which is used for v1 digests */
    crm_buffer_add_char(&buffer, &offset, &max, ' ');
    crm_xml_dump(an_xml_node, 0, &buffer, &offset, &max, 0);
    crm_buffer_add_char(&buffer, &offset, &max, '\n');

    return buffer;
}

/* "c048eae664dba840e1d2060f00299e9d" */
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

static char *
calculate_xml_digest_v2(xmlNode * source, gboolean do_filter)
{
    char *digest = NULL;
    char *buffer = NULL;
    int offset, max;

    static struct qb_log_callsite *digest_cs = NULL;

    crm_trace("Begin digest %s", do_filter?"filtered":"");
    if (do_filter && BEST_EFFORT_STATUS) {
        /* Exclude the status calculation from the digest
         *
         * This doesn't mean it wont be sync'd, we just wont be paranoid
         * about it being an _exact_ copy
         *
         * We don't need it to be exact, since we throw it away and regenerate
         * from our peers whenever a new DC is elected anyway
         *
         * Importantly, this reduces the amount of XML to copy+export as
         * well as the amount of data for MD5 needs to operate on
         */

    } else {
        crm_xml_dump(source, do_filter ? xml_log_option_filtered : 0, &buffer, &offset, &max, 0);
    }

    CRM_ASSERT(buffer != NULL);
    digest = crm_md5sum(buffer);

    if (digest_cs == NULL) {
        digest_cs = qb_log_callsite_get(__func__, __FILE__, "cib-digest", LOG_TRACE, __LINE__,
                                        crm_trace_nonlog);
    }
    if (digest_cs && digest_cs->targets) {
        char *trace_file = crm_concat("/tmp/digest", digest, '-');

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

char *
calculate_on_disk_digest(xmlNode * input)
{
    /* Always use the v1 format for on-disk digests
     * a) its a compatability nightmare
     * b) we only use this once at startup, all other
     *    invocations are in a separate child process
     */
    return calculate_xml_digest_v1(input, FALSE, FALSE);
}

char *
calculate_operation_digest(xmlNode * input, const char *version)
{
    /* We still need the sorting for parameter digests */
    return calculate_xml_digest_v1(input, TRUE, FALSE);
}

char *
calculate_xml_versioned_digest(xmlNode * input, gboolean sort, gboolean do_filter,
                               const char *version)
{
    /*
     * The sorting associated with v1 digest creation accounted for 23% of
     * the CIB's CPU usage on the server. v2 drops this.
     *
     * The filtering accounts for an additional 2.5% and we may want to
     * remove it in future.
     *
     * v2 also uses the xmlBuffer contents directly to avoid additional copying
     */
    if (version == NULL || compare_version("3.0.5", version) > 0) {
        crm_trace("Using v1 digest algorithm for %s", crm_str(version));
        return calculate_xml_digest_v1(input, sort, do_filter);
    }
    crm_trace("Using v2 digest algorithm for %s", crm_str(version));
    return calculate_xml_digest_v2(input, do_filter);
}
