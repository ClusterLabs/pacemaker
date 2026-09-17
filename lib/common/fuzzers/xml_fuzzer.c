/*
 * Copyright 2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <libgen.h>                 // dirname()
#include <limits.h>                 // PATH_MAX
#include <stdbool.h>                // bool, false, true
#include <stdint.h>                 // uint8_t
#include <stdlib.h>                 // free(), getenv(), setenv()
#include <string.h>                 // memcpy()
#include <unistd.h>                 // readlink()

#include <glib.h>                   // GString, g_string_sized_new()

#include <crm/common/xml.h>

/* The input is treated as a CIB document and taken through the stages a real
 * configuration goes through: parse, walk, serialize, validate against a
 * schema, then upgrade to the newest schema. Each stage lives in a different
 * source file, so one input covers the whole XML pipeline.
 */

// Schema copy shipped beside the fuzzer binary
#define SCHEMA_SUBDIR "pacemaker-schemas"

// Maximum element depth to walk (a deep document costs more to walk than parse)
#define MAX_DEPTH 8

static bool initialized = false;

/*!
 * \internal
 * \brief Point \c PCMK_schema_directory at the schema copy beside this binary
 *
 * \note The schema cache reads .rng and upgrade .xsl files from disk, so the
 *       validate and upgrade stages return early unless it can find them. An
 *       existing value is left alone, so a caller can override the location.
 */
static void
set_schema_dir(void)
{
    char exe[PATH_MAX] = { '\0', };
    char *schema_dir = NULL;
    ssize_t len = 0;

    if (getenv("PCMK_schema_directory") != NULL) {
        return;
    }

    len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len <= 0) {
        return;
    }
    exe[len] = '\0';

    schema_dir = pcmk__assert_asprintf("%s/%s", dirname(exe), SCHEMA_SUBDIR);
    setenv("PCMK_schema_directory", schema_dir, 0);
    free(schema_dir);
}

/*!
 * \internal
 * \brief Parse an XML attribute's value as each of several types
 *
 * \param[in]     attr       XML attribute
 * \param[in,out] user_data  Ignored
 *
 * \return \c true (to continue iterating)
 *
 * \note This is compatible with \c pcmk__xe_foreach_const_attr().
 * \note The parsed values are discarded. What is under test is turning an
 *       arbitrary attribute string into a score, a number, a boolean, or a
 *       date/time, not whatever any given attribute happens to hold.
 */
static bool
parse_attr(const xmlAttr *attr, void *user_data)
{
    const xmlNode *element = attr->parent;
    const char *name = (const char *) attr->name;
    int score = 0;
    long long ll = 0;
    bool boolean = false;
    crm_time_t *t = NULL;

    pcmk__xe_get_score(element, name, &score, 0);
    pcmk__xe_get_ll(element, name, &ll);
    pcmk__xe_get_bool(element, name, &boolean);

    if (pcmk__xe_get_datetime(element, name, &t) == pcmk_rc_ok) {
        free(t);
    }
    return true;
}

/*!
 * \internal
 * \brief Recursively parse every attribute of every element
 *
 * \param[in] xml    XML element to walk the children of
 * \param[in] depth  Current recursion depth
 */
static void
walk_children(const xmlNode *xml, int depth)
{
    if ((xml == NULL) || (depth >= MAX_DEPTH)) {
        return;
    }

    for (const xmlNode *child = pcmk__xe_first_child(xml, NULL, NULL, NULL);
         child != NULL; child = pcmk__xe_next(child, NULL)) {

        pcmk__xe_foreach_const_attr(child, parse_attr, NULL);
        walk_children(child, depth + 1);
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *ns = NULL;
    xmlNode *xml = NULL;
    xmlNode *upgraded = NULL;
    GString *buffer = NULL;

    // Have at least some data
    if (size < 5) {
        return -1; // Do not add input to testing corpus
    }

    if (!initialized) {
        set_schema_dir();
        pcmk__schema_init();
        initialized = true;
    }

    // pcmk__assert_alloc() zeroes the memory, so the string is terminated
    ns = pcmk__assert_alloc(size + 1, sizeof(char));
    memcpy(ns, data, size);

    xml = pcmk__xml_parse(ns);
    if (xml == NULL) {
        goto done;
    }

    walk_children(xml, 0);

    buffer = g_string_sized_new(1024);
    pcmk__xml_string(xml, pcmk__xml_fmt_pretty|pcmk__xml_fmt_open
                          |pcmk__xml_fmt_children|pcmk__xml_fmt_close
                          |pcmk__xml_fmt_text, buffer, 0);

    pcmk__validate_xml(xml, NULL, NULL);

    /* pcmk__update_schema() replaces the node it is given, so hand it a copy
     * and free whatever comes back. Only a crash along the way is of interest
     * here, so its return code is ignored.
     */
    upgraded = pcmk__xml_copy(NULL, xml);
    if (upgraded != NULL) {
        pcmk__update_schema(&upgraded, NULL, true, false);
    }

done:
    if (buffer != NULL) {
        g_string_free(buffer, TRUE);
    }
    pcmk__xml_free(upgraded);
    pcmk__xml_free(xml);
    free(ns);
    return 0;
}
