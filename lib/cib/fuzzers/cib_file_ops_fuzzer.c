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
#include <stdlib.h>                 // free(), getenv(), mkstemp(), setenv()
#include <string.h>                 // memcpy()
#include <unistd.h>                 // close(), readlink(), unlink(), write()

#include <crm/cib.h>
#include <crm/cib/internal.h>
#include <crm/common/xml.h>

/*
 * CIB file client operations fuzzer
 *
 * Threat model: a Pacemaker cluster applies CIB operations whose content is
 * not trusted (a cibadmin invocation by a local admin, or a request relayed
 * from a peer). The op processors in libcib (cib_ops.c, cib_utils.c) parse
 * XPath sections, locate target elements, apply arbitrary XML call data, and
 * enforce ACLs on the result. A memory-safety violation or a permission-check
 * bypass reachable here is attacker-relevant.
 *
 * The input is an XML envelope:
 *
 *     <cib-fuzz op="cib_modify" section="//cib/..." user="alice" callop="17">
 *       <cib-input> current CIB, loaded through the real disk path </cib-input>
 *       <request-data> operation call data, fully attacker-controlled </request-data>
 *     </cib-fuzz>
 *
 * The current CIB is written to a temporary file and loaded by the file
 * client's own sign-on path (parse plus schema validation), then a single
 * request is processed via cib_internal_op(), the dispatch entry point the
 * command-line tools use. This exercises cib_file.c, cib_ops.c, and
 * cib_utils.c, along with the ACL filtering, patchset generation, and version
 * checks that wrap every operation. One input covers one full operation, so
 * corpus entries built from real CIB files reach the op logic immediately.
 */

// Envelope element names
#define ENVELOPE_CIB        "cib-input"
#define ENVELOPE_DATA       "request-data"

// Bounds on a single input (a CIB plus one request)
#define MAX_INPUT_SIZE      (1024 * 1024)
#define MIN_INPUT_SIZE      20

static bool initialized = false;

/*!
 * \internal
 * \brief Point \c PCMK_schema_directory at the schema copy beside this binary
 *
 * \note The schema cache reads .rng and upgrade .xsl files from disk, so the
 *       sign-on validation stage returns early unless it can find them. An
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

    schema_dir = pcmk__assert_asprintf("%s/pacemaker-schemas", dirname(exe));
    setenv("PCMK_schema_directory", schema_dir, 0);
    free(schema_dir);
}

/*!
 * \internal
 * \brief Write the current CIB from the envelope to a fresh temporary file
 *
 * \param[in] cib  Current CIB XML from the envelope
 *
 * \return Newly allocated filename (owned by the caller), or NULL on error
 */
static char *
write_temp_cib(const xmlNode *cib)
{
    const char *tmpdir = getenv("TMPDIR");
    char *template = NULL;
    int fd = -1;

    if ((tmpdir == NULL) || (tmpdir[0] == '\0')) {
        tmpdir = "/tmp";
    }
    template = pcmk__assert_asprintf("%s/cib-fuzz-XXXXXX", tmpdir);

    fd = mkstemp(template);
    if (fd < 0) {
        free(template);
        return NULL;
    }
    close(fd);

    if (pcmk__xml_write_file(cib, template, false) != pcmk_rc_ok) {
        unlink(template);
        free(template);
        return NULL;
    }
    return template;    // Ownership transferred to the caller
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    xmlNode *envelope = NULL;
    const xmlNode *cib = NULL;
    const xmlNode *request_data = NULL;
    const char *op = NULL;
    const char *section = NULL;
    const char *user = NULL;
    char *ns = NULL;
    char *filename = NULL;
    int call_options = 0;

    // Have at least enough data for a minimal envelope
    if ((size < MIN_INPUT_SIZE) || (size > MAX_INPUT_SIZE)) {
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
    envelope = pcmk__xml_parse(ns);
    free(ns);
    if (envelope == NULL) {
        return 0;
    }

    cib = pcmk__xe_first_child(envelope, ENVELOPE_CIB, NULL, NULL);
    if (cib == NULL) {
        pcmk__xml_free(envelope);
        return 0;
    }

    // Request parameters; cib__get_operation() rejects unknown values
    op = pcmk__xe_get(envelope, "op");
    if (op == NULL) {
        op = PCMK__CIB_REQUEST_QUERY;
    }
    section = pcmk__xe_get(envelope, "section");
    user = pcmk__xe_get(envelope, "user");
    pcmk__xe_get_int(envelope, "callop", &call_options);
    request_data = pcmk__xe_first_child(envelope, ENVELOPE_DATA, NULL, NULL);

    filename = write_temp_cib(cib);
    if (filename != NULL) {
        cib_t *cib_client = cib_file_new(filename);

        if (cib_client != NULL) {
            if (cib_client->cmds->signon(cib_client, "cib_file_ops_fuzzer",
                                         cib_command) == pcmk_ok) {
                xmlNode *output = NULL;

                cib_internal_op(cib_client, op, NULL, section,
                                (xmlNode *) request_data, &output,
                                call_options, user);

                pcmk__xml_free(output);
                cib_client->cmds->signoff(cib_client);
            }
            cib_delete(cib_client);
        }
        unlink(filename);
        free(filename);
    }

    pcmk__xml_free(envelope);
    return 0;
}
