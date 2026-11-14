/*
 * Copyright 2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <fuzzers_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_FUZZERS_INTERNAL__H
#define PCMK__CRM_COMMON_FUZZERS_INTERNAL__H

#include <libgen.h>                         // dirname()
#include <limits.h>                         // PATH_MAX
#include <stdlib.h>                         // free(), getenv(), setenv()
#include <unistd.h>                         // readlink()

#include <crm/common/strings_internal.h>    // pcmk__assert_asprintf

#ifdef __cplusplus
extern "C" {
#endif

/* Helper code shared by the libFuzzer targets (built out-of-tree by OSS-Fuzz) */

// Schema copy shipped beside a fuzzer binary
#define SCHEMA_SUBDIR "pacemaker-schemas"

/*!
 * \internal
 * \brief Point \c PCMK_schema_directory at the schema copy beside this binary
 *
 * \note The schema cache reads .rng and upgrade .xsl files from disk, so the
 *       schema validation stage returns early unless it can find them. An
 *       existing value is left alone, so a caller can override the location.
 */
static inline void
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

    schema_dir = pcmk__assert_asprintf("%s/" SCHEMA_SUBDIR, dirname(exe));
    setenv("PCMK_schema_directory", schema_dir, 0);
    free(schema_dir);
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_FUZZERS_INTERNAL__H