/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdarg.h>

#include <libxml/relaxng.h>
#include <libxslt/xslt.h>
#include <libxslt/transform.h>
#include <libxslt/security.h>
#include <libxslt/xsltutils.h>

#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>  /* PCMK__XML_LOG_BASE */

#include "crmcommon_private.h"

#define SCHEMA_ZERO { .v = { 0, 0 } }

#define schema_strdup_printf(prefix, version, suffix) \
    crm_strdup_printf(prefix "%u.%u" suffix, (version).v[0], (version).v[1])

typedef struct {
    xmlRelaxNGPtr rng;
    xmlRelaxNGValidCtxtPtr valid;
    xmlRelaxNGParserCtxtPtr parser;
} relaxng_ctx_cache_t;

static GList *known_schemas = NULL;
static bool silent_logging = FALSE;

static void G_GNUC_PRINTF(2, 3)
xml_log(int priority, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (silent_logging == FALSE) {
        /* XXX should not this enable dechunking as well? */
        PCMK__XML_LOG_BASE(priority, FALSE, 0, NULL, fmt, ap);
    }
    va_end(ap);
}

static int
xml_latest_schema_index(void)
{
    /* This function assumes that crm_schema_init() has been called beforehand,
     * so we have at least three schemas (one real schema, the "pacemaker-next"
     * schema, and the "none" schema).
     *
     * @COMPAT: pacemaker-next is deprecated since 2.1.5.
     * Update this when we drop that schema.
     */
    return g_list_length(known_schemas) - 3;
}

/*!
 * \internal
 * \brief Return the schema entry of the highest-versioned schema
 *
 * \return Schema entry of highest-versioned schema (or NULL on error)
 */
static GList *
get_highest_schema(void)
{
    /* The highest numerically versioned schema is the one before pacemaker-next
     *
     * @COMPAT pacemaker-next is deprecated since 2.1.5
     */
    GList *entry = pcmk__get_schema("pacemaker-next");

    CRM_ASSERT((entry != NULL) && (entry->prev != NULL));
    return entry->prev;
}

/*!
 * \internal
 * \brief Return the name of the highest-versioned schema
 *
 * \return Name of highest-versioned schema (or NULL on error)
 */
const char *
pcmk__highest_schema_name(void)
{
    GList *entry = get_highest_schema();

    return ((pcmk__schema_t *)(entry->data))->name;
}

/*!
 * \internal
 * \brief Find first entry of highest major schema version series
 *
 * \return Schema entry of first schema with highest major version
 */
GList *
pcmk__find_x_0_schema(void)
{
#if defined(PCMK__UNIT_TESTING)
    /* If we're unit testing, this can't be static because it'll stick
     * around from one test run to the next. It needs to be cleared out
     * every time.
     */
    GList *x_0_entry = NULL;
#else
    static GList *x_0_entry = NULL;
#endif

    pcmk__schema_t *highest_schema = NULL;

    if (x_0_entry != NULL) {
        return x_0_entry;
    }
    x_0_entry = get_highest_schema();
    highest_schema = x_0_entry->data;

    for (GList *iter = x_0_entry->prev; iter != NULL; iter = iter->prev) {
        pcmk__schema_t *schema = iter->data;

        /* We've found a schema in an older major version series.  Return
         * the index of the first one in the same major version series as
         * the highest schema.
         */
        if (schema->version.v[0] < highest_schema->version.v[0]) {
            x_0_entry = iter->next;
            break;
        }

        /* We're out of list to examine.  This probably means there was only
         * one major version series, so return the first schema entry.
         */
        if (iter->prev == NULL) {
            x_0_entry = known_schemas->data;
            break;
        }
    }
    return x_0_entry;
}

static inline bool
version_from_filename(const char *filename, pcmk__schema_version_t *version)
{
    if (pcmk__ends_with(filename, ".rng")) {
        return sscanf(filename, "pacemaker-%hhu.%hhu.rng", &(version->v[0]), &(version->v[1])) == 2;
    } else {
        return sscanf(filename, "pacemaker-%hhu.%hhu", &(version->v[0]), &(version->v[1])) == 2;
    }
}

static int
schema_filter(const struct dirent *a)
{
    int rc = 0;
    pcmk__schema_version_t version = SCHEMA_ZERO;

    if (strstr(a->d_name, "pacemaker-") != a->d_name) {
        /* crm_trace("%s - wrong prefix", a->d_name); */

    } else if (!pcmk__ends_with_ext(a->d_name, ".rng")) {
        /* crm_trace("%s - wrong suffix", a->d_name); */

    } else if (!version_from_filename(a->d_name, &version)) {
        /* crm_trace("%s - wrong format", a->d_name); */

    } else {
        /* crm_debug("%s - candidate", a->d_name); */
        rc = 1;
    }

    return rc;
}

static int
schema_cmp(pcmk__schema_version_t a_version, pcmk__schema_version_t b_version)
{
    for (int i = 0; i < 2; ++i) {
        if (a_version.v[i] < b_version.v[i]) {
            return -1;
        } else if (a_version.v[i] > b_version.v[i]) {
            return 1;
        }
    }
    return 0;
}

static int
schema_cmp_directory(const struct dirent **a, const struct dirent **b)
{
    pcmk__schema_version_t a_version = SCHEMA_ZERO;
    pcmk__schema_version_t b_version = SCHEMA_ZERO;

    if (!version_from_filename(a[0]->d_name, &a_version)
        || !version_from_filename(b[0]->d_name, &b_version)) {
        // Shouldn't be possible, but makes static analysis happy
        return 0;
    }

    return schema_cmp(a_version, b_version);
}

/*!
 * \internal
 * \brief Add given schema + auxiliary data to internal bookkeeping.
 *
 * \note When providing \p version, should not be called directly but
 *       through \c add_schema_by_version.
 */
static void
add_schema(enum pcmk__schema_validator validator, const pcmk__schema_version_t *version,
           const char *name, const char *transform,
           const char *transform_enter, bool transform_onleave)
{
    pcmk__schema_t *schema = NULL;

    schema = pcmk__assert_alloc(1, sizeof(pcmk__schema_t));

    schema->validator = validator;
    schema->version.v[0] = version->v[0];
    schema->version.v[1] = version->v[1];
    schema->transform_onleave = transform_onleave;
    // schema->schema_index is set after all schemas are loaded and sorted

    if (version->v[0] || version->v[1]) {
        schema->name = schema_strdup_printf("pacemaker-", *version, "");
    } else {
        schema->name = pcmk__str_copy(name);
    }

    if (transform) {
        schema->transform = pcmk__str_copy(transform);
    }

    if (transform_enter) {
        schema->transform_enter = pcmk__str_copy(transform_enter);
    }

    known_schemas = g_list_prepend(known_schemas, schema);
}

/*!
 * \internal
 * \brief Add version-specified schema + auxiliary data to internal bookkeeping.
 * \return Standard Pacemaker return value (the only possible values are
 * \c ENOENT when no upgrade schema is associated, or \c pcmk_rc_ok otherwise.
 *
 * \note There's no reliance on the particular order of schemas entering here.
 *
 * \par A bit of theory
 * We track 3 XSLT stylesheets that differ per usage:
 * - "upgrade":
 *   . sparsely spread over the sequence of all available schemas,
 *     as they are only relevant when major version of the schema
 *     is getting bumped -- in that case, it MUST be set
 *   . name convention:  upgrade-X.Y.xsl
 * - "upgrade-enter":
 *   . may only accompany "upgrade" occurrence, but doesn't need to
 *     be present anytime such one is, i.e., it MAY not be set when
 *     "upgrade" is
 *   . name convention:  upgrade-X.Y-enter.xsl,
 *     when not present: upgrade-enter.xsl
 * - "upgrade-leave":
 *   . like "upgrade-enter", but SHOULD be present whenever
 *     "upgrade-enter" is (and vice versa, but that's only
 *     to prevent confusion based on observing the files,
 *     it would get ignored regardless)
 *   . name convention:  (see "upgrade-enter")
 */
static int
add_schema_by_version(const pcmk__schema_version_t *version, bool transform_expected)
{
    bool transform_onleave = FALSE;
    int rc = pcmk_rc_ok;
    struct stat s;
    char *xslt = NULL,
         *transform_upgrade = NULL,
         *transform_enter = NULL;

    /* prologue for further transform_expected handling */
    if (transform_expected) {
        /* check if there's suitable "upgrade" stylesheet */
        transform_upgrade = schema_strdup_printf("upgrade-", *version, );
        xslt = pcmk__xml_artefact_path(pcmk__xml_artefact_ns_legacy_xslt,
                                       transform_upgrade);
    }

    if (!transform_expected) {
        /* jump directly to the end */

    } else if (stat(xslt, &s) == 0) {
        /* perhaps there's also a targeted "upgrade-enter" stylesheet */
        transform_enter = schema_strdup_printf("upgrade-", *version, "-enter");
        free(xslt);
        xslt = pcmk__xml_artefact_path(pcmk__xml_artefact_ns_legacy_xslt,
                                       transform_enter);
        if (stat(xslt, &s) != 0) {
            /* or initially, at least a generic one */
            crm_debug("Upgrade-enter transform %s.xsl not found", xslt);
            free(xslt);
            free(transform_enter);
            transform_enter = strdup("upgrade-enter");
            xslt = pcmk__xml_artefact_path(pcmk__xml_artefact_ns_legacy_xslt,
                                           transform_enter);
            if (stat(xslt, &s) != 0) {
                crm_debug("Upgrade-enter transform %s.xsl not found, either", xslt);
                free(xslt);
                xslt = NULL;
            }
        }
        /* xslt contains full path to "upgrade-enter" stylesheet */
        if (xslt != NULL) {
            /* then there should be "upgrade-leave" counterpart (enter->leave) */
            memcpy(strrchr(xslt, '-') + 1, "leave", sizeof("leave") - 1);
            transform_onleave = (stat(xslt, &s) == 0);
            free(xslt);
        } else {
            free(transform_enter);
            transform_enter = NULL;
        }

    } else {
        crm_err("Upgrade transform %s not found", xslt);
        free(xslt);
        free(transform_upgrade);
        transform_upgrade = NULL;
        rc = ENOENT;
    }

    add_schema(pcmk__schema_validator_rng, version, NULL,
               transform_upgrade, transform_enter, transform_onleave);

    free(transform_upgrade);
    free(transform_enter);

    return rc;
}

static void
wrap_libxslt(bool finalize)
{
    static xsltSecurityPrefsPtr secprefs;
    int ret = 0;

    /* security framework preferences */
    if (!finalize) {
        CRM_ASSERT(secprefs == NULL);
        secprefs = xsltNewSecurityPrefs();
        ret = xsltSetSecurityPrefs(secprefs, XSLT_SECPREF_WRITE_FILE,
                                   xsltSecurityForbid)
              | xsltSetSecurityPrefs(secprefs, XSLT_SECPREF_CREATE_DIRECTORY,
                                     xsltSecurityForbid)
              | xsltSetSecurityPrefs(secprefs, XSLT_SECPREF_READ_NETWORK,
                                     xsltSecurityForbid)
              | xsltSetSecurityPrefs(secprefs, XSLT_SECPREF_WRITE_NETWORK,
                                     xsltSecurityForbid);
        if (ret != 0) {
            return;
        }
    } else {
        xsltFreeSecurityPrefs(secprefs);
        secprefs = NULL;
    }

    /* cleanup only */
    if (finalize) {
        xsltCleanupGlobals();
    }
}

void
pcmk__load_schemas_from_dir(const char *dir)
{
    int lpc, max;
    struct dirent **namelist = NULL;

    max = scandir(dir, &namelist, schema_filter, schema_cmp_directory);
    if (max < 0) {
        crm_warn("Could not load schemas from %s: %s", dir, strerror(errno));
        return;
    }

    for (lpc = 0; lpc < max; lpc++) {
        bool transform_expected = false;
        pcmk__schema_version_t version = SCHEMA_ZERO;

        if (!version_from_filename(namelist[lpc]->d_name, &version)) {
            // Shouldn't be possible, but makes static analysis happy
            crm_warn("Skipping schema '%s': could not parse version",
                     namelist[lpc]->d_name);
            continue;
        }
        if ((lpc + 1) < max) {
            pcmk__schema_version_t next_version = SCHEMA_ZERO;

            if (version_from_filename(namelist[lpc+1]->d_name, &next_version)
                    && (version.v[0] < next_version.v[0])) {
                transform_expected = true;
            }
        }

        if (add_schema_by_version(&version, transform_expected) != pcmk_rc_ok) {
            break;
        }
    }

    for (lpc = 0; lpc < max; lpc++) {
        free(namelist[lpc]);
    }

    free(namelist);
}

static gint
schema_sort_GCompareFunc(gconstpointer a, gconstpointer b)
{
    const pcmk__schema_t *schema_a = a;
    const pcmk__schema_t *schema_b = b;

    if (pcmk__str_eq(schema_a->name, "pacemaker-next", pcmk__str_none)) {
        if (pcmk__str_eq(schema_b->name, PCMK_VALUE_NONE, pcmk__str_none)) {
            return -1;
        } else {
            return 1;
        }
    } else if (pcmk__str_eq(schema_a->name, PCMK_VALUE_NONE, pcmk__str_none)) {
        return 1;
    } else if (pcmk__str_eq(schema_b->name, "pacemaker-next", pcmk__str_none)) {
        return -1;
    } else {
        return schema_cmp(schema_a->version, schema_b->version);
    }
}

/*!
 * \internal
 * \brief Sort the list of known schemas such that all pacemaker-X.Y are in
 *        version order, then pacemaker-next, then none
 *
 * This function should be called whenever additional schemas are loaded using
 * pcmk__load_schemas_from_dir(), after the initial sets in crm_schema_init().
 */
void
pcmk__sort_schemas(void)
{
    known_schemas = g_list_sort(known_schemas, schema_sort_GCompareFunc);
}

/*!
 * \internal
 * \brief Load pacemaker schemas into cache
 *
 * \note This currently also serves as an entry point for the
 *       generic initialization of the libxslt library.
 */
void
crm_schema_init(void)
{
    const char *remote_schema_dir = pcmk__remote_schema_dir();
    char *base = pcmk__xml_artefact_root(pcmk__xml_artefact_ns_legacy_rng);
    const pcmk__schema_version_t zero = SCHEMA_ZERO;
    int schema_index = 0;

    wrap_libxslt(false);

    pcmk__load_schemas_from_dir(base);
    pcmk__load_schemas_from_dir(remote_schema_dir);

    // @COMPAT: Deprecated since 2.1.5
    add_schema(pcmk__schema_validator_rng, &zero, "pacemaker-next",
               NULL, NULL, FALSE);

    add_schema(pcmk__schema_validator_none, &zero, PCMK_VALUE_NONE,
               NULL, NULL, FALSE);

    /* add_schema() prepends items to the list, so in the simple case, this just
     * reverses the list. However if there were any remote schemas, sorting is
     * necessary.
     */
    pcmk__sort_schemas();

    // Now set the schema indexes and log the final result
    for (GList *iter = known_schemas; iter != NULL; iter = iter->next) {
        pcmk__schema_t *schema = iter->data;

        if (schema->transform == NULL) {
            crm_debug("Loaded schema %d: %s", schema_index, schema->name);
        } else {
            crm_debug("Loaded schema %d: %s (upgrades with %s.xsl)",
                      schema_index, schema->name, schema->transform);
        }
        schema->schema_index = schema_index++;
    }
}

static gboolean
validate_with_relaxng(xmlDocPtr doc, xmlRelaxNGValidityErrorFunc error_handler, void *error_handler_context, const char *relaxng_file,
                      relaxng_ctx_cache_t **cached_ctx)
{
    int rc = 0;
    gboolean valid = TRUE;
    relaxng_ctx_cache_t *ctx = NULL;

    CRM_CHECK(doc != NULL, return FALSE);
    CRM_CHECK(relaxng_file != NULL, return FALSE);

    if (cached_ctx && *cached_ctx) {
        ctx = *cached_ctx;

    } else {
        crm_debug("Creating RNG parser context");
        ctx = pcmk__assert_alloc(1, sizeof(relaxng_ctx_cache_t));

        ctx->parser = xmlRelaxNGNewParserCtxt(relaxng_file);
        CRM_CHECK(ctx->parser != NULL, goto cleanup);

        if (error_handler) {
            xmlRelaxNGSetParserErrors(ctx->parser,
                                      (xmlRelaxNGValidityErrorFunc) error_handler,
                                      (xmlRelaxNGValidityWarningFunc) error_handler,
                                      error_handler_context);
        } else {
            xmlRelaxNGSetParserErrors(ctx->parser,
                                      (xmlRelaxNGValidityErrorFunc) fprintf,
                                      (xmlRelaxNGValidityWarningFunc) fprintf,
                                      stderr);
        }

        ctx->rng = xmlRelaxNGParse(ctx->parser);
        CRM_CHECK(ctx->rng != NULL,
                  crm_err("Could not find/parse %s", relaxng_file);
                  goto cleanup);

        ctx->valid = xmlRelaxNGNewValidCtxt(ctx->rng);
        CRM_CHECK(ctx->valid != NULL, goto cleanup);

        if (error_handler) {
            xmlRelaxNGSetValidErrors(ctx->valid,
                                     (xmlRelaxNGValidityErrorFunc) error_handler,
                                     (xmlRelaxNGValidityWarningFunc) error_handler,
                                     error_handler_context);
        } else {
            xmlRelaxNGSetValidErrors(ctx->valid,
                                     (xmlRelaxNGValidityErrorFunc) fprintf,
                                     (xmlRelaxNGValidityWarningFunc) fprintf,
                                     stderr);
        }
    }

    rc = xmlRelaxNGValidateDoc(ctx->valid, doc);
    if (rc > 0) {
        valid = FALSE;

    } else if (rc < 0) {
        crm_err("Internal libxml error during validation");
    }

  cleanup:

    if (cached_ctx) {
        *cached_ctx = ctx;

    } else {
        if (ctx->parser != NULL) {
            xmlRelaxNGFreeParserCtxt(ctx->parser);
        }
        if (ctx->valid != NULL) {
            xmlRelaxNGFreeValidCtxt(ctx->valid);
        }
        if (ctx->rng != NULL) {
            xmlRelaxNGFree(ctx->rng);
        }
        free(ctx);
    }

    return valid;
}

static void
free_schema(gpointer data)
{
    pcmk__schema_t *schema = data;
    relaxng_ctx_cache_t *ctx = NULL;

    switch (schema->validator) {
        case pcmk__schema_validator_none: // not cached
            break;

        case pcmk__schema_validator_rng: // cached
            ctx = (relaxng_ctx_cache_t *) schema->cache;
            if (ctx == NULL) {
                break;
            }

            if (ctx->parser != NULL) {
                xmlRelaxNGFreeParserCtxt(ctx->parser);
            }

            if (ctx->valid != NULL) {
                xmlRelaxNGFreeValidCtxt(ctx->valid);
            }

            if (ctx->rng != NULL) {
                xmlRelaxNGFree(ctx->rng);
            }

            free(ctx);
            schema->cache = NULL;
            break;
    }

    free(schema->name);
    free(schema->transform);
    free(schema->transform_enter);
}

/*!
 * \internal
 * \brief Clean up global memory associated with XML schemas
 */
void
crm_schema_cleanup(void)
{
    g_list_free_full(known_schemas, free_schema);
    known_schemas = NULL;

    wrap_libxslt(true);
}

/*!
 * \internal
 * \brief Get schema list entry corresponding to a schema name
 *
 * \param[in] name  Name of schema to get
 *
 * \return Schema list entry corresponding to \p name, or NULL if unknown
 */
GList *
pcmk__get_schema(const char *name)
{
    if (name == NULL) {
        name = PCMK_VALUE_NONE;
    }
    for (GList *iter = known_schemas; iter != NULL; iter = iter->next) {
        pcmk__schema_t *schema = iter->data;

        if (pcmk__str_eq(name, schema->name, pcmk__str_casei)) {
            return iter;
        }
    }
    return NULL;
}

/*!
 * \internal
 * \brief Compare two schema version numbers given the schema names
 *
 * \param[in] schema1  Name of first schema to compare
 * \param[in] schema2  Name of second schema to compare
 *
 * \return Standard comparison result (negative integer if \p schema1 has the
 *         lower version number, positive integer if \p schema1 has the higher
 *         version number, of 0 if the version numbers are equal)
 */
int
pcmk__cmp_schemas_by_name(const char *schema1_name, const char *schema2_name)
{
    GList *entry1 = pcmk__get_schema(schema1_name);
    GList *entry2 = pcmk__get_schema(schema2_name);

    if (entry1 == NULL) {
        return (entry2 == NULL)? 0 : -1;

    } else if (entry2 == NULL) {
        return 1;

    } else {
        pcmk__schema_t *schema1 = entry1->data;
        pcmk__schema_t *schema2 = entry2->data;

        return schema1->schema_index - schema2->schema_index;
    }
}

static gboolean
validate_with(xmlNode *xml, pcmk__schema_t *schema, xmlRelaxNGValidityErrorFunc error_handler, void* error_handler_context)
{
    gboolean valid = FALSE;
    char *file = NULL;
    relaxng_ctx_cache_t **cache = NULL;

    if (schema == NULL) {
        return FALSE;
    }

    if (schema->validator == pcmk__schema_validator_none) {
        return TRUE;
    }

    if (pcmk__str_eq(schema->name, "pacemaker-next", pcmk__str_none)) {
        crm_warn("The pacemaker-next schema is deprecated and will be removed "
                 "in a future release.");
    }

    file = pcmk__xml_artefact_path(pcmk__xml_artefact_ns_legacy_rng,
                                   schema->name);

    crm_trace("Validating with %s (type=%d)",
              pcmk__s(file, "missing schema"), schema->validator);
    switch (schema->validator) {
        case pcmk__schema_validator_rng:
            cache = (relaxng_ctx_cache_t **) &(schema->cache);
            valid = validate_with_relaxng(xml->doc, error_handler, error_handler_context, file, cache);
            break;
        default:
            crm_err("Unknown validator type: %d", schema->validator);
            break;
    }

    free(file);
    return valid;
}

static bool
validate_with_silent(xmlNode *xml, pcmk__schema_t *schema)
{
    bool rc, sl_backup = silent_logging;
    silent_logging = TRUE;
    rc = validate_with(xml, schema, (xmlRelaxNGValidityErrorFunc) xml_log, GUINT_TO_POINTER(LOG_ERR));
    silent_logging = sl_backup;
    return rc;
}

static void
dump_file(const char *filename)
{

    FILE *fp = NULL;
    int ch, line = 0;

    CRM_CHECK(filename != NULL, return);

    fp = fopen(filename, "r");
    if (fp == NULL) {
        crm_perror(LOG_ERR, "Could not open %s for reading", filename);
        return;
    }

    fprintf(stderr, "%4d ", ++line);
    do {
        ch = getc(fp);
        if (ch == EOF) {
            putc('\n', stderr);
            break;
        } else if (ch == '\n') {
            fprintf(stderr, "\n%4d ", ++line);
        } else {
            putc(ch, stderr);
        }
    } while (1);

    fclose(fp);
}

gboolean
validate_xml_verbose(const xmlNode *xml_blob)
{
    int fd = 0;
    xmlDoc *doc = NULL;
    xmlNode *xml = NULL;
    gboolean rc = FALSE;
    char *filename = NULL;

    filename = crm_strdup_printf("%s/cib-invalid.XXXXXX", pcmk__get_tmpdir());

    umask(S_IWGRP | S_IWOTH | S_IROTH);
    fd = mkstemp(filename);
    pcmk__xml_write_fd(xml_blob, filename, fd, false, NULL);

    dump_file(filename);

    doc = xmlReadFile(filename, NULL, 0);
    xml = xmlDocGetRootElement(doc);
    rc = pcmk__validate_xml(xml, NULL, NULL, NULL);
    free_xml(xml);

    unlink(filename);
    free(filename);

    return rc;
}

gboolean
validate_xml(xmlNode *xml_blob, const char *validation, gboolean to_logs)
{
    return pcmk__validate_xml(xml_blob, validation, to_logs ? (xmlRelaxNGValidityErrorFunc) xml_log : NULL, GUINT_TO_POINTER(LOG_ERR));
}

gboolean
pcmk__validate_xml(xmlNode *xml_blob, const char *validation,
                   xmlRelaxNGValidityErrorFunc error_handler,
                   void *error_handler_context)
{
    GList *entry = NULL;
    pcmk__schema_t *schema = NULL;

    CRM_CHECK((xml_blob != NULL) && (xml_blob->doc != NULL), return FALSE);

    if (validation == NULL) {
        validation = crm_element_value(xml_blob, PCMK_XA_VALIDATE_WITH);
    }

    if (validation == NULL) {
        bool valid = FALSE;

        for (entry = known_schemas; entry != NULL; entry = entry->next) {
            schema = entry->data;
            if (validate_with(xml_blob, schema, NULL, NULL)) {
                valid = TRUE;
                crm_xml_add(xml_blob, PCMK_XA_VALIDATE_WITH, schema->name);
                crm_info("XML validated against %s", schema->name);
            }
        }
        return valid;
    }

    entry = pcmk__get_schema(validation);
    if (entry != NULL) {
        schema = entry->data;
        return validate_with(xml_blob, schema, error_handler,
                             error_handler_context);
    }

    crm_err("Unknown validator: %s", validation);
    return FALSE;
}

/* With this arrangement, an attempt to identify the message severity
   as explicitly signalled directly from XSLT is performed in rather
   a smart way (no reliance on formatting string + arguments being
   always specified as ["%s", purposeful_string], as it can also be
   ["%s: %s", some_prefix, purposeful_string] etc. so every argument
   pertaining %s specifier is investigated), and if such a mark found,
   the respective level is determined and, when the messages are to go
   to the native logs, the mark itself gets dropped
   (by the means of string shift).

   NOTE: whether the native logging is the right sink is decided per
         the ctx parameter -- NULL denotes this case, otherwise it
         carries a pointer to the numeric expression of the desired
         target logging level (messages with higher level will be
         suppressed)

   NOTE: on some architectures, this string shift may not have any
         effect, but that's an acceptable tradeoff

   The logging level for not explicitly designated messages
   (suspicious, likely internal errors or some runaways) is
   LOG_WARNING.
 */
static void G_GNUC_PRINTF(2, 3)
cib_upgrade_err(void *ctx, const char *fmt, ...)
{
    va_list ap, aq;
    char *arg_cur;

    bool found = FALSE;
    const char *fmt_iter = fmt;
    uint8_t msg_log_level = LOG_WARNING;  /* default for runaway messages */
    const unsigned * log_level = (const unsigned *) ctx;
    enum {
        escan_seennothing,
        escan_seenpercent,
    } scan_state = escan_seennothing;

    va_start(ap, fmt);
    va_copy(aq, ap);

    while (!found && *fmt_iter != '\0') {
        /* while casing schema borrowed from libqb:qb_vsnprintf_serialize */
        switch (*fmt_iter++) {
        case '%':
            if (scan_state == escan_seennothing) {
                scan_state = escan_seenpercent;
            } else if (scan_state == escan_seenpercent) {
                scan_state = escan_seennothing;
            }
            break;
        case 's':
            if (scan_state == escan_seenpercent) {
                scan_state = escan_seennothing;
                arg_cur = va_arg(aq, char *);
                if (arg_cur != NULL) {
                    switch (arg_cur[0]) {
                    case 'W':
                        if (!strncmp(arg_cur, "WARNING: ",
                                     sizeof("WARNING: ") - 1)) {
                            msg_log_level = LOG_WARNING;
                        }
                        if (ctx == NULL) {
                            memmove(arg_cur, arg_cur + sizeof("WARNING: ") - 1,
                                    strlen(arg_cur + sizeof("WARNING: ") - 1) + 1);
                        }
                        found = TRUE;
                        break;
                    case 'I':
                        if (!strncmp(arg_cur, "INFO: ",
                                     sizeof("INFO: ") - 1)) {
                            msg_log_level = LOG_INFO;
                        }
                        if (ctx == NULL) {
                            memmove(arg_cur, arg_cur + sizeof("INFO: ") - 1,
                                    strlen(arg_cur + sizeof("INFO: ") - 1) + 1);
                        }
                        found = TRUE;
                        break;
                    case 'D':
                        if (!strncmp(arg_cur, "DEBUG: ",
                                     sizeof("DEBUG: ") - 1)) {
                            msg_log_level = LOG_DEBUG;
                        }
                        if (ctx == NULL) {
                            memmove(arg_cur, arg_cur + sizeof("DEBUG: ") - 1,
                                    strlen(arg_cur + sizeof("DEBUG: ") - 1) + 1);
                        }
                        found = TRUE;
                        break;
                    }
                }
            }
            break;
        case '#': case '-': case ' ': case '+': case '\'': case 'I': case '.':
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
        case '*':
            break;
        case 'l':
        case 'z':
        case 't':
        case 'j':
        case 'd': case 'i':
        case 'o':
        case 'u':
        case 'x': case 'X':
        case 'e': case 'E':
        case 'f': case 'F':
        case 'g': case 'G':
        case 'a': case 'A':
        case 'c':
        case 'p':
            if (scan_state == escan_seenpercent) {
                (void) va_arg(aq, void *);  /* skip forward */
                scan_state = escan_seennothing;
            }
            break;
        default:
            scan_state = escan_seennothing;
            break;
        }
    }

    if (log_level != NULL) {
        /* intention of the following offset is:
           cibadmin -V -> start showing INFO labelled messages */
        if (*log_level + 4 >= msg_log_level) {
            vfprintf(stderr, fmt, ap);
        }
    } else {
        PCMK__XML_LOG_BASE(msg_log_level, TRUE, 0, "CIB upgrade: ", fmt, ap);
    }

    va_end(aq);
    va_end(ap);
}

/*!
 * \internal
 * \brief Apply a single XSL transformation to given XML
 *
 * \param[in] xml        XML to transform
 * \param[in] transform  XSL name
 * \param[in] to_logs    If false, certain validation errors will be sent to
 *                       stderr rather than logged
 *
 * \return Transformed XML on success, otherwise NULL
 */
static xmlNode *
apply_transformation(const xmlNode *xml, const char *transform,
                     gboolean to_logs)
{
    char *xform = NULL;
    xmlNode *out = NULL;
    xmlDocPtr res = NULL;
    xsltStylesheet *xslt = NULL;

    xform = pcmk__xml_artefact_path(pcmk__xml_artefact_ns_legacy_xslt,
                                    transform);

    /* for capturing, e.g., what's emitted via <xsl:message> */
    if (to_logs) {
        xsltSetGenericErrorFunc(NULL, cib_upgrade_err);
    } else {
        xsltSetGenericErrorFunc(&crm_log_level, cib_upgrade_err);
    }

    xslt = xsltParseStylesheetFile((pcmkXmlStr) xform);
    CRM_CHECK(xslt != NULL, goto cleanup);

    res = xsltApplyStylesheet(xslt, xml->doc, NULL);
    CRM_CHECK(res != NULL, goto cleanup);

    xsltSetGenericErrorFunc(NULL, NULL);  /* restore default one */

    out = xmlDocGetRootElement(res);

  cleanup:
    if (xslt) {
        xsltFreeStylesheet(xslt);
    }

    free(xform);

    return out;
}

/*!
 * \internal
 * \brief Perform all transformations needed to upgrade XML to next schema
 *
 * A schema upgrade can require up to three XSL transformations: an "enter"
 * transform, the main upgrade transform, and a "leave" transform. Perform
 * all needed transforms to upgrade given XML to the next schema.
 *
 * \param[in] original_xml  XML to transform
 * \param[in] schema_index  Index of schema that successfully validates
 *                          \p original_xml
 * \param[in] to_logs       If false, certain validation errors will be sent to
 *                          stderr rather than logged
 *
 * \return XML result of schema transforms if successful, otherwise NULL
 */
static xmlNode *
apply_upgrade(const xmlNode *original_xml, int schema_index, gboolean to_logs)
{
    pcmk__schema_t *schema = g_list_nth_data(known_schemas, schema_index);
    pcmk__schema_t *upgraded_schema = g_list_nth_data(known_schemas,
                                                      schema_index + 1);
    bool transform_onleave = false;
    char *transform_leave;
    const xmlNode *xml = original_xml;
    xmlNode *upgrade = NULL;
    xmlNode *final = NULL;
    xmlRelaxNGValidityErrorFunc error_handler = NULL;

    CRM_ASSERT((schema != NULL) && (upgraded_schema != NULL));

    if (to_logs) {
        error_handler = (xmlRelaxNGValidityErrorFunc) xml_log;
    }

    transform_onleave = schema->transform_onleave;
    if (schema->transform_enter != NULL) {
        crm_debug("Upgrading schema from %s to %s: "
                  "applying pre-upgrade XSL transform %s",
                  schema->name, upgraded_schema->name, schema->transform_enter);
        upgrade = apply_transformation(xml, schema->transform_enter, to_logs);
        if (upgrade == NULL) {
            crm_warn("Pre-upgrade XSL transform %s failed, "
                     "will skip post-upgrade transform",
                     schema->transform_enter);
            transform_onleave = FALSE;
        } else {
            xml = upgrade;
        }
    }


    crm_debug("Upgrading schema from %s to %s: "
              "applying upgrade XSL transform %s",
              schema->name, upgraded_schema->name, schema->transform);
    final = apply_transformation(xml, schema->transform, to_logs);
    if (upgrade != xml) {
        free_xml(upgrade);
        upgrade = NULL;
    }

    if ((final != NULL) && transform_onleave) {
        upgrade = final;
        /* following condition ensured in add_schema_by_version */
        CRM_ASSERT(schema->transform_enter != NULL);
        transform_leave = strdup(schema->transform_enter);
        /* enter -> leave */
        memcpy(strrchr(transform_leave, '-') + 1, "leave", sizeof("leave") - 1);
        crm_debug("Upgrading schema from %s to %s: "
                  "applying post-upgrade XSL transform %s",
                  schema->name, upgraded_schema->name, transform_leave);
        final = apply_transformation(upgrade, transform_leave, to_logs);
        if (final == NULL) {
            crm_warn("Ignoring failure of post-upgrade XSL transform %s",
                     transform_leave);
            final = upgrade;
        } else {
            free_xml(upgrade);
        }
        free(transform_leave);
    }

    if (final == NULL) {
        return NULL;
    }

    // Ensure result validates with its new schema
    if (!validate_with(final, upgraded_schema, error_handler,
                       GUINT_TO_POINTER(LOG_ERR))) {
        crm_err("Schema upgrade from %s to %s failed: "
                "XSL transform %s produced an invalid configuration",
                schema->name, upgraded_schema->name, schema->transform);
        crm_log_xml_debug(final, "bad-transform-result");
        free_xml(final);
        return NULL;
    }

    crm_info("Schema upgrade from %s to %s succeeded",
             schema->name, upgraded_schema->name);
    return final;
}

const char *
get_schema_name(int version)
{
    pcmk__schema_t *schema = g_list_nth_data(known_schemas, version);

    return (schema != NULL)? schema->name : "unknown";
}

int
get_schema_version(const char *name)
{
    int lpc = 0;

    if (name == NULL) {
        name = PCMK_VALUE_NONE;
    }

    for (GList *iter = known_schemas; iter != NULL; iter = iter->next) {
        pcmk__schema_t *schema = iter->data;

        if (pcmk__str_eq(name, schema->name, pcmk__str_casei)) {
            return lpc;
        }

        lpc++;
    }

    return -1;
}

/*!
 * \internal
 * \brief Get the schema list entry corresponding to XML configuration
 *
 * \param[in] xml  CIB XML to check
 *
 * \return List entry of schema configured in \p xml
 */
static GList *
get_configured_schema(const xmlNode *xml)
{
    const char *schema_name = crm_element_value(xml, PCMK_XA_VALIDATE_WITH);

    if (schema_name == NULL) {
        return NULL;
    }
    return pcmk__get_schema(schema_name);
}

/*!
 * \brief Update CIB XML to latest schema that validates it
 *
 * \param[in,out] xml              XML to update (may be freed and replaced
 *                                 after being transformed)
 * \param[in]     max_schema_name  If not NULL, do not update \p xml to any
 *                                 schema later than this one
 * \param[in]     transform        If false, do not update \p xml to any schema
 *                                 that requires an XSL transform
 * \param[in]     to_logs          If false, certain validation errors will be
 *                                 sent to stderr rather than logged
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__update_schema(xmlNode **xml, const char *max_schema_name, bool transform,
                    bool to_logs)
{
    int max_stable_schemas = xml_latest_schema_index();
    int max_schema_index = 0;
    int rc = pcmk_rc_ok;
    GList *entry = NULL;
    pcmk__schema_t *best_schema = NULL;
    pcmk__schema_t *original_schema = NULL;
    xmlRelaxNGValidityErrorFunc error_handler = 
        to_logs ? (xmlRelaxNGValidityErrorFunc) xml_log : NULL;

    CRM_CHECK((xml != NULL) && (*xml != NULL) && ((*xml)->doc != NULL),
              return EINVAL);

    if (max_schema_name != NULL) {
        GList *max_entry = pcmk__get_schema(max_schema_name);

        if (max_entry != NULL) {
            pcmk__schema_t *max_schema = max_entry->data;

            max_schema_index = max_schema->schema_index;
        }
    }
    if ((max_schema_index < 1) || (max_schema_index > max_stable_schemas)) {
        max_schema_index = max_stable_schemas;
    }

    entry = get_configured_schema(*xml);
    if (entry == NULL) {
        entry = known_schemas;
    } else {
        original_schema = entry->data;
        if (original_schema->schema_index >= max_schema_index) {
            return pcmk_rc_ok;
        }
    }

    for (; entry != NULL; entry = entry->next) {
        pcmk__schema_t *current_schema = entry->data;
        xmlNode *upgrade = NULL;

        if (current_schema->schema_index > max_schema_index) {
            break;
        }

        if (!validate_with(*xml, current_schema, error_handler,
                           GUINT_TO_POINTER(LOG_ERR))) {
            crm_debug("Schema %s does not validate", current_schema->name);
            if (best_schema != NULL) {
                /* we've satisfied the validation, no need to check further */
                break;
            }
            rc = pcmk_rc_schema_validation;
            continue; // Try again with the next higher schema
        }

        crm_debug("Schema %s validates", current_schema->name);
        rc = pcmk_rc_ok;
        best_schema = current_schema;
        if (current_schema->schema_index == max_schema_index) {
            break; // No further transformations possible
        }

        if (!transform || (current_schema->transform == NULL)
            || validate_with_silent(*xml, entry->next->data)) {
            /* The next schema either doesn't require a transform or validates
             * successfully even without the transform. Skip the transform and
             * try the next schema with the same XML.
             */
            continue;
        }

        upgrade = apply_upgrade(*xml, current_schema->schema_index, to_logs);
        if (upgrade == NULL) {
            /* The transform failed, so this schema can't be used. Later
             * schemas are unlikely to validate, but try anyway until we
             * run out of options.
             */
            rc = pcmk_rc_transform_failed;
        } else {
            best_schema = current_schema;
            free_xml(*xml);
            *xml = upgrade;
        }
    }

    if (best_schema != NULL) {
        if ((original_schema == NULL)
            || (best_schema->schema_index > original_schema->schema_index)) {
            crm_info("%s the configuration schema to %s",
                     (transform? "Transformed" : "Upgraded"),
                     best_schema->name);
            crm_xml_add(*xml, PCMK_XA_VALIDATE_WITH, best_schema->name);
        }
    }
    return rc;
}

gboolean
cli_config_update(xmlNode **xml, int *best_version, gboolean to_logs)
{
    gboolean rc = TRUE;
    char *original_schema_name = NULL;
    int version = 0;
    int orig_version = 0;
    pcmk__schema_t *x_0_schema = pcmk__find_x_0_schema()->data;

    original_schema_name = crm_element_value_copy(*xml, PCMK_XA_VALIDATE_WITH);
    version = get_schema_version(original_schema_name);
    orig_version = version;
    if (version < x_0_schema->schema_index) {
        // Current configuration schema is not acceptable, try to update
        xmlNode *converted = NULL;
        const char *new_schema_name = NULL;

        converted = pcmk__xml_copy(NULL, *xml);
        if (pcmk__update_schema(&converted, NULL, true, to_logs) == pcmk_rc_ok) {
            new_schema_name = crm_element_value(converted,
                                                PCMK_XA_VALIDATE_WITH);
            version = get_schema_version(new_schema_name);
        } else {
            version = 0;
        }

        if (version < x_0_schema->schema_index) {
            // Updated configuration schema is still not acceptable

            if (version < orig_version || orig_version == -1) {
                // We couldn't validate any schema at all
                if (to_logs) {
                    pcmk__config_err("Cannot upgrade configuration (claiming "
                                     "%s schema) to at least %s because it "
                                     "does not validate with any schema from "
                                     "%s to the latest",
                                     pcmk__s(original_schema_name, "no"),
                                     x_0_schema->name,
                                     get_schema_name(orig_version));
                } else {
                    fprintf(stderr, "Cannot upgrade configuration (claiming "
                                    "%s schema) to at least %s because it "
                                    "does not validate with any schema from "
                                    "%s to the latest\n",
                                    pcmk__s(original_schema_name, "no"),
                                    x_0_schema->name,
                                    get_schema_name(orig_version));
                }
            } else {
                // We updated configuration successfully, but still too low
                if (to_logs) {
                    pcmk__config_err("Cannot upgrade configuration (claiming "
                                     "%s schema) to at least %s because it "
                                     "would not upgrade past %s",
                                     pcmk__s(original_schema_name, "no"),
                                     x_0_schema->name,
                                     pcmk__s(new_schema_name, "unspecified version"));
                } else {
                    fprintf(stderr, "Cannot upgrade configuration (claiming "
                                    "%s schema) to at least %s because it "
                                    "would not upgrade past %s\n",
                                    pcmk__s(original_schema_name, "no"),
                                    x_0_schema->name,
                                    pcmk__s(new_schema_name, "unspecified version"));
                }
            }

            free_xml(converted);
            converted = NULL;
            rc = FALSE;

        } else {
            // Updated configuration schema is acceptable
            free_xml(*xml);
            *xml = converted;

            if (version < xml_latest_schema_index()) {
                if (to_logs) {
                    pcmk__config_warn("Configuration with %s schema was "
                                      "internally upgraded to acceptable (but "
                                      "not most recent) %s",
                                      pcmk__s(original_schema_name, "no"),
                                      get_schema_name(version));
                }
            } else {
                if (to_logs) {
                    crm_info("Configuration with %s schema was internally "
                             "upgraded to latest version %s",
                             pcmk__s(original_schema_name, "no"),
                             get_schema_name(version));
                }
            }
        }

    } else if (version >= get_schema_version(PCMK_VALUE_NONE)) {
        // Schema validation is disabled
        if (to_logs) {
            pcmk__config_warn("Schema validation of configuration is disabled "
                              "(enabling is encouraged and prevents common "
                              "misconfigurations)");

        } else {
            fprintf(stderr, "Schema validation of configuration is disabled "
                            "(enabling is encouraged and prevents common "
                            "misconfigurations)\n");
        }
    }

    if (best_version) {
        *best_version = version;
    }

    free(original_schema_name);
    return rc;
}

/*!
 * \internal
 * \brief Return a list of all schema files and any associated XSLT files
 *        later than the given one
 * \brief Return a list of all schema versions later than the given one
 *
 * \param[in] schema The schema to compare against (for example,
 *                   "pacemaker-3.1.rng" or "pacemaker-3.1")
 *
 * \note The caller is responsible for freeing both the returned list and
 *       the elements of the list
 */
GList *
pcmk__schema_files_later_than(const char *name)
{
    GList *lst = NULL;
    pcmk__schema_version_t ver;

    if (!version_from_filename(name, &ver)) {
        return lst;
    }

    for (GList *iter = g_list_nth(known_schemas, xml_latest_schema_index());
         iter != NULL; iter = iter->prev) {
        pcmk__schema_t *schema = iter->data;
        char *s = NULL;

        if (schema_cmp(ver, schema->version) != -1) {
            continue;
        }

        s = crm_strdup_printf("%s.rng", schema->name);
        lst = g_list_prepend(lst, s);

        if (schema->transform != NULL) {
            char *xform = crm_strdup_printf("%s.xsl", schema->transform);
            lst = g_list_prepend(lst, xform);
        }

        if (schema->transform_enter != NULL) {
            char *enter = crm_strdup_printf("%s.xsl", schema->transform_enter);

            lst = g_list_prepend(lst, enter);

            if (schema->transform_onleave) {
                int last_dash = strrchr(enter, '-') - enter;
                char *leave = crm_strdup_printf("%.*s-leave.xsl", last_dash, enter);

                lst = g_list_prepend(lst, leave);
            }
        }
    }

    return lst;
}

static void
append_href(xmlNode *xml, void *user_data)
{
    GList **list = user_data;
    char *href = crm_element_value_copy(xml, "href");

    if (href == NULL) {
        return;
    }
    *list = g_list_prepend(*list, href);
}

static void
external_refs_in_schema(GList **list, const char *contents)
{
    /* local-name()= is needed to ignore the xmlns= setting at the top of
     * the XML file.  Otherwise, the xpath query will always return nothing.
     */
    const char *search = "//*[local-name()='externalRef'] | //*[local-name()='include']";
    xmlNode *xml = pcmk__xml_parse(contents);

    crm_foreach_xpath_result(xml, search, append_href, list);
    free_xml(xml);
}

static int
read_file_contents(const char *file, char **contents)
{
    int rc = pcmk_rc_ok;
    char *path = NULL;

    if (pcmk__ends_with(file, ".rng")) {
        path = pcmk__xml_artefact_path(pcmk__xml_artefact_ns_legacy_rng, file);
    } else {
        path = pcmk__xml_artefact_path(pcmk__xml_artefact_ns_legacy_xslt, file);
    }

    rc = pcmk__file_contents(path, contents);

    free(path);
    return rc;
}

static void
add_schema_file_to_xml(xmlNode *parent, const char *file, GList **already_included)
{
    char *contents = NULL;
    char *path = NULL;
    xmlNode *file_node = NULL;
    GList *includes = NULL;
    int rc = pcmk_rc_ok;

    /* If we already included this file, don't do so again. */
    if (g_list_find_custom(*already_included, file, (GCompareFunc) strcmp) != NULL) {
        return;
    }

    /* Ensure whatever file we were given has a suffix we know about.  If not,
     * just assume it's an RNG file.
     */
    if (!pcmk__ends_with(file, ".rng") && !pcmk__ends_with(file, ".xsl")) {
        path = crm_strdup_printf("%s.rng", file);
    } else {
        path = pcmk__str_copy(file);
    }

    rc = read_file_contents(path, &contents);
    if (rc != pcmk_rc_ok || contents == NULL) {
        crm_warn("Could not read schema file %s: %s", file, pcmk_rc_str(rc));
        free(path);
        return;
    }

    /* Create a new <file path="..."> node with the contents of the file
     * as a CDATA block underneath it.
     */
    file_node = pcmk__xe_create(parent, PCMK_XA_FILE);
    crm_xml_add(file_node, PCMK_XA_PATH, path);
    *already_included = g_list_prepend(*already_included, path);

    xmlAddChild(file_node, xmlNewCDataBlock(parent->doc, (pcmkXmlStr) contents,
                                            strlen(contents)));

    /* Scan the file for any <externalRef> or <include> nodes and build up
     * a list of the files they reference.
     */
    external_refs_in_schema(&includes, contents);

    /* For each referenced file, recurse to add it (and potentially anything it
     * references, ...) to the XML.
     */
    for (GList *iter = includes; iter != NULL; iter = iter->next) {
        add_schema_file_to_xml(parent, iter->data, already_included);
    }

    free(contents);
    g_list_free_full(includes, free);
}

/*!
 * \internal
 * \brief Add an XML schema file and all the files it references as children
 *        of a given XML node
 *
 * \param[in,out] parent            The parent XML node
 * \param[in] name                  The schema version to compare against
 *                                  (for example, "pacemaker-3.1" or "pacemaker-3.1.rng")
 * \param[in,out] already_included  A list of names that have already been added
 *                                  to the parent node.
 *
 * \note The caller is responsible for freeing both the returned list and
 *       the elements of the list
 */
void
pcmk__build_schema_xml_node(xmlNode *parent, const char *name, GList **already_included)
{
    /* First, create an unattached node to add all the schema files to as children. */
    xmlNode *schema_node = pcmk__xe_create(NULL, PCMK__XA_SCHEMA);

    crm_xml_add(schema_node, PCMK_XA_VERSION, name);
    add_schema_file_to_xml(schema_node, name, already_included);

    /* Then, if we actually added any children, attach the node to parent.  If
     * we did not add any children (for instance, name was invalid), this prevents
     * us from returning a document with additional empty children.
     */
    if (schema_node->children != NULL) {
        xmlAddChild(parent, schema_node);
    } else {
        free_xml(schema_node);
    }
}

/*!
 * \internal
 * \brief Return the directory containing any extra schema files that a
 *        Pacemaker Remote node fetched from the cluster
 */
const char *
pcmk__remote_schema_dir(void)
{
    const char *dir = pcmk__env_option(PCMK__ENV_REMOTE_SCHEMA_DIRECTORY);

    if (pcmk__str_empty(dir)) {
        return PCMK__REMOTE_SCHEMA_DIR;
    }

    return dir;
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/common/schemas_compat.h>

const char *
xml_latest_schema(void)
{
    return pcmk__highest_schema_name();
}

int
update_validation(xmlNode **xml, int *best, int max, gboolean transform,
                  gboolean to_logs)
{
    int rc = pcmk__update_schema(xml, get_schema_name(max), transform, to_logs);

    if ((best != NULL) && (xml != NULL) && (rc == pcmk_rc_ok)) {
        const char *schema_name = crm_element_value(*xml,
                                                    PCMK_XA_VALIDATE_WITH);
        GList *schema_entry = pcmk__get_schema(schema_name);

        if (schema_entry != NULL) {
            *best = ((pcmk__schema_t *)(schema_entry->data))->schema_index;
        }
    }

    return pcmk_rc2legacy(rc);
}

// LCOV_EXCL_STOP
// End deprecated API
