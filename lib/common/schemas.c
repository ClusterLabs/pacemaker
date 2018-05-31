/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
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

#if HAVE_LIBXSLT
#  include <libxslt/xslt.h>
#  include <libxslt/transform.h>
#  include <libxslt/xsltutils.h>
#endif

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>  /* CRM_XML_LOG_BASE */

typedef struct {
    unsigned char v[2];
} schema_version_t;

#define SCHEMA_ZERO { .v = { 0, 0 } }

#define schema_scanf(s, prefix, version, suffix) \
    sscanf((s), prefix "%hhu.%hhu" suffix, &((version).v[0]), &((version).v[1]))

#define schema_strdup_printf(prefix, version, suffix) \
    crm_strdup_printf(prefix "%u.%u" suffix, (version).v[0], (version).v[1])

typedef struct {
    xmlRelaxNGPtr rng;
    xmlRelaxNGValidCtxtPtr valid;
    xmlRelaxNGParserCtxtPtr parser;
} relaxng_ctx_cache_t;

enum schema_validator_e {
    schema_validator_none,
    schema_validator_rng
};

struct schema_s {
    char *name;
    char *location;
    char *transform;
    void *cache;
    enum schema_validator_e validator;
    int after_transform;
    schema_version_t version;
    char *transform_enter;
    bool transform_onleave;
};

static struct schema_s *known_schemas = NULL;
static int xml_schema_max = 0;
static bool silent_logging = FALSE;

static void
xml_log(int priority, const char *fmt, ...)
G_GNUC_PRINTF(2, 3);

static void
xml_log(int priority, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (silent_logging == FALSE) {
        /* XXX should not this enable dechunking as well? */
        CRM_XML_LOG_BASE(priority, FALSE, 0, NULL, fmt, ap);
    }
    va_end(ap);
}

static int
xml_latest_schema_index(void)
{
    return xml_schema_max - 3; // index from 0, ignore "pacemaker-next"/"none"
}

static int
xml_minimum_schema_index(void)
{
    static int best = 0;
    if (best == 0) {
        int lpc = 0;

        best = xml_latest_schema_index();
        for (lpc = best; lpc > 0; lpc--) {
            if (known_schemas[lpc].version.v[0]
                < known_schemas[best].version.v[0]) {
                return best;
            } else {
                best = lpc;
            }
        }
        best = xml_latest_schema_index();
    }
    return best;
}

const char *
xml_latest_schema(void)
{
    return get_schema_name(xml_latest_schema_index());
}

static const char *
get_schema_root(void)
{
    static const char *base = NULL;

    if (base == NULL) {
        base = getenv("PCMK_schema_directory");
    }
    if (base == NULL || strlen(base) == 0) {
        base = CRM_SCHEMA_DIRECTORY;
    }
    return base;
}

static char *
get_schema_path(const char *name, const char *file)
{
    const char *base = get_schema_root();

    if (file) {
        return crm_strdup_printf("%s/%s", base, file);
    }
    return crm_strdup_printf("%s/%s.rng", base, name);
}

static inline bool
version_from_filename(const char *filename, schema_version_t *version)
{
    int rc = schema_scanf(filename, "pacemaker-", *version, ".rng");

    return (rc == 2);
}

static int
schema_filter(const struct dirent *a)
{
    int rc = 0;
    schema_version_t version = SCHEMA_ZERO;

    if (strstr(a->d_name, "pacemaker-") != a->d_name) {
        /* crm_trace("%s - wrong prefix", a->d_name); */

    } else if (!crm_ends_with_ext(a->d_name, ".rng")) {
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
schema_sort(const struct dirent **a, const struct dirent **b)
{
    schema_version_t a_version = SCHEMA_ZERO;
    schema_version_t b_version = SCHEMA_ZERO;

    if (!version_from_filename(a[0]->d_name, &a_version)
        || !version_from_filename(b[0]->d_name, &b_version)) {
        // Shouldn't be possible, but makes static analysis happy
        return 0;
    }

    for (int i = 0; i < 2; ++i) {
        if (a_version.v[i] < b_version.v[i]) {
            return -1;
        } else if (a_version.v[i] > b_version.v[i]) {
            return 1;
        }
    }
    return 0;
}

static void
add_schema(enum schema_validator_e validator, const schema_version_t *version,
           const char *name, const char *location, const char *transform,
           const char *transform_enter, bool transform_onleave,
           int after_transform)
{
    int last = xml_schema_max;
    bool have_version = FALSE;

    xml_schema_max++;
    known_schemas = realloc_safe(known_schemas,
                                 xml_schema_max * sizeof(struct schema_s));
    CRM_ASSERT(known_schemas != NULL);
    memset(known_schemas+last, 0, sizeof(struct schema_s));
    known_schemas[last].validator = validator;
    known_schemas[last].after_transform = after_transform;

    for (int i = 0; i < 2; ++i) {
        known_schemas[last].version.v[i] = version->v[i];
        if (version->v[i]) {
            have_version = TRUE;
        }
    }
    if (have_version) {
        known_schemas[last].name = schema_strdup_printf("pacemaker-", *version, "");
        known_schemas[last].location = crm_strdup_printf("%s.rng",
                                                         known_schemas[last].name);
    } else {
        CRM_ASSERT(name);
        CRM_ASSERT(location);
        schema_scanf(name, "%*[^-]-", known_schemas[last].version, "");
        known_schemas[last].name = strdup(name);
        known_schemas[last].location = strdup(location);
    }

    if (transform) {
        known_schemas[last].transform = strdup(transform);
    }
    if (transform_enter) {
        known_schemas[last].transform_enter = strdup(transform_enter);
    }
    known_schemas[last].transform_onleave = transform_onleave;
    if (after_transform == 0) {
        after_transform = xml_schema_max;  /* upgrade is a one-way */
    }
    known_schemas[last].after_transform = after_transform;

    if (known_schemas[last].after_transform < 0) {
        crm_debug("Added supported schema %d: %s (%s)",
                  last, known_schemas[last].name, known_schemas[last].location);

    } else if (known_schemas[last].transform) {
        crm_debug("Added supported schema %d: %s (%s upgrades to %d with %s)",
                  last, known_schemas[last].name, known_schemas[last].location,
                  known_schemas[last].after_transform,
                  known_schemas[last].transform);

    } else {
        crm_debug("Added supported schema %d: %s (%s upgrades to %d)",
                  last, known_schemas[last].name, known_schemas[last].location,
                  known_schemas[last].after_transform);
    }
}

/*!
 * \internal
 * \brief Add version-specified schema + auxiliary data to internal bookkeeping.
 * \return \c -ENOENT when no upgrade schema associated, \c pcmk_ok otherwise.
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
 *     "upgrade-enter" is
 *   . name convention:  (see "upgrade-enter")
 */
static int
add_schema_by_version(const schema_version_t *version, int next,
                      bool transform_expected)
{
    bool transform_onleave = FALSE;
    int rc = pcmk_ok;
    struct stat s;
    char *xslt = NULL,
         *transform_upgrade = NULL,
         *transform_enter = NULL;

    /* prologue for further transform_expected handling */
    if (transform_expected) {
        /* check if there's suitable "upgrade" stylesheet */
        transform_upgrade = schema_strdup_printf("upgrade-", *version, ".xsl");
        xslt = get_schema_path(NULL, transform_upgrade);
    }

    if (!transform_expected) {
        /* jump directly to the end */

    } else if (stat(xslt, &s) == 0) {
        /* perhaps there's also a targeted "upgrade-enter" stylesheet */
        transform_enter = schema_strdup_printf("upgrade-", *version, "-enter.xsl");
        free(xslt);
        xslt = get_schema_path(NULL, transform_enter);
        if (stat(xslt, &s) != 0) {
            /* or initially, at least a generic one */
            crm_debug("Upgrade-enter transform %s not found", xslt);
            free(xslt);
            xslt = get_schema_path(NULL, "upgrade-enter.xsl");
            if (stat(xslt, &s) != 0) {
                crm_debug("Upgrade-enter transform %s not found, either", xslt);
                free(xslt);
                xslt = NULL;
            }
        }
        /* xslt contains full path to "upgrade-enter" stylesheet */
        if (xslt != NULL) {
            /* then there should be "upgrade-leave" counterpart */
            memcpy(strrchr(xslt, '-') + 1, "leave", 5);  /* enter -> leave */
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
        next = -1;
        rc = -ENOENT;
    }

    add_schema(schema_validator_rng, version, NULL, NULL,
               transform_upgrade, transform_enter, transform_onleave, next);

    free(transform_upgrade);
    free(transform_enter);

    return rc;
}

/*!
 * \internal
 * \brief Load pacemaker schemas into cache
 */
void
crm_schema_init(void)
{
    int lpc, max;
    const char *base = get_schema_root();
    struct dirent **namelist = NULL;
    const schema_version_t zero = SCHEMA_ZERO;

    max = scandir(base, &namelist, schema_filter, schema_sort);
    if (max < 0) {
        crm_notice("scandir(%s) failed: %s (%d)", base, strerror(errno), errno);

    } else {
        for (lpc = 0; lpc < max; lpc++) {
            int next = 0;
            schema_version_t version = SCHEMA_ZERO;
            char *transform = NULL;

            if (!version_from_filename(namelist[lpc]->d_name, &version)) {
                // Shouldn't be possible, but makes static analysis happy
                crm_err("Skipping schema '%s': could not parse version",
                        namelist[lpc]->d_name);
                continue;
            }
            if ((lpc + 1) < max) {
                schema_version_t next_version = SCHEMA_ZERO;

                if (version_from_filename(namelist[lpc+1]->d_name, &next_version)
                    && (version.v[0] < next_version.v[0])) {

                    struct stat s;
                    char *xslt = NULL;

                    transform = schema_strdup_printf("upgrade-", version, ".xsl");
                    xslt = get_schema_path(NULL, transform);
                    if (stat(xslt, &s) != 0) {
                        crm_err("Transform %s not found", xslt);
                        free(transform);
                        transform = NULL;
                        next = -1;
                    }
                    free(xslt);
                }

            } else {
                next = -1;
            }
            add_schema(schema_validator_rng, &version, NULL, NULL, transform,
                       NULL, FALSE, next);
            if (transform == NULL && next == -1) {
                break;
            }
            free(transform);
        }

        for (lpc = 0; lpc < max; lpc++) {
            free(namelist[lpc]);
        }
        free(namelist);
    }

    add_schema(schema_validator_rng, &zero, "pacemaker-next",
               "pacemaker-next.rng", NULL, NULL, FALSE, -1);

    add_schema(schema_validator_none, &zero, "none",
               "N/A", NULL, NULL, FALSE, -1);
}

#if 0
static void
relaxng_invalid_stderr(void *userData, xmlErrorPtr error)
{
    /*
       Structure xmlError
       struct _xmlError {
       int      domain  : What part of the library raised this er
       int      code    : The error code, e.g. an xmlParserError
       char *   message : human-readable informative error messag
       xmlErrorLevel    level   : how consequent is the error
       char *   file    : the filename
       int      line    : the line number if available
       char *   str1    : extra string information
       char *   str2    : extra string information
       char *   str3    : extra string information
       int      int1    : extra number information
       int      int2    : column number of the error or 0 if N/A
       void *   ctxt    : the parser context if available
       void *   node    : the node in the tree
       }
     */
    crm_err("Structured error: line=%d, level=%d %s", error->line, error->level, error->message);
}
#endif

static gboolean
validate_with_relaxng(xmlDocPtr doc, gboolean to_logs, const char *relaxng_file,
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
        crm_info("Creating RNG parser context");
        ctx = calloc(1, sizeof(relaxng_ctx_cache_t));

        xmlLoadExtDtdDefaultValue = 1;
        ctx->parser = xmlRelaxNGNewParserCtxt(relaxng_file);
        CRM_CHECK(ctx->parser != NULL, goto cleanup);

        if (to_logs) {
            xmlRelaxNGSetParserErrors(ctx->parser,
                                      (xmlRelaxNGValidityErrorFunc) xml_log,
                                      (xmlRelaxNGValidityWarningFunc) xml_log,
                                      GUINT_TO_POINTER(LOG_ERR));
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

        if (to_logs) {
            xmlRelaxNGSetValidErrors(ctx->valid,
                                     (xmlRelaxNGValidityErrorFunc) xml_log,
                                     (xmlRelaxNGValidityWarningFunc) xml_log,
                                     GUINT_TO_POINTER(LOG_ERR));
        } else {
            xmlRelaxNGSetValidErrors(ctx->valid,
                                     (xmlRelaxNGValidityErrorFunc) fprintf,
                                     (xmlRelaxNGValidityWarningFunc) fprintf,
                                     stderr);
        }
    }

    /* xmlRelaxNGSetValidStructuredErrors( */
    /*  valid, relaxng_invalid_stderr, valid); */

    xmlLineNumbersDefault(1);
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

/*!
 * \internal
 * \brief Clean up global memory associated with XML schemas
 */
void
crm_schema_cleanup(void)
{
    int lpc;
    relaxng_ctx_cache_t *ctx = NULL;

    for (lpc = 0; lpc < xml_schema_max; lpc++) {

        switch (known_schemas[lpc].validator) {
            case schema_validator_none: // not cached
                break;
            case schema_validator_rng: // cached
                ctx = (relaxng_ctx_cache_t *) known_schemas[lpc].cache;
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
                known_schemas[lpc].cache = NULL;
                break;
        }
        free(known_schemas[lpc].name);
        free(known_schemas[lpc].location);
        free(known_schemas[lpc].transform);
        free(known_schemas[lpc].transform_enter);
    }
    free(known_schemas);
    known_schemas = NULL;

    xsltCleanupGlobals();  /* XXX proper, explicit reshaking regarding
                                  init/fini routines is pending (pair
                                  of facade functions to express the
                                  intentions in a clean way) */
}

static gboolean
validate_with(xmlNode *xml, int method, gboolean to_logs)
{
    xmlDocPtr doc = NULL;
    gboolean valid = FALSE;
    char *file = NULL;

    if (method < 0) {
        return FALSE;
    }

    if (known_schemas[method].validator == schema_validator_none) {
        return TRUE;
    }

    CRM_CHECK(xml != NULL, return FALSE);
    doc = getDocPtr(xml);
    file = get_schema_path(known_schemas[method].name,
                           known_schemas[method].location);

    crm_trace("Validating with: %s (type=%d)",
              crm_str(file), known_schemas[method].validator);
    switch (known_schemas[method].validator) {
        case schema_validator_rng:
            valid =
                validate_with_relaxng(doc, to_logs, file,
                                      (relaxng_ctx_cache_t **) & (known_schemas[method].cache));
            break;
        default:
            crm_err("Unknown validator type: %d",
                    known_schemas[method].validator);
            break;
    }

    free(file);
    return valid;
}

static bool
validate_with_silent(xmlNode *xml, int method)
{
    bool rc, sl_backup = silent_logging;
    silent_logging = TRUE;
    rc = validate_with(xml, method, TRUE);
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
validate_xml_verbose(xmlNode *xml_blob)
{
    int fd = 0;
    xmlDoc *doc = NULL;
    xmlNode *xml = NULL;
    gboolean rc = FALSE;
    char *filename = NULL;

    filename = crm_strdup_printf("%s/cib-invalid.XXXXXX", crm_get_tmpdir());

    umask(S_IWGRP | S_IWOTH | S_IROTH);
    fd = mkstemp(filename);
    write_xml_fd(xml_blob, filename, fd, FALSE);

    dump_file(filename);

    doc = xmlParseFile(filename);
    xml = xmlDocGetRootElement(doc);
    rc = validate_xml(xml, NULL, FALSE);
    free_xml(xml);

    unlink(filename);
    free(filename);

    return rc;
}

gboolean
validate_xml(xmlNode *xml_blob, const char *validation, gboolean to_logs)
{
    int version = 0;

    if (validation == NULL) {
        validation = crm_element_value(xml_blob, XML_ATTR_VALIDATION);
    }

    if (validation == NULL) {
        int lpc = 0;
        bool valid = FALSE;

        for (lpc = 0; lpc < xml_schema_max; lpc++) {
            if (validate_with(xml_blob, lpc, FALSE)) {
                valid = TRUE;
                crm_xml_add(xml_blob, XML_ATTR_VALIDATION,
                            known_schemas[lpc].name);
                crm_info("XML validated against %s", known_schemas[lpc].name);
                if(known_schemas[lpc].after_transform == 0) {
                    break;
                }
            }
        }

        return valid;
    }

    version = get_schema_version(validation);
    if (strcmp(validation, "none") == 0) {
        return TRUE;
    } else if (version < xml_schema_max) {
        return validate_with(xml_blob, version, to_logs);
    }

    crm_err("Unknown validator: %s", validation);
    return FALSE;
}

#if HAVE_LIBXSLT

static void
cib_upgrade_err(void *ctx, const char *fmt, ...)
G_GNUC_PRINTF(2, 3);

static void
cib_upgrade_err(void *ctx, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    CRM_XML_LOG_BASE(LOG_WARNING, TRUE, 0, "CIB upgrade: ", fmt, ap);
    va_end(ap);
}


/* Denotes temporary emergency fix for "xmldiff'ing not text-node-ready";
   proper fix is most likely to teach __xml_diff_object and friends to
   deal with XML_TEXT_NODE (and more?), i.e., those nodes currently
   missing "_private" field (implicitly as NULL) which clashes with
   unchecked accesses (e.g. in __xml_offset) -- the outcome may be that
   those unexpected XML nodes will simply be ignored for the purpose of
   diff'ing, or it may be made more robust, or per the user's preference
   (which then may be exposed as crm_diff switch).

   Said XML_TEXT_NODE may appear unexpectedly due to how upgrade-2.10.xsl
   is arranged.

   The emergency fix is simple: reparse XSLT output with blank-ignoring
   parser. */
#ifndef PCMK_SCHEMAS_EMERGENCY_XSLT
#define PCMK_SCHEMAS_EMERGENCY_XSLT 1
#endif

static xmlNode *
apply_transformation(xmlNode *xml, const char *transform, gboolean to_logs)
{
    char *xform = NULL;
    xmlNode *out = NULL;
    xmlDocPtr res = NULL;
    xmlDocPtr doc = NULL;
    xsltStylesheet *xslt = NULL;
#if PCMK_SCHEMAS_EMERGENCY_XSLT != 0
    xmlChar *emergency_result;
    int emergency_txt_len;
    int emergency_res;
#endif

    CRM_CHECK(xml != NULL, return FALSE);
    doc = getDocPtr(xml);
    xform = get_schema_path(NULL, transform);

    xmlLoadExtDtdDefaultValue = 1;
    xmlSubstituteEntitiesDefault(1);

    /* for capturing, e.g., what's emitted via <xsl:message> */
    if (to_logs) {
        xsltSetGenericErrorFunc(NULL, cib_upgrade_err);
    } else {
        xsltSetGenericErrorFunc((void *) stderr, (xmlGenericErrorFunc) fprintf);
    }

    xslt = xsltParseStylesheetFile((const xmlChar *)xform);
    CRM_CHECK(xslt != NULL, goto cleanup);

    res = xsltApplyStylesheet(xslt, doc, NULL);
    CRM_CHECK(res != NULL, goto cleanup);

    xsltSetGenericErrorFunc(NULL, NULL);  /* restore default one */


#if PCMK_SCHEMAS_EMERGENCY_XSLT != 0
    emergency_res = xsltSaveResultToString(&emergency_result,
                                           &emergency_txt_len, res, xslt);
    xmlFreeDoc(res);
    CRM_CHECK(emergency_res == 0, goto cleanup);
    out = string2xml((const char *) emergency_result);
    free(emergency_result);
#else
    out = xmlDocGetRootElement(res);
#endif

  cleanup:
    if (xslt) {
        xsltFreeStylesheet(xslt);
    }

    free(xform);

    return out;
}
#endif

const char *
get_schema_name(int version)
{
    if (version < 0 || version >= xml_schema_max) {
        return "unknown";
    }
    return known_schemas[version].name;
}

int
get_schema_version(const char *name)
{
    int lpc = 0;

    if (name == NULL) {
        name = "none";
    }
    for (; lpc < xml_schema_max; lpc++) {
        if (safe_str_eq(name, known_schemas[lpc].name)) {
            return lpc;
        }
    }
    return -1;
}

/* set which validation to use */
int
update_validation(xmlNode **xml_blob, int *best, int max, gboolean transform,
                  gboolean to_logs)
{
    xmlNode *xml = NULL;
    char *value = NULL;
    int max_stable_schemas = xml_latest_schema_index();
    int lpc = 0, match = -1, rc = pcmk_ok;
    int next = -1;  /* -1 denotes "inactive" value */

    CRM_CHECK(best != NULL, return -EINVAL);
    *best = 0;

    CRM_CHECK(xml_blob != NULL, return -EINVAL);
    CRM_CHECK(*xml_blob != NULL, return -EINVAL);

    xml = *xml_blob;
    value = crm_element_value_copy(xml, XML_ATTR_VALIDATION);

    if (value != NULL) {
        match = get_schema_version(value);

        lpc = match;
        if (lpc >= 0 && transform == FALSE) {
            *best = lpc++;

        } else if (lpc < 0) {
            crm_debug("Unknown validation schema");
            lpc = 0;
        }
    }

    if (match >= max_stable_schemas) {
        /* nothing to do */
        free(value);
        *best = match;
        return pcmk_ok;
    }

    while (lpc <= max_stable_schemas) {
        crm_debug("Testing '%s' validation (%d of %d)",
                  known_schemas[lpc].name ? known_schemas[lpc].name : "<unset>",
                  lpc, max_stable_schemas);

        if (validate_with(xml, lpc, to_logs) == FALSE) {
            if (next != -1) {
                crm_info("Configuration not valid for schema: %s",
                         known_schemas[lpc].name);
                next = -1;
            } else {
                crm_trace("%s validation failed",
                          known_schemas[lpc].name ? known_schemas[lpc].name : "<unset>");
            }
            if (*best) {
                /* we've satisfied the validation, no need to check further */
                break;
            }
            rc = -pcmk_err_schema_validation;

        } else {
            if (next != -1) {
                crm_debug("Configuration valid for schema: %s",
                          known_schemas[next].name);
                next = -1;
            }
            rc = pcmk_ok;
        }

        if (rc == pcmk_ok) {
            *best = lpc;
        }

        if (rc == pcmk_ok && transform) {
            xmlNode *upgrade = NULL;
            next = known_schemas[lpc].after_transform;

            if (next <= lpc) {
                /* There is no next version, or next would regress */
                crm_trace("Stopping at %s", known_schemas[lpc].name);
                break;

            } else if (max > 0 && (lpc == max || next > max)) {
                crm_trace("Upgrade limit reached at %s (lpc=%d, next=%d, max=%d)",
                          known_schemas[lpc].name, lpc, next, max);
                break;

            } else if (known_schemas[lpc].transform == NULL
                       /* possibly avoid transforming when readily valid
                          (in general more restricted when crossing the major
                          version boundary, as X.0 "transitional" version is
                          expected to be more strict than it's successors that
                          may re-allow constructs from previous major line) */
                       || validate_with_silent(xml, next)) {
                crm_debug("%s-style configuration is also valid for %s",
                           known_schemas[lpc].name, known_schemas[next].name);

                lpc = next;

            } else {
                crm_debug("Upgrading %s-style configuration to %s with %s",
                           known_schemas[lpc].name, known_schemas[next].name,
                           known_schemas[lpc].transform);

#if HAVE_LIBXSLT
                upgrade = apply_transformation(xml, known_schemas[lpc].transform, to_logs);
#endif
                if (upgrade == NULL) {
                    crm_err("Transformation %s failed",
                            known_schemas[lpc].transform);
                    rc = -pcmk_err_transform_failed;

                } else if (validate_with(upgrade, next, to_logs)) {
                    crm_info("Transformation %s successful",
                             known_schemas[lpc].transform);
                    lpc = next;
                    *best = next;
                    free_xml(xml);
                    xml = upgrade;
                    rc = pcmk_ok;

                } else {
                    crm_err("Transformation %s did not produce a valid configuration",
                            known_schemas[lpc].transform);
                    crm_log_xml_info(upgrade, "transform:bad");
                    free_xml(upgrade);
                    rc = -pcmk_err_schema_validation;
                }
                next = -1;
            }
        }

        if (transform == FALSE || rc != pcmk_ok) {
            /* we need some progress! */
            lpc++;
        }
    }

    if (*best > match && *best) {
        crm_info("%s the configuration from %s to %s",
                   transform?"Transformed":"Upgraded",
                   value ? value : "<none>", known_schemas[*best].name);
        crm_xml_add(xml, XML_ATTR_VALIDATION, known_schemas[*best].name);
    }

    *xml_blob = xml;
    free(value);
    return rc;
}

gboolean
cli_config_update(xmlNode **xml, int *best_version, gboolean to_logs)
{
    gboolean rc = TRUE;
    const char *value = crm_element_value(*xml, XML_ATTR_VALIDATION);
    char *const orig_value = strdup(value == NULL ? "(none)" : value);

    int version = get_schema_version(value);
    int orig_version = version;
    int min_version = xml_minimum_schema_index();

    if (version < min_version) {
        xmlNode *converted = NULL;

        converted = copy_xml(*xml);
        update_validation(&converted, &version, 0, TRUE, to_logs);

        value = crm_element_value(converted, XML_ATTR_VALIDATION);
        if (version < min_version) {
            if (version < orig_version || orig_version == -1) {
                if (to_logs) {
                    crm_config_err("Your current configuration %s could not"
                                   " validate with any schema in range [%s, %s],"
                                   " cannot upgrade to %s.",
                                   orig_value,
                                   get_schema_name(orig_version),
                                   xml_latest_schema(),
                                   get_schema_name(min_version));
                } else {
                    fprintf(stderr, "Your current configuration %s could not"
                                    " validate with any schema in range [%s, %s],"
                                    " cannot upgrade to %s.\n",
                                    orig_value,
                                    get_schema_name(orig_version),
                                    xml_latest_schema(),
                                    get_schema_name(min_version));
                }
            } else if (to_logs) {
                crm_config_err("Your current configuration could only be upgraded to %s... "
                               "the minimum requirement is %s.", crm_str(value),
                               get_schema_name(min_version));
            } else {
                fprintf(stderr, "Your current configuration could only be upgraded to %s... "
                        "the minimum requirement is %s.\n",
                        crm_str(value), get_schema_name(min_version));
            }

            free_xml(converted);
            converted = NULL;
            rc = FALSE;

        } else {
            free_xml(*xml);
            *xml = converted;

            if (version < xml_latest_schema_index()) {
                crm_config_warn("Your configuration was internally updated to %s... "
                                "which is acceptable but not the most recent",
                                get_schema_name(version));

            } else if (to_logs) {
                crm_info("Your configuration was internally updated to the latest version (%s)",
                         get_schema_name(version));
            }
        }

    } else if (version >= get_schema_version("none")) {
        if (to_logs) {
            crm_config_warn("Configuration validation is currently disabled."
                            " It is highly encouraged and prevents many common cluster issues.");

        } else {
            fprintf(stderr, "Configuration validation is currently disabled."
                    " It is highly encouraged and prevents many common cluster issues.\n");
        }
    }

    if (best_version) {
        *best_version = version;
    }

    free(orig_value);
    return rc;
}
