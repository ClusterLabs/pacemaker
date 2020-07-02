/*
 * Copyright 2004-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <bzlib.h>
#include <sys/types.h>

char *
crm_itoa_stack(int an_int, char *buffer, size_t len)
{
    if (buffer != NULL) {
        snprintf(buffer, len, "%d", an_int);
    }

    return buffer;
}

/*!
 * \internal
 * \brief Scan a long long integer from a string
 *
 * \param[in]  text      String to scan
 * \param[out] result    If not NULL, where to store scanned value
 * \param[out] end_text  If not NULL, where to store pointer to just after value
 *
 * \return Standard Pacemaker return code (also set errno on error)
 */
static int
scan_ll(const char *text, long long *result, char **end_text)
{
    long long local_result = -1;
    char *local_end_text = NULL;
    int rc = pcmk_rc_ok;

    errno = 0;
    if (text != NULL) {
#ifdef ANSI_ONLY
        local_result = (long long) strtol(text, &local_end_text, 10);
#else
        local_result = strtoll(text, &local_end_text, 10);
#endif
        if (errno == ERANGE) {
            rc = errno;
            crm_warn("Integer parsed from %s was clipped to %lld",
                     text, local_result);

        } else if (errno != 0) {
            rc = errno;
            local_result = -1;
            crm_err("Could not parse integer from %s (using -1 instead): %s",
                    text, pcmk_rc_str(rc));

        } else if (local_end_text == text) {
            rc = EINVAL;
            local_result = -1;
            crm_err("Could not parse integer from %s (using -1 instead): "
                    "No digits found", text);
        }

        if ((end_text == NULL) && (local_end_text != NULL)
            && (local_end_text[0] != '\0')) {
            crm_warn("Characters left over after parsing '%s': '%s'",
                     text, local_end_text);
        }
        errno = rc;
    }
    if (end_text != NULL) {
        *end_text = local_end_text;
    }
    if (result != NULL) {
        *result = local_result;
    }
    return rc;
}

/*!
 * \brief Parse a long long integer value from a string
 *
 * \param[in] text          The string to parse
 * \param[in] default_text  Default string to parse if text is NULL
 *
 * \return Parsed value on success, -1 (and set errno) on error
 */
long long
crm_parse_ll(const char *text, const char *default_text)
{
    long long result;

    if (text == NULL) {
        text = default_text;
        if (text == NULL) {
            crm_err("No default conversion value supplied");
            errno = EINVAL;
            return -1;
        }
    }
    scan_ll(text, &result, NULL);
    return result;
}

/*!
 * \brief Parse an integer value from a string
 *
 * \param[in] text          The string to parse
 * \param[in] default_text  Default string to parse if text is NULL
 *
 * \return Parsed value on success, INT_MIN or INT_MAX (and set errno to ERANGE)
 *         if parsed value is out of integer range, otherwise -1 (and set errno)
 */
int
crm_parse_int(const char *text, const char *default_text)
{
    long long result = crm_parse_ll(text, default_text);

    if (result < INT_MIN) {
        // If errno is ERANGE, crm_parse_ll() has already logged a message
        if (errno != ERANGE) {
            crm_err("Conversion of %s was clipped: %lld", text, result);
            errno = ERANGE;
        }
        return INT_MIN;

    } else if (result > INT_MAX) {
        // If errno is ERANGE, crm_parse_ll() has already logged a message
        if (errno != ERANGE) {
            crm_err("Conversion of %s was clipped: %lld", text, result);
            errno = ERANGE;
        }
        return INT_MAX;
    }

    return (int) result;
}

/*!
 * \internal
 * \brief Parse a guint from a string stored in a hash table
 *
 * \param[in]  table        Hash table to search
 * \param[in]  key          Hash table key to use to retrieve string
 * \param[in]  default_val  What to use if key has no entry in table
 * \param[out] result       If not NULL, where to store parsed integer
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__guint_from_hash(GHashTable *table, const char *key, guint default_val,
                      guint *result)
{
    const char *value;
    long long value_ll;

    CRM_CHECK((table != NULL) && (key != NULL), return EINVAL);

    value = g_hash_table_lookup(table, key);
    if (value == NULL) {
        if (result != NULL) {
            *result = default_val;
        }
        return pcmk_rc_ok;
    }

    errno = 0;
    value_ll = crm_parse_ll(value, NULL);
    if (errno != 0) {
        return errno; // Message already logged
    }
    if ((value_ll < 0) || (value_ll > G_MAXUINT)) {
        crm_warn("Could not parse non-negative integer from %s", value);
        return ERANGE;
    }

    if (result != NULL) {
        *result = (guint) value_ll;
    }
    return pcmk_rc_ok;
}

#ifndef NUMCHARS
#  define	NUMCHARS	"0123456789."
#endif

#ifndef WHITESPACE
#  define	WHITESPACE	" \t\n\r\f"
#endif

/*!
 * \brief Parse a time+units string and return milliseconds equivalent
 *
 * \param[in] input  String with a number and units (optionally with whitespace
 *                   before and/or after the number)
 *
 * \return Milliseconds corresponding to string expression, or -1 on error
 */
long long
crm_get_msec(const char *input)
{
    const char *num_start = NULL;
    const char *units;
    long long multiplier = 1000;
    long long divisor = 1;
    long long msec = -1;
    size_t num_len = 0;
    char *end_text = NULL;

    if (input == NULL) {
        return -1;
    }

    num_start = input + strspn(input, WHITESPACE);
    num_len = strspn(num_start, NUMCHARS);
    if (num_len < 1) {
        return -1;
    }
    units = num_start + num_len;
    units += strspn(units, WHITESPACE);

    if (!strncasecmp(units, "ms", 2) || !strncasecmp(units, "msec", 4)) {
        multiplier = 1;
        divisor = 1;
    } else if (!strncasecmp(units, "us", 2) || !strncasecmp(units, "usec", 4)) {
        multiplier = 1;
        divisor = 1000;
    } else if (!strncasecmp(units, "s", 1) || !strncasecmp(units, "sec", 3)) {
        multiplier = 1000;
        divisor = 1;
    } else if (!strncasecmp(units, "m", 1) || !strncasecmp(units, "min", 3)) {
        multiplier = 60 * 1000;
        divisor = 1;
    } else if (!strncasecmp(units, "h", 1) || !strncasecmp(units, "hr", 2)) {
        multiplier = 60 * 60 * 1000;
        divisor = 1;
    } else if ((*units != EOS) && (*units != '\n') && (*units != '\r')) {
        return -1;
    }

    scan_ll(num_start, &msec, &end_text);
    if (msec > (LLONG_MAX / multiplier)) {
        // Arithmetics overflow while multiplier/divisor mutually exclusive
        return LLONG_MAX;
    }
    msec *= multiplier;
    msec /= divisor;
    return msec;
}

gboolean
safe_str_neq(const char *a, const char *b)
{
    if (a == b) {
        return FALSE;

    } else if (a == NULL || b == NULL) {
        return TRUE;

    } else if (strcasecmp(a, b) == 0) {
        return FALSE;
    }
    return TRUE;
}

gboolean
crm_is_true(const char *s)
{
    gboolean ret = FALSE;

    if (s != NULL) {
        crm_str_to_boolean(s, &ret);
    }
    return ret;
}

int
crm_str_to_boolean(const char *s, int *ret)
{
    if (s == NULL) {
        return -1;

    } else if (strcasecmp(s, "true") == 0
               || strcasecmp(s, "on") == 0
               || strcasecmp(s, "yes") == 0 || strcasecmp(s, "y") == 0 || strcasecmp(s, "1") == 0) {
        *ret = TRUE;
        return 1;

    } else if (strcasecmp(s, "false") == 0
               || strcasecmp(s, "off") == 0
               || strcasecmp(s, "no") == 0 || strcasecmp(s, "n") == 0 || strcasecmp(s, "0") == 0) {
        *ret = FALSE;
        return 1;
    }
    return -1;
}

char *
crm_strip_trailing_newline(char *str)
{
    int len;

    if (str == NULL) {
        return str;
    }

    for (len = strlen(str) - 1; len >= 0 && str[len] == '\n'; len--) {
        str[len] = '\0';
    }

    return str;
}

gboolean
crm_str_eq(const char *a, const char *b, gboolean use_case)
{
    if (use_case) {
        return g_strcmp0(a, b) == 0;

        /* TODO - Figure out which calls, if any, really need to be case independent */
    } else if (a == b) {
        return TRUE;

    } else if (a == NULL || b == NULL) {
        /* shouldn't be comparing NULLs */
        return FALSE;

    } else if (strcasecmp(a, b) == 0) {
        return TRUE;
    }
    return FALSE;
}

/*!
 * \brief Check whether a string starts with a certain sequence
 *
 * \param[in] str    String to check
 * \param[in] prefix Sequence to match against beginning of \p str
 *
 * \return \c true if \p str begins with match, \c false otherwise
 * \note This is equivalent to !strncmp(s, prefix, strlen(prefix))
 *       but is likely less efficient when prefix is a string literal
 *       if the compiler optimizes away the strlen() at compile time,
 *       and more efficient otherwise.
 */
bool
pcmk__starts_with(const char *str, const char *prefix)
{
    const char *s = str;
    const char *p = prefix;

    if (!s || !p) {
        return false;
    }
    while (*s && *p) {
        if (*s++ != *p++) {
            return false;
        }
    }
    return (*p == 0);
}

static inline bool
ends_with(const char *s, const char *match, bool as_extension)
{
    if (pcmk__str_empty(match)) {
        return true;
    } else if (s == NULL) {
        return false;
    } else {
        size_t slen, mlen;

        /* Besides as_extension, we could also check
           !strchr(&match[1], match[0]) but that would be inefficient.
         */
        if (as_extension) {
            s = strrchr(s, match[0]);
            return (s == NULL)? false : !strcmp(s, match);
        }

        mlen = strlen(match);
        slen = strlen(s);
        return ((slen >= mlen) && !strcmp(s + slen - mlen, match));
    }
}

/*!
 * \internal
 * \brief Check whether a string ends with a certain sequence
 *
 * \param[in] s      String to check
 * \param[in] match  Sequence to match against end of \p s
 *
 * \return \c true if \p s ends case-sensitively with match, \c false otherwise
 * \note pcmk__ends_with_ext() can be used if the first character of match
 *       does not recur in match.
 */
bool
pcmk__ends_with(const char *s, const char *match)
{
    return ends_with(s, match, false);
}

/*!
 * \internal
 * \brief Check whether a string ends with a certain "extension"
 *
 * \param[in] s      String to check
 * \param[in] match  Extension to match against end of \p s, that is,
 *                   its first character must not occur anywhere
 *                   in the rest of that very sequence (example: file
 *                   extension where the last dot is its delimiter,
 *                   e.g., ".html"); incorrect results may be
 *                   returned otherwise.
 *
 * \return \c true if \p s ends (verbatim, i.e., case sensitively)
 *         with "extension" designated as \p match (including empty
 *         string), \c false otherwise
 *
 * \note Main incentive to prefer this function over \c pcmk__ends_with()
 *       where possible is the efficiency (at the cost of added
 *       restriction on \p match as stated; the complexity class
 *       remains the same, though: BigO(M+N) vs. BigO(M+2N)).
 */
bool
pcmk__ends_with_ext(const char *s, const char *match)
{
    return ends_with(s, match, true);
}

/*
 * This re-implements g_str_hash as it was prior to glib2-2.28:
 *
 * https://gitlab.gnome.org/GNOME/glib/commit/354d655ba8a54b754cb5a3efb42767327775696c
 *
 * Note that the new g_str_hash is presumably a *better* hash (it's actually
 * a correct implementation of DJB's hash), but we need to preserve existing
 * behaviour, because the hash key ultimately determines the "sort" order
 * when iterating through GHashTables, which affects allocation of scores to
 * clone instances when iterating through rsc->allowed_nodes.  It (somehow)
 * also appears to have some minor impact on the ordering of a few
 * pseudo_event IDs in the transition graph.
 */
guint
g_str_hash_traditional(gconstpointer v)
{
    const signed char *p;
    guint32 h = 0;

    for (p = v; *p != '\0'; p++)
        h = (h << 5) - h + *p;

    return h;
}

/* used with hash tables where case does not matter */
gboolean
crm_strcase_equal(gconstpointer a, gconstpointer b)
{
    return crm_str_eq((const char *) a, (const char *) b, FALSE);
}

guint
crm_strcase_hash(gconstpointer v)
{
    const signed char *p;
    guint32 h = 0;

    for (p = v; *p != '\0'; p++)
        h = (h << 5) - h + g_ascii_tolower(*p);

    return h;
}

static void
copy_str_table_entry(gpointer key, gpointer value, gpointer user_data)
{
    if (key && value && user_data) {
        g_hash_table_insert((GHashTable*)user_data, strdup(key), strdup(value));
    }
}

GHashTable *
crm_str_table_dup(GHashTable *old_table)
{
    GHashTable *new_table = NULL;

    if (old_table) {
        new_table = crm_str_table_new();
        g_hash_table_foreach(old_table, copy_str_table_entry, new_table);
    }
    return new_table;
}

/*!
 * \internal
 * \brief Add a word to a space-separated string list
 *
 * \param[in,out] list  Pointer to beginning of list
 * \param[in]     word  Word to add to list
 *
 * \return (Potentially new) beginning of list
 * \note This dynamically reallocates list as needed.
 */
char *
pcmk__add_word(char *list, const char *word)
{
    if (word != NULL) {
        size_t len = list? strlen(list) : 0;

        list = realloc_safe(list, len + strlen(word) + 2); // 2 = space + EOS
        sprintf(list + len, " %s", word);
    }
    return list;
}

/*!
 * \internal
 * \brief Compress data
 *
 * \param[in]  data        Data to compress
 * \param[in]  length      Number of characters of data to compress
 * \param[in]  max         Maximum size of compressed data (or 0 to estimate)
 * \param[out] result      Where to store newly allocated compressed result
 * \param[out] result_len  Where to store actual compressed length of result
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__compress(const char *data, unsigned int length, unsigned int max,
               char **result, unsigned int *result_len)
{
    int rc;
    char *compressed = NULL;
    char *uncompressed = strdup(data);
#ifdef CLOCK_MONOTONIC
    struct timespec after_t;
    struct timespec before_t;
#endif

    if (max == 0) {
        max = (length * 1.01) + 601; // Size guaranteed to hold result
    }

#ifdef CLOCK_MONOTONIC
    clock_gettime(CLOCK_MONOTONIC, &before_t);
#endif

    compressed = calloc((size_t) max, sizeof(char));
    CRM_ASSERT(compressed);

    *result_len = max;
    rc = BZ2_bzBuffToBuffCompress(compressed, result_len, uncompressed, length,
                                  CRM_BZ2_BLOCKS, 0, CRM_BZ2_WORK);
    free(uncompressed);
    if (rc != BZ_OK) {
        crm_err("Compression of %d bytes failed: %s " CRM_XS " bzerror=%d",
                length, bz2_strerror(rc), rc);
        free(compressed);
        return pcmk_rc_error;
    }

#ifdef CLOCK_MONOTONIC
    clock_gettime(CLOCK_MONOTONIC, &after_t);

    crm_trace("Compressed %d bytes into %d (ratio %d:1) in %.0fms",
             length, *result_len, length / (*result_len),
             (after_t.tv_sec - before_t.tv_sec) * 1000 +
             (after_t.tv_nsec - before_t.tv_nsec) / 1e6);
#else
    crm_trace("Compressed %d bytes into %d (ratio %d:1)",
             length, *result_len, length / (*result_len));
#endif

    *result = compressed;
    return pcmk_rc_ok;
}

char *
crm_strdup_printf(char const *format, ...)
{
    va_list ap;
    int len = 0;
    char *string = NULL;

    va_start(ap, format);
    len = vasprintf (&string, format, ap);
    CRM_ASSERT(len > 0);
    va_end(ap);
    return string;
}

int
pcmk__parse_ll_range(const char *srcstring, long long *start, long long *end)
{
    char *remainder = NULL;

    CRM_ASSERT(start != NULL && end != NULL);

    *start = -1;
    *end = -1;

    crm_trace("Attempting to decode: [%s]", srcstring);
    if (srcstring == NULL || strcmp(srcstring, "") == 0 || strcmp(srcstring, "-") == 0) {
        return pcmk_rc_unknown_format;
    }

    /* String starts with a dash, so this is either a range with
     * no beginning or garbage.
     * */
    if (*srcstring == '-') {
        int rc = scan_ll(srcstring+1, end, &remainder);

        if (rc != pcmk_rc_ok || *remainder != '\0') {
            return pcmk_rc_unknown_format;
        } else {
            return pcmk_rc_ok;
        }
    }

    if (scan_ll(srcstring, start, &remainder) != pcmk_rc_ok) {
        return pcmk_rc_unknown_format;
    }

    if (*remainder && *remainder == '-') {
        if (*(remainder+1)) {
            char *more_remainder = NULL;
            int rc = scan_ll(remainder+1, end, &more_remainder);

            if (rc != pcmk_rc_ok || *more_remainder != '\0') {
                return pcmk_rc_unknown_format;
            }
        }
    } else if (*remainder && *remainder != '-') {
        *start = -1;
        return pcmk_rc_unknown_format;
    } else {
        /* The input string contained only one number.  Set start and end
         * to the same value and return pcmk_rc_ok.  This gives the caller
         * a way to tell this condition apart from a range with no end.
         */
        *end = *start;
    }

    return pcmk_rc_ok;
}

gboolean
pcmk__str_in_list(GList *lst, const gchar *s)
{
    if (lst == NULL) {
        return FALSE;
    }

    if (strcmp(lst->data, "*") == 0 && lst->next == NULL) {
        return TRUE;
    }

    return g_list_find_custom(lst, s, (GCompareFunc) strcmp) != NULL;
}

bool
pcmk__str_any_of(const char *s, ...)
{
    bool rc = false;
    va_list ap;

    va_start(ap, s);

    while (1) {
        const char *ele = va_arg(ap, const char *);

        if (ele == NULL) {
            break;
        } else if (crm_str_eq(s, ele, FALSE)) {
            rc = true;
            break;
        }
    }

    va_end(ap);
    return rc;
}

bool
pcmk__str_none_of(const char *s, ...)
{
    bool rc = true;
    va_list ap;

    va_start(ap, s);

    while (1) {
        const char *ele = va_arg(ap, const char *);

        if (ele == NULL) {
            break;
        } else if (crm_str_eq(s, ele, FALSE)) {
            rc = false;
            break;
        }
    }

    va_end(ap);
    return rc;
}

/*
 * \brief Sort strings, with numeric portions sorted numerically
 *
 * Sort two strings case-insensitively like strcasecmp(), but with any numeric
 * portions of the string sorted numerically. This is particularly useful for
 * node names (for example, "node10" will sort higher than "node9" but lower
 * than "remotenode9").
 *
 * \param[in] s1  First string to compare (must not be NULL)
 * \param[in] s2  Second string to compare (must not be NULL)
 *
 * \retval -1 \p s1 comes before \p s2
 * \retval  0 \p s1 and \p s2 are equal
 * \retval  1 \p s1 comes after \p s2
 */
int
pcmk_numeric_strcasecmp(const char *s1, const char *s2)
{
    while (*s1 && *s2) {
        if (isdigit(*s1) && isdigit(*s2)) {
            // If node names contain a number, sort numerically

            char *end1 = NULL;
            char *end2 = NULL;
            long num1 = strtol(s1, &end1, 10);
            long num2 = strtol(s2, &end2, 10);

            // allow ordering e.g. 007 > 7
            size_t len1 = end1 - s1;
            size_t len2 = end2 - s2;

            if (num1 < num2) {
                return -1;
            } else if (num1 > num2) {
                return 1;
            } else if (len1 < len2) {
                return -1;
            } else if (len1 > len2) {
                return 1;
            }
            s1 = end1;
            s2 = end2;
        } else {
            // Compare non-digits case-insensitively
            int lower1 = tolower(*s1);
            int lower2 = tolower(*s2);

            if (lower1 < lower2) {
                return -1;
            } else if (lower1 > lower2) {
                return 1;
            }
            ++s1;
            ++s2;
        }
    }
    if (!*s1 && *s2) {
        return -1;
    } else if (*s1 && !*s2) {
        return 1;
    }
    return 0;
}
