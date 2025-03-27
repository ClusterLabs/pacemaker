/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <float.h>  // DBL_MIN
#include <limits.h>
#include <bzlib.h>
#include <sys/types.h>

/*!
 * \internal
 * \brief Scan a long long integer from a string
 *
 * \param[in]  text           String to scan
 * \param[out] result         If not NULL, where to store scanned value
 * \param[in]  default_value  Value to use if text is NULL or invalid
 * \param[out] end_text       If not NULL, where to store pointer to first
 *                            non-integer character
 *
 * \return Standard Pacemaker return code (\c pcmk_rc_ok on success,
 *         \c pcmk_rc_bad_input on failed string conversion due to invalid
 *         input, or \c ERANGE if outside long long range)
 * \note Sets \c errno on error
 */
static int
scan_ll(const char *text, long long *result, long long default_value,
        char **end_text)
{
    long long local_result = default_value;
    char *local_end_text = NULL;
    int rc = pcmk_rc_ok;

    errno = 0;
    if (text != NULL) {
        local_result = strtoll(text, &local_end_text, 10);
        if (errno == ERANGE) {
            rc = errno;
            crm_debug("Integer parsed from '%s' was clipped to %lld",
                      text, local_result);

        } else if (local_end_text == text) {
            rc = pcmk_rc_bad_input;
            local_result = default_value;
            crm_debug("Could not parse integer from '%s' (using %lld instead): "
                      "No digits found", text, default_value);

        } else if (errno != 0) {
            rc = errno;
            local_result = default_value;
            crm_debug("Could not parse integer from '%s' (using %lld instead): "
                      "%s", text, default_value, pcmk_rc_str(rc));
        }

        if ((end_text == NULL) && !pcmk__str_empty(local_end_text)) {
            crm_debug("Characters left over after parsing '%s': '%s'",
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
 * \internal
 * \brief Scan a long long integer value from a string
 *
 * \param[in]  text           The string to scan (may be NULL)
 * \param[out] result         Where to store result (or NULL to ignore)
 * \param[in]  default_value  Value to use if text is NULL or invalid
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__scan_ll(const char *text, long long *result, long long default_value)
{
    long long local_result = default_value;
    int rc = scan_ll(text, &local_result, default_value, NULL);

    if (result != NULL) {
        *result = local_result;
    }
    return rc;
}

/*!
 * \internal
 * \brief Scan an integer value from a string, constrained to a minimum
 *
 * \param[in]  text           The string to scan (may be NULL)
 * \param[out] result         Where to store result (or NULL to ignore)
 * \param[in]  minimum        Value to use as default and minimum
 *
 * \return Standard Pacemaker return code
 * \note If the value is larger than the maximum integer, EOVERFLOW will be
 *       returned and \p result will be set to the maximum integer.
 */
int
pcmk__scan_min_int(const char *text, int *result, int minimum)
{
    int rc;
    long long result_ll;

    rc = pcmk__scan_ll(text, &result_ll, (long long) minimum);

    if (result_ll < (long long) minimum) {
        crm_warn("Clipped '%s' to minimum acceptable value %d", text, minimum);
        result_ll = (long long) minimum;

    } else if (result_ll > INT_MAX) {
        crm_warn("Clipped '%s' to maximum integer %d", text, INT_MAX);
        result_ll = (long long) INT_MAX;
        rc = EOVERFLOW;
    }

    if (result != NULL) {
        *result = (int) result_ll;
    }
    return rc;
}

/*!
 * \internal
 * \brief Scan a TCP port number from a string
 *
 * \param[in]  text  The string to scan
 * \param[out] port  Where to store result (or NULL to ignore)
 *
 * \return Standard Pacemaker return code
 * \note \p port will be -1 if \p text is NULL or invalid
 */
int
pcmk__scan_port(const char *text, int *port)
{
    long long port_ll;
    int rc = pcmk__scan_ll(text, &port_ll, -1LL);

    if (rc != pcmk_rc_ok) {
        crm_warn("'%s' is not a valid port: %s", text, pcmk_rc_str(rc));

    } else if ((text != NULL) // wasn't default or invalid
        && ((port_ll < 0LL) || (port_ll > 65535LL))) {
        crm_warn("Ignoring port specification '%s' "
                 "not in valid range (0-65535)", text);
        rc = (port_ll < 0LL)? pcmk_rc_before_range : pcmk_rc_after_range;
        port_ll = -1LL;
    }
    if (port != NULL) {
        *port = (int) port_ll;
    }
    return rc;
}

/*!
 * \internal
 * \brief Scan a double-precision floating-point value from a string
 *
 * \param[in]      text         The string to parse
 * \param[out]     result       Parsed value on success, or
 *                              \c PCMK__PARSE_DBL_DEFAULT on error
 * \param[in]      default_text Default string to parse if \p text is
 *                              \c NULL
 * \param[out]     end_text     If not \c NULL, where to store a pointer
 *                              to the position immediately after the
 *                              value
 *
 * \return Standard Pacemaker return code (\c pcmk_rc_ok on success,
 *         \c EINVAL on failed string conversion due to invalid input,
 *         \c EOVERFLOW on arithmetic overflow, \c pcmk_rc_underflow
 *         on arithmetic underflow, or \c errno from \c strtod() on
 *         other parse errors)
 */
int
pcmk__scan_double(const char *text, double *result, const char *default_text,
                  char **end_text)
{
    int rc = pcmk_rc_ok;
    char *local_end_text = NULL;

    pcmk__assert(result != NULL);
    *result = PCMK__PARSE_DBL_DEFAULT;

    text = (text != NULL) ? text : default_text;

    if (text == NULL) {
        rc = EINVAL;
        crm_debug("No text and no default conversion value supplied");

    } else {
        errno = 0;
        *result = strtod(text, &local_end_text);

        if (errno == ERANGE) {
            /*
             * Overflow: strtod() returns +/- HUGE_VAL and sets errno to
             *           ERANGE
             *
             * Underflow: strtod() returns "a value whose magnitude is
             *            no greater than the smallest normalized
             *            positive" double. Whether ERANGE is set is
             *            implementation-defined.
             */
            const char *over_under;

            if (QB_ABS(*result) > DBL_MIN) {
                rc = EOVERFLOW;
                over_under = "over";
            } else {
                rc = pcmk_rc_underflow;
                over_under = "under";
            }

            crm_debug("Floating-point value parsed from '%s' would %sflow "
                      "(using %g instead)", text, over_under, *result);

        } else if (errno != 0) {
            rc = errno;
            // strtod() set *result = 0 on parse failure
            *result = PCMK__PARSE_DBL_DEFAULT;

            crm_debug("Could not parse floating-point value from '%s' (using "
                      "%.1f instead): %s", text, PCMK__PARSE_DBL_DEFAULT,
                      pcmk_rc_str(rc));

        } else if (local_end_text == text) {
            // errno == 0, but nothing was parsed
            rc = EINVAL;
            *result = PCMK__PARSE_DBL_DEFAULT;

            crm_debug("Could not parse floating-point value from '%s' (using "
                      "%.1f instead): No digits found", text,
                      PCMK__PARSE_DBL_DEFAULT);

        } else if (QB_ABS(*result) <= DBL_MIN) {
            /*
             * errno == 0 and text was parsed, but value might have
             * underflowed.
             *
             * ERANGE might not be set for underflow. Check magnitude
             * of *result, but also make sure the input number is not
             * actually zero (0 <= DBL_MIN is not underflow).
             *
             * This check must come last. A parse failure in strtod()
             * also sets *result == 0, so a parse failure would match
             * this test condition prematurely.
             */
            for (const char *p = text; p != local_end_text; p++) {
                if (strchr("0.eE", *p) == NULL) {
                    rc = pcmk_rc_underflow;
                    crm_debug("Floating-point value parsed from '%s' would "
                              "underflow (using %g instead)", text, *result);
                    break;
                }
            }

        } else {
            crm_trace("Floating-point value parsed successfully from "
                      "'%s': %g", text, *result);
        }

        if ((end_text == NULL) && !pcmk__str_empty(local_end_text)) {
            crm_debug("Characters left over after parsing '%s': '%s'",
                      text, local_end_text);
        }
    }

    if (end_text != NULL) {
        *end_text = local_end_text;
    }

    return rc;
}

/*!
 * \internal
 * \brief Parse a guint from a string stored in a hash table
 *
 * \param[in]     table        Hash table to search
 * \param[in]     key          Hash table key to use to retrieve string
 * \param[in]     default_val  What to use if key has no entry in table
 * \param[out]    result       If not NULL, where to store parsed integer
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__guint_from_hash(GHashTable *table, const char *key, guint default_val,
                      guint *result)
{
    const char *value;
    long long value_ll;
    int rc = pcmk_rc_ok;

    CRM_CHECK((table != NULL) && (key != NULL), return EINVAL);

    if (result != NULL) {
        *result = default_val;
    }

    value = g_hash_table_lookup(table, key);
    if (value == NULL) {
        return pcmk_rc_ok;
    }

    rc = pcmk__scan_ll(value, &value_ll, 0LL);
    if (rc != pcmk_rc_ok) {
        crm_warn("Using default (%u) for %s because '%s' is not a "
                 "valid integer: %s", default_val, key, value, pcmk_rc_str(rc));
        return rc;
    }

    if ((value_ll < 0) || (value_ll > G_MAXUINT)) {
        crm_warn("Using default (%u) for %s because '%s' is not in valid range",
                 default_val, key, value);
        return ERANGE;
    }

    if (result != NULL) {
        *result = (guint) value_ll;
    }
    return pcmk_rc_ok;
}

/*!
 * \brief Parse a time+units string and return milliseconds equivalent
 *
 * \param[in] input  String with a nonnegative number and optional unit
 *                   (optionally with whitespace before and/or after the
 *                   number). If missing, the unit defaults to seconds.
 *
 * \return Milliseconds corresponding to string expression, or
 *         \c PCMK__PARSE_INT_DEFAULT on error
 */
long long
crm_get_msec(const char *input)
{
    char *units = NULL; // Do not free; will point to part of input
    long long multiplier = 1000;
    long long divisor = 1;
    long long msec = PCMK__PARSE_INT_DEFAULT;
    int rc = pcmk_rc_ok;

    if (input == NULL) {
        return PCMK__PARSE_INT_DEFAULT;
    }

    // Skip initial whitespace
    while (isspace(*input)) {
        input++;
    }

    rc = scan_ll(input, &msec, PCMK__PARSE_INT_DEFAULT, &units);

    if ((rc == ERANGE) && (msec > 0)) {
        crm_warn("'%s' will be clipped to %lld", input, msec);

    } else if ((rc != pcmk_rc_ok) || (msec < 0)) {
        crm_warn("'%s' is not a valid time duration: %s",
                 input, ((rc == pcmk_rc_ok)? "Negative" : pcmk_rc_str(rc)));
        return PCMK__PARSE_INT_DEFAULT;
    }

    /* If the number is a decimal, scan_ll() reads only the integer part. Skip
     * any remaining digits or decimal characters.
     *
     * @COMPAT Well-formed and malformed decimals are both accepted inputs. For
     * example, "3.14 ms" and "3.1.4 ms" are treated the same as "3ms" and
     * parsed successfully. At a compatibility break, decide if this is still
     * desired.
     */
    while (isdigit(*units) || (*units == '.')) {
        units++;
    }

    // Skip any additional whitespace after the number
    while (isspace(*units)) {
        units++;
    }

    /* @COMPAT Use exact comparisons. Currently, we match too liberally, and the
     * second strncasecmp() in each case is redundant.
     */
    if ((*units == '\0')
        || (strncasecmp(units, "s", 1) == 0)
        || (strncasecmp(units, "sec", 3) == 0)) {
        multiplier = 1000;
        divisor = 1;

    } else if ((strncasecmp(units, "ms", 2) == 0)
               || (strncasecmp(units, "msec", 4) == 0)) {
        multiplier = 1;
        divisor = 1;

    } else if ((strncasecmp(units, "us", 2) == 0)
               || (strncasecmp(units, "usec", 4) == 0)) {
        multiplier = 1;
        divisor = 1000;

    } else if ((strncasecmp(units, "m", 1) == 0)
               || (strncasecmp(units, "min", 3) == 0)) {
        multiplier = 60 * 1000;
        divisor = 1;

    } else if ((strncasecmp(units, "h", 1) == 0)
               || (strncasecmp(units, "hr", 2) == 0)) {
        multiplier = 60 * 60 * 1000;
        divisor = 1;

    } else {
        // Invalid units
        return PCMK__PARSE_INT_DEFAULT;
    }

    // Apply units, capping at LLONG_MAX
    if (msec > (LLONG_MAX / multiplier)) {
        return LLONG_MAX;
    }
    return (msec * multiplier) / divisor;
}

/*!
 * \brief Parse milliseconds from a Pacemaker interval specification
 *
 * \param[in]  input      Pacemaker time interval specification (a bare number
 *                        of seconds; a number with a unit, optionally with
 *                        whitespace before and/or after the number; or an ISO
 *                        8601 duration)
 * \param[out] result_ms  Where to store milliseconds equivalent of \p input on
 *                        success (limited to the range of an unsigned integer),
 *                        or 0 if \p input is \c NULL or invalid
 *
 * \return Standard Pacemaker return code (specifically, \c pcmk_rc_ok if
 *         \p input is valid or \c NULL, and \c EINVAL otherwise)
 */
int
pcmk_parse_interval_spec(const char *input, guint *result_ms)
{
    long long msec = PCMK__PARSE_INT_DEFAULT;
    int rc = pcmk_rc_ok;

    if (input == NULL) {
        msec = 0;
        goto done;
    }

    if (input[0] == 'P') {
        crm_time_t *period_s = crm_time_parse_duration(input);

        if (period_s != NULL) {
            msec = crm_time_get_seconds(period_s);
            msec = QB_MIN(msec, G_MAXUINT / 1000) * 1000;
            crm_time_free(period_s);
        }

    } else {
        msec = crm_get_msec(input);
    }

    if (msec < 0) {
        crm_warn("Using 0 instead of invalid interval specification '%s'",
                 input);
        msec = 0;
        rc = EINVAL;
    }

done:
    if (result_ms != NULL) {
        *result_ms = (msec >= G_MAXUINT)? G_MAXUINT : (guint) msec;
    }
    return rc;
}

gboolean
crm_is_true(const char *s)
{
    gboolean ret = FALSE;

    return (crm_str_to_boolean(s, &ret) < 0)? FALSE : ret;
}

int
crm_str_to_boolean(const char *s, int *ret)
{
    if (s == NULL) {
        return -1;
    }

    if (pcmk__strcase_any_of(s, PCMK_VALUE_TRUE, "on", "yes", "y", "1", NULL)) {
        if (ret != NULL) {
            *ret = TRUE;
        }
        return 1;
    }

    if (pcmk__strcase_any_of(s, PCMK_VALUE_FALSE, PCMK_VALUE_OFF, "no", "n",
                             "0", NULL)) {
        if (ret != NULL) {
            *ret = FALSE;
        }
        return 1;
    }
    return -1;
}

/*!
 * \internal
 * \brief Replace any trailing newlines in a string with \0's
 *
 * \param[in,out] str  String to trim
 *
 * \return \p str
 */
char *
pcmk__trim(char *str)
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

/*!
 * \internal
 * \brief Create a hash of a string suitable for use with GHashTable
 *
 * \param[in] v  String to hash
 *
 * \return A hash of \p v compatible with g_str_hash() before glib 2.28
 * \note glib changed their hash implementation:
 *
 * https://gitlab.gnome.org/GNOME/glib/commit/354d655ba8a54b754cb5a3efb42767327775696c
 *
 * Note that the new g_str_hash is presumably a *better* hash (it's actually
 * a correct implementation of DJB's hash), but we need to preserve existing
 * behaviour, because the hash key ultimately determines the "sort" order
 * when iterating through GHashTables, which affects allocation of scores to
 * clone instances when iterating through allowed nodes. It (somehow) also
 * appears to have some minor impact on the ordering of a few pseudo_event IDs
 * in the transition graph.
 */
static guint
pcmk__str_hash(gconstpointer v)
{
    const signed char *p;
    guint32 h = 0;

    for (p = v; *p != '\0'; p++)
        h = (h << 5) - h + *p;

    return h;
}

/*!
 * \internal
 * \brief Create a hash table with case-sensitive strings as keys
 *
 * \param[in] key_destroy_func    Function to free a key
 * \param[in] value_destroy_func  Function to free a value
 *
 * \return Newly allocated hash table
 * \note It is the caller's responsibility to free the result, using
 *       g_hash_table_destroy().
 */
GHashTable *
pcmk__strkey_table(GDestroyNotify key_destroy_func,
                   GDestroyNotify value_destroy_func)
{
    return g_hash_table_new_full(pcmk__str_hash, g_str_equal,
                                 key_destroy_func, value_destroy_func);
}

/*!
 * \internal
 * \brief Insert string copies into a hash table as key and value
 *
 * \param[in,out] table  Hash table to add to
 * \param[in]     name   String to add a copy of as key
 * \param[in]     value  String to add a copy of as value
 *
 * \note This asserts on invalid arguments or memory allocation failure.
 */
void
pcmk__insert_dup(GHashTable *table, const char *name, const char *value)
{
    pcmk__assert((table != NULL) && (name != NULL));

    g_hash_table_insert(table, pcmk__str_copy(name), pcmk__str_copy(value));
}

/* used with hash tables where case does not matter */
static gboolean
pcmk__strcase_equal(gconstpointer a, gconstpointer b)
{
    return pcmk__str_eq((const char *)a, (const char *)b, pcmk__str_casei);
}

static guint
pcmk__strcase_hash(gconstpointer v)
{
    const signed char *p;
    guint32 h = 0;

    for (p = v; *p != '\0'; p++)
        h = (h << 5) - h + g_ascii_tolower(*p);

    return h;
}

/*!
 * \internal
 * \brief Create a hash table with case-insensitive strings as keys
 *
 * \param[in] key_destroy_func    Function to free a key
 * \param[in] value_destroy_func  Function to free a value
 *
 * \return Newly allocated hash table
 * \note It is the caller's responsibility to free the result, using
 *       g_hash_table_destroy().
 */
GHashTable *
pcmk__strikey_table(GDestroyNotify key_destroy_func,
                    GDestroyNotify value_destroy_func)
{
    return g_hash_table_new_full(pcmk__strcase_hash, pcmk__strcase_equal,
                                 key_destroy_func, value_destroy_func);
}

static void
copy_str_table_entry(gpointer key, gpointer value, gpointer user_data)
{
    if (key && value && user_data) {
        pcmk__insert_dup((GHashTable *) user_data,
                         (const char *) key, (const char *) value);
    }
}

/*!
 * \internal
 * \brief Copy a hash table that uses dynamically allocated strings
 *
 * \param[in,out] old_table  Hash table to duplicate
 *
 * \return New hash table with copies of everything in \p old_table
 * \note This assumes the hash table uses dynamically allocated strings -- that
 *       is, both the key and value free functions are free().
 */
GHashTable *
pcmk__str_table_dup(GHashTable *old_table)
{
    GHashTable *new_table = NULL;

    if (old_table) {
        new_table = pcmk__strkey_table(free, free);
        g_hash_table_foreach(old_table, copy_str_table_entry, new_table);
    }
    return new_table;
}

/*!
 * \internal
 * \brief Add a word to a string list of words
 *
 * \param[in,out] list       Pointer to current string list (may not be \p NULL)
 * \param[in]     init_size  \p list will be initialized to at least this size,
 *                           if it needs initialization (if 0, use GLib's default
 *                           initial string size)
 * \param[in]     word       String to add to \p list (\p list will be
 *                           unchanged if this is \p NULL or the empty string)
 * \param[in]     separator  String to separate words in \p list
 *                           (a space will be used if this is NULL)
 *
 * \note \p word may contain \p separator, though that would be a bad idea if
 *       the string needs to be parsed later.
 */
void
pcmk__add_separated_word(GString **list, size_t init_size, const char *word,
                         const char *separator)
{
    pcmk__assert(list != NULL);

    if (pcmk__str_empty(word)) {
        return;
    }

    if (*list == NULL) {
        if (init_size > 0) {
            *list = g_string_sized_new(init_size);
        } else {
            *list = g_string_new(NULL);
        }
    }

    if ((*list)->len == 0) {
        // Don't add a separator before the first word in the list
        separator = "";

    } else if (separator == NULL) {
        // Default to space-separated
        separator = " ";
    }

    g_string_append(*list, separator);
    g_string_append(*list, word);
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

    compressed = pcmk__assert_alloc((size_t) max, sizeof(char));

    *result_len = max;
    rc = BZ2_bzBuffToBuffCompress(compressed, result_len, uncompressed, length,
                                  PCMK__BZ2_BLOCKS, 0, PCMK__BZ2_WORK);
    rc = pcmk__bzlib2rc(rc);

    free(uncompressed);

    if (rc != pcmk_rc_ok) {
        crm_err("Compression of %d bytes failed: %s " QB_XS " rc=%d",
                length, pcmk_rc_str(rc), rc);
        free(compressed);
        return rc;
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
    len = vasprintf(&string, format, ap);
    pcmk__assert(len > 0);
    va_end(ap);
    return string;
}

int
pcmk__parse_ll_range(const char *srcstring, long long *start, long long *end)
{
    char *remainder = NULL;
    int rc = pcmk_rc_ok;

    pcmk__assert((start != NULL) && (end != NULL));

    *start = PCMK__PARSE_INT_DEFAULT;
    // cppcheck doesn't understand the above pcmk__assert line
    // cppcheck-suppress ctunullpointer
    *end = PCMK__PARSE_INT_DEFAULT;

    crm_trace("Attempting to decode: [%s]", srcstring);
    if (pcmk__str_eq(srcstring, "", pcmk__str_null_matches)) {
        return ENODATA;
    } else if (pcmk__str_eq(srcstring, "-", pcmk__str_none)) {
        return pcmk_rc_bad_input;
    }

    /* String starts with a dash, so this is either a range with
     * no beginning or garbage.
     * */
    if (*srcstring == '-') {
        int rc = scan_ll(srcstring+1, end, PCMK__PARSE_INT_DEFAULT, &remainder);

        if ((rc == pcmk_rc_ok) && (*remainder != '\0')) {
            rc = pcmk_rc_bad_input;
        }
        return rc;
    }

    rc = scan_ll(srcstring, start, PCMK__PARSE_INT_DEFAULT, &remainder);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    if (*remainder && *remainder == '-') {
        if (*(remainder+1)) {
            char *more_remainder = NULL;
            int rc = scan_ll(remainder+1, end, PCMK__PARSE_INT_DEFAULT,
                             &more_remainder);

            if (rc != pcmk_rc_ok) {
                return rc;
            } else if (*more_remainder != '\0') {
                return pcmk_rc_bad_input;
            }
        }
    } else if (*remainder && *remainder != '-') {
        *start = PCMK__PARSE_INT_DEFAULT;
        return pcmk_rc_bad_input;
    } else {
        /* The input string contained only one number.  Set start and end
         * to the same value and return pcmk_rc_ok.  This gives the caller
         * a way to tell this condition apart from a range with no end.
         */
        *end = *start;
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Find a string in a list of strings
 *
 * \note This function takes the same flags and has the same behavior as
 *       pcmk__str_eq().
 *
 * \note No matter what input string or flags are provided, an empty
 *       list will always return FALSE.
 *
 * \param[in] s      String to search for
 * \param[in] lst    List to search
 * \param[in] flags  A bitfield of pcmk__str_flags to modify operation
 *
 * \return \c TRUE if \p s is in \p lst, or \c FALSE otherwise
 */
gboolean
pcmk__str_in_list(const gchar *s, const GList *lst, uint32_t flags)
{
    for (const GList *ele = lst; ele != NULL; ele = ele->next) {
        if (pcmk__str_eq(s, ele->data, flags)) {
            return TRUE;
        }
    }

    return FALSE;
}

static bool
str_any_of(const char *s, va_list args, uint32_t flags)
{
    if (s == NULL) {
        return false;
    }

    while (1) {
        const char *ele = va_arg(args, const char *);

        if (ele == NULL) {
            break;
        } else if (pcmk__str_eq(s, ele, flags)) {
            return true;
        }
    }

    return false;
}

/*!
 * \internal
 * \brief Is a string a member of a list of strings?
 *
 * \param[in]  s    String to search for in \p ...
 * \param[in]  ...  Strings to compare \p s against.  The final string
 *                  must be NULL.
 *
 * \note The comparison is done case-insensitively.  The function name is
 *       meant to be reminiscent of strcasecmp.
 *
 * \return \c true if \p s is in \p ..., or \c false otherwise
 */
bool
pcmk__strcase_any_of(const char *s, ...)
{
    va_list ap;
    bool rc;

    va_start(ap, s);
    rc = str_any_of(s, ap, pcmk__str_casei);
    va_end(ap);
    return rc;
}

/*!
 * \internal
 * \brief Is a string a member of a list of strings?
 *
 * \param[in]  s    String to search for in \p ...
 * \param[in]  ...  Strings to compare \p s against.  The final string
 *                  must be NULL.
 *
 * \note The comparison is done taking case into account.
 *
 * \return \c true if \p s is in \p ..., or \c false otherwise
 */
bool
pcmk__str_any_of(const char *s, ...)
{
    va_list ap;
    bool rc;

    va_start(ap, s);
    rc = str_any_of(s, ap, pcmk__str_none);
    va_end(ap);
    return rc;
}

/*!
 * \internal
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
pcmk__numeric_strcasecmp(const char *s1, const char *s2)
{
    pcmk__assert((s1 != NULL) && (s2 != NULL));

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

/*!
 * \internal
 * \brief Sort strings.
 *
 * This is your one-stop function for string comparison. By default, this
 * function works like \p g_strcmp0. That is, like \p strcmp but a \p NULL
 * string sorts before a non-<tt>NULL</tt> string.
 *
 * The \p pcmk__str_none flag produces the default behavior. Behavior can be
 * changed with various flags:
 *
 * - \p pcmk__str_regex - The second string is a regular expression that the
 *                        first string will be matched against.
 * - \p pcmk__str_casei - By default, comparisons are done taking case into
 *                        account. This flag makes comparisons case-
 *                        insensitive. This can be combined with
 *                        \p pcmk__str_regex.
 * - \p pcmk__str_null_matches - If one string is \p NULL and the other is not,
 *                               still return \p 0.
 * - \p pcmk__str_star_matches - If one string is \p "*" and the other is not,
 *                               still return \p 0.
 *
 * \param[in] s1     First string to compare
 * \param[in] s2     Second string to compare, or a regular expression to
 *                   match if \p pcmk__str_regex is set
 * \param[in] flags  A bitfield of \p pcmk__str_flags to modify operation
 *
 * \retval  negative \p s1 is \p NULL or comes before \p s2
 * \retval  0        \p s1 and \p s2 are equal, or \p s1 is found in \p s2 if
 *                   \c pcmk__str_regex is set
 * \retval  positive \p s2 is \p NULL or \p s1 comes after \p s2, or \p s2
 *                   is an invalid regular expression, or \p s1 was not found
 *                   in \p s2 if \p pcmk__str_regex is set.
 */
int
pcmk__strcmp(const char *s1, const char *s2, uint32_t flags)
{
    /* If this flag is set, the second string is a regex. */
    if (pcmk_is_set(flags, pcmk__str_regex)) {
        regex_t r_patt;
        int reg_flags = REG_EXTENDED | REG_NOSUB;
        int regcomp_rc = 0;
        int rc = 0;

        if (s1 == NULL || s2 == NULL) {
            return 1;
        }

        if (pcmk_is_set(flags, pcmk__str_casei)) {
            reg_flags |= REG_ICASE;
        }
        regcomp_rc = regcomp(&r_patt, s2, reg_flags);
        if (regcomp_rc != 0) {
            rc = 1;
            crm_err("Bad regex '%s' for update: %s", s2, strerror(regcomp_rc));
        } else {
            rc = regexec(&r_patt, s1, 0, NULL, 0);
            regfree(&r_patt);
            if (rc != 0) {
                rc = 1;
            }
        }
        return rc;
    }

    /* If the strings are the same pointer, return 0 immediately. */
    if (s1 == s2) {
        return 0;
    }

    /* If this flag is set, return 0 if either (or both) of the input strings
     * are NULL.  If neither one is NULL, we need to continue and compare
     * them normally.
     */
    if (pcmk_is_set(flags, pcmk__str_null_matches)) {
        if (s1 == NULL || s2 == NULL) {
            return 0;
        }
    }

    /* Handle the cases where one is NULL and the str_null_matches flag is not set.
     * A NULL string always sorts to the beginning.
     */
    if (s1 == NULL) {
        return -1;
    } else if (s2 == NULL) {
        return 1;
    }

    /* If this flag is set, return 0 if either (or both) of the input strings
     * are "*".  If neither one is, we need to continue and compare them
     * normally.
     */
    if (pcmk_is_set(flags, pcmk__str_star_matches)) {
        if (strcmp(s1, "*") == 0 || strcmp(s2, "*") == 0) {
            return 0;
        }
    }

    if (pcmk_is_set(flags, pcmk__str_casei)) {
        return strcasecmp(s1, s2);
    } else {
        return strcmp(s1, s2);
    }
}

/*!
 * \internal
 * \brief Copy a string, asserting on failure
 *
 * \param[in] file      File where \p function is located
 * \param[in] function  Calling function
 * \param[in] line      Line within \p file
 * \param[in] str       String to copy (can be \c NULL)
 *
 * \return Newly allocated copy of \p str, or \c NULL if \p str is \c NULL
 *
 * \note The caller is responsible for freeing the return value using \c free().
 */
char *
pcmk__str_copy_as(const char *file, const char *function, uint32_t line,
                  const char *str)
{
    if (str != NULL) {
        char *result = strdup(str);

        if (result == NULL) {
            crm_abort(file, function, line, "Out of memory", FALSE, TRUE);
            crm_exit(CRM_EX_OSERR);
        }
        return result;
    }
    return NULL;
}

/*!
 * \internal
 * \brief Update a dynamically allocated string with a new value
 *
 * Given a dynamically allocated string and a new value for it, if the string
 * is different from the new value, free the string and replace it with either a
 * newly allocated duplicate of the value or NULL as appropriate.
 *
 * \param[in,out] str    Pointer to dynamically allocated string
 * \param[in]     value  New value to duplicate (or NULL)
 *
 * \note The caller remains responsibile for freeing \p *str.
 */
void
pcmk__str_update(char **str, const char *value)
{
    if ((str != NULL) && !pcmk__str_eq(*str, value, pcmk__str_none)) {
        free(*str);
        *str = pcmk__str_copy(value);
    }
}

/*!
 * \internal
 * \brief Append a list of strings to a destination \p GString
 *
 * \param[in,out] buffer  Where to append the strings (must not be \p NULL)
 * \param[in]     ...     A <tt>NULL</tt>-terminated list of strings
 *
 * \note This tends to be more efficient than a single call to
 *       \p g_string_append_printf().
 */
void
pcmk__g_strcat(GString *buffer, ...)
{
    va_list ap;

    pcmk__assert(buffer != NULL);
    va_start(ap, buffer);

    while (true) {
        const char *ele = va_arg(ap, const char *);

        if (ele == NULL) {
            break;
        }
        g_string_append(buffer, ele);
    }
    va_end(ap);
}
