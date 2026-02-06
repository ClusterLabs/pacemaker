/*
 * Copyright 2015-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <strings_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_STRINGS_INTERNAL__H
#define PCMK__CRM_COMMON_STRINGS_INTERNAL__H

#include <stdbool.h>            // bool
#include <stdint.h>             // uint32_t, etc.

#include <glib.h>               // guint, GList, GHashTable

#include <crm/common/options.h> // PCMK_VALUE_TRUE, PCMK_VALUE_FALSE
#include <crm/common/results.h> // pcmk_rc_ok

#ifdef __cplusplus
extern "C" {
#endif

/* internal constants for generic string functions (from strings.c) */

#define PCMK__PARSE_INT_DEFAULT -1
#define PCMK__PARSE_DBL_DEFAULT -1.0

/* internal generic string functions (from strings.c) */

enum pcmk__str_flags {
    pcmk__str_none          = 0,
    pcmk__str_casei         = (UINT32_C(1) << 0),
    pcmk__str_null_matches  = (UINT32_C(1) << 1),
    pcmk__str_regex         = (UINT32_C(1) << 2),
    pcmk__str_star_matches  = (UINT32_C(1) << 3),
};

int pcmk__scan_double(const char *text, double *result,
                      const char *default_text, char **end_text);
int pcmk__guint_from_hash(GHashTable *table, const char *key, guint default_val,
                          guint *result);
void pcmk__add_separated_word(GString **list, size_t init_size,
                              const char *word, const char *separator);
int pcmk__compress(const char *data, unsigned int length, unsigned int max,
                   char **result, unsigned int *result_len);

int pcmk__scan_ll(const char *text, long long *result, long long default_value);
int pcmk__scan_min_int(const char *text, int *result, int minimum);
int pcmk__scan_port(const char *text, int *port);
int pcmk__parse_bool(const char *input, bool *result);
int pcmk__parse_ll_range(const char *text, long long *start, long long *end);
int pcmk__parse_ms(const char *input, long long *result);

/*!
 * \internal
 * \brief Check whether a string parses to \c true
 *
 * \param[in] input  Input string
 *
 * \retval \c true   if \p input is not \c NULL and \c pcmk__parse_bool() parses
 *                   it to \c true
 * \retval \c false  otherwise
 */
static inline bool
pcmk__is_true(const char *input)
{
    bool result = false;

    return (input != NULL) && (pcmk__parse_bool(input, &result) == pcmk_rc_ok)
           && result;
}

GHashTable *pcmk__strkey_table(GDestroyNotify key_destroy_func,
                               GDestroyNotify value_destroy_func);
GHashTable *pcmk__strikey_table(GDestroyNotify key_destroy_func,
                                GDestroyNotify value_destroy_func);
GHashTable *pcmk__str_table_dup(GHashTable *old_table);
void pcmk__insert_dup(GHashTable *table, const char *name, const char *value);

/*!
 * \internal
 * \brief Get a string value with a default if NULL
 *
 * \param[in] s              String to return if non-NULL
 * \param[in] default_value  String (or NULL) to return if \p s is NULL
 *
 * \return \p s if \p s is non-NULL, otherwise \p default_value
 */
static inline const char *
pcmk__s(const char *s, const char *default_value)
{
    return (s == NULL)? default_value : s;
}

/*!
 * \internal
 * \brief Create a hash table with integer keys
 *
 * \param[in] value_destroy_func  Function to free a value
 *
 * \return Newly allocated hash table
 * \note It is the caller's responsibility to free the result, using
 *       g_hash_table_destroy().
 */
static inline GHashTable *
pcmk__intkey_table(GDestroyNotify value_destroy_func)
{
    return g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                 value_destroy_func);
}

/*!
 * \internal
 * \brief Insert a value into a hash table with integer keys
 *
 * \param[in,out] hash_table  Table to insert into
 * \param[in]     key         Integer key to insert
 * \param[in]     value       Value to insert
 *
 * \return Whether the key/value was already in the table
 * \note This has the same semantics as g_hash_table_insert(). If the key
 *       already exists in the table, the old value is freed and replaced.
 */
static inline gboolean
pcmk__intkey_table_insert(GHashTable *hash_table, int key, gpointer value)
{
    return g_hash_table_insert(hash_table, GINT_TO_POINTER(key), value);
}

/*!
 * \internal
 * \brief Look up a value in a hash table with integer keys
 *
 * \param[in] hash_table  Table to check
 * \param[in] key         Integer key to look for
 *
 * \return Value in table for \key (or NULL if not found)
 */
static inline gpointer
pcmk__intkey_table_lookup(GHashTable *hash_table, int key)
{
    return g_hash_table_lookup(hash_table, GINT_TO_POINTER(key));
}

/*!
 * \internal
 * \brief Remove a key/value from a hash table with integer keys
 *
 * \param[in,out] hash_table  Table to modify
 * \param[in]     key         Integer key of entry to remove
 *
 * \return Whether \p key was found and removed from \p hash_table
 */
static inline gboolean
pcmk__intkey_table_remove(GHashTable *hash_table, int key)
{
    return g_hash_table_remove(hash_table, GINT_TO_POINTER(key));
}

bool pcmk__str_in_list(const char *str, const GList *list, uint32_t flags);
bool pcmk__g_strv_contains(const gchar *const *strv, const gchar *str);

bool pcmk__strcase_any_of(const char *s, ...) G_GNUC_NULL_TERMINATED;
bool pcmk__str_any_of(const char *s, ...) G_GNUC_NULL_TERMINATED;
bool pcmk__char_in_any_str(int ch, ...) G_GNUC_NULL_TERMINATED;

int pcmk__strcmp(const char *s1, const char *s2, uint32_t flags);
int pcmk__numeric_strcasecmp(const char *s1, const char *s2);

char *pcmk__str_copy_as(const char *file, const char *function, uint32_t line,
                        const char *str);

/*!
 * \internal
 * \brief Copy a string, asserting on failure
 *
 * \param[in] str  String to copy (can be \c NULL)
 *
 * \return Newly allocated copy of \p str, or \c NULL if \p str is \c NULL
 *
 * \note The caller is responsible for freeing the return value using \c free().
 */
#define pcmk__str_copy(str) pcmk__str_copy_as(__FILE__, __func__, __LINE__, str)

void pcmk__str_update(char **str, const char *value);

char *pcmk__assert_asprintf(const char *format, ...) G_GNUC_PRINTF(1, 2);

void pcmk__g_strcat(GString *buffer, ...) G_GNUC_NULL_TERMINATED;

static inline bool
pcmk__str_eq(const char *s1, const char *s2, uint32_t flags)
{
    return pcmk__strcmp(s1, s2, flags) == 0;
}

// Like pcmk__add_separated_word() but using a space as separator
static inline void
pcmk__add_word(GString **list, size_t init_size, const char *word)
{
    return pcmk__add_separated_word(list, init_size, word, " ");
}

/* Correctly displaying singular or plural is complicated; consider "1 node has"
 * vs. "2 nodes have". A flexible solution is to pluralize entire strings, e.g.
 *
 * if (a == 1) {
 *     pcmk__info("singular message"):
 * } else {
 *     pcmk__info("plural message");
 * }
 *
 * though even that's not sufficient for all languages besides English (if we
 * ever desire to do translations of output and log messages). But the following
 * convenience macros are "good enough" and more concise for many cases.
 */

/* Example:
 * pcmk__info("Found %d %s", nentries,
 *            pcmk__plural_alt(nentries, "entry", "entries"));
 */
#define pcmk__plural_alt(i, s1, s2) (((i) == 1)? (s1) : (s2))

// Example: pcmk__info("Found %d node%s", nnodes, pcmk__plural_s(nnodes));
#define pcmk__plural_s(i) pcmk__plural_alt(i, "", "s")

static inline int
pcmk__str_empty(const char *s)
{
    return (s == NULL) || (s[0] == '\0');
}

static inline char *
pcmk__itoa(int an_int)
{
    return pcmk__assert_asprintf("%d", an_int);
}

static inline char *
pcmk__ftoa(double a_float)
{
    return pcmk__assert_asprintf("%f", a_float);
}

static inline char *
pcmk__ttoa(time_t epoch_time)
{
    return pcmk__assert_asprintf("%lld", (long long) epoch_time);
}

// note this returns const not allocated
static inline const char *
pcmk__btoa(bool condition)
{
    return condition? PCMK_VALUE_TRUE : PCMK_VALUE_FALSE;
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_STRINGS_INTERNAL__H
