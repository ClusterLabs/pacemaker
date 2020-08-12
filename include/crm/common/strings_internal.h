/*
 * Copyright 2015-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__STRINGS_INTERNAL__H
#define PCMK__STRINGS_INTERNAL__H

#include <stdbool.h>            // bool

#include <glib.h>               // guint, GList, GHashTable

/* internal generic string functions (from strings.c) */

enum pcmk__str_flags {
    pcmk__str_none          = 0,
    pcmk__str_casei         = 1 << 0,
    pcmk__str_null_matches  = 1 << 1,
    pcmk__str_regex         = 1 << 2
};

int pcmk__guint_from_hash(GHashTable *table, const char *key, guint default_val,
                          guint *result);
bool pcmk__starts_with(const char *str, const char *prefix);
bool pcmk__ends_with(const char *s, const char *match);
bool pcmk__ends_with_ext(const char *s, const char *match);
char *pcmk__add_word(char *list, const char *word);
int pcmk__compress(const char *data, unsigned int length, unsigned int max,
                   char **result, unsigned int *result_len);

int pcmk__parse_ll_range(const char *srcstring, long long *start, long long *end);
gboolean pcmk__str_in_list(GList *lst, const gchar *s);

bool pcmk__strcase_any_of(const char *s, ...) G_GNUC_NULL_TERMINATED;
bool pcmk__str_any_of(const char *s, ...) G_GNUC_NULL_TERMINATED;

int pcmk__strcmp(const char *s1, const char *s2, uint32_t flags);

static inline bool
pcmk__str_eq(const char *s1, const char *s2, uint32_t flags)
{
    return pcmk__strcmp(s1, s2, flags) == 0;
}

/* Correctly displaying singular or plural is complicated; consider "1 node has"
 * vs. "2 nodes have". A flexible solution is to pluralize entire strings, e.g.
 *
 * if (a == 1) {
 *     crm_info("singular message"):
 * } else {
 *     crm_info("plural message");
 * }
 *
 * though even that's not sufficient for all languages besides English (if we
 * ever desire to do translations of output and log messages). But the following
 * convenience macros are "good enough" and more concise for many cases.
 */

/* Example:
 * crm_info("Found %d %s", nentries,
 *          pcmk__plural_alt(nentries, "entry", "entries"));
 */
#define pcmk__plural_alt(i, s1, s2) (((i) == 1)? (s1) : (s2))

// Example: crm_info("Found %d node%s", nnodes, pcmk__plural_s(nnodes));
#define pcmk__plural_s(i) pcmk__plural_alt(i, "", "s")

static inline int
pcmk__str_empty(const char *s)
{
    return (s == NULL) || (s[0] == '\0');
}

#endif /* PCMK__STRINGS_INTERNAL__H */
