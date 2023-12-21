/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_UTIL_COMPAT__H
#  define PCMK__CRM_COMMON_UTIL_COMPAT__H

#  include <glib.h>
#  include <libxml/tree.h>
#  include <crm/common/util.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker utilities
 * \ingroup core
 * \deprecated Do not include this header directly. The utilities in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Do not use
#define crm_get_interval crm_parse_interval_spec

//! \deprecated Do not use
#define CRM_DEFAULT_OP_TIMEOUT_S "20s"

//! \deprecated Use !pcmk_is_set() or !pcmk_all_flags_set() instead
static inline gboolean
is_not_set(long long word, long long bit)
{
    return ((word & bit) == 0);
}

//! \deprecated Use pcmk_is_set() or pcmk_all_flags_set() instead
static inline gboolean
is_set(long long word, long long bit)
{
    return ((word & bit) == bit);
}

//! \deprecated Use pcmk_any_flags_set() instead
static inline gboolean
is_set_any(long long word, long long bit)
{
    return ((word & bit) != 0);
}

//! \deprecated Use strcmp() or strcasecmp() instead
gboolean crm_str_eq(const char *a, const char *b, gboolean use_case);

//! \deprecated Use strcmp() instead
gboolean safe_str_neq(const char *a, const char *b);

//! \deprecated Use strcasecmp() instead
#define safe_str_eq(a, b) crm_str_eq(a, b, FALSE)

//! \deprecated Use snprintf() instead
char *crm_itoa_stack(int an_int, char *buf, size_t len);

//! \deprecated Use sscanf() instead
int pcmk_scan_nvpair(const char *input, char **name, char **value);

//! \deprecated Use a standard printf()-style function instead
char *pcmk_format_nvpair(const char *name, const char *value,
                         const char *units);

//! \deprecated Use \c crm_xml_add() or \c xml_remove_prop() instead
const char *crm_xml_replace(xmlNode *node, const char *name, const char *value);

//! \deprecated Use a standard printf()-style function instead
char *pcmk_format_named_time(const char *name, time_t epoch_time);

//! \deprecated Use strtoll() instead
long long crm_parse_ll(const char *text, const char *default_text);

//! \deprecated Use strtoll() instead
int crm_parse_int(const char *text, const char *default_text);

//! \deprecated Use strtoll() instead
#  define crm_atoi(text, default_text) crm_parse_int(text, default_text)

//! \deprecated Use g_str_hash() instead
guint g_str_hash_traditional(gconstpointer v);

//! \deprecated Use g_str_hash() instead
#define crm_str_hash g_str_hash_traditional

//! \deprecated Do not use Pacemaker for generic string comparison
gboolean crm_strcase_equal(gconstpointer a, gconstpointer b);

//! \deprecated Do not use Pacemaker for generic string manipulation
guint crm_strcase_hash(gconstpointer v);

//! \deprecated Use g_hash_table_new_full() instead
static inline GHashTable *
crm_str_table_new(void)
{
    return g_hash_table_new_full(crm_str_hash, g_str_equal, free, free);
}

//! \deprecated Use g_hash_table_new_full() instead
static inline GHashTable *
crm_strcase_table_new(void)
{
    return g_hash_table_new_full(crm_strcase_hash, crm_strcase_equal,
                                 free, free);
}

//! \deprecated Do not use Pacemaker for generic hash table manipulation
GHashTable *crm_str_table_dup(GHashTable *old_table);

//! \deprecated Use g_hash_able_size() instead
static inline guint
crm_hash_table_size(GHashTable *hashtable)
{
    if (hashtable == NULL) {
        return 0;
    }
    return g_hash_table_size(hashtable);
}

//! \deprecated Don't use Pacemaker for string manipulation
char *crm_strip_trailing_newline(char *str);

//! \deprecated Don't use Pacemaker for string manipulation
int pcmk_numeric_strcasecmp(const char *s1, const char *s2);

//! \deprecated Don't use Pacemaker for string manipulation
static inline char *
crm_itoa(int an_int)
{
    return crm_strdup_printf("%d", an_int);
}

//! \deprecated Don't use Pacemaker for string manipulation
static inline char *
crm_ftoa(double a_float)
{
    return crm_strdup_printf("%f", a_float);
}

//! \deprecated Don't use Pacemaker for string manipulation
static inline char *
crm_ttoa(time_t epoch_time)
{
    return crm_strdup_printf("%lld", (long long) epoch_time);
}

//! \deprecated Do not use Pacemaker libraries for generic I/O
void crm_build_path(const char *path_c, mode_t mode);

//! \deprecated Use pcmk_readable_score() instead
char *score2char(int score);

//! \deprecated Use pcmk_readable_score() instead
char *score2char_stack(int score, char *buf, size_t len);

//! \deprecated Do not use
guint crm_parse_interval_spec(const char *input);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_UTIL_COMPAT__H
