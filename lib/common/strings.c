/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <bzlib.h>
#include <sys/types.h>

char *
crm_concat(const char *prefix, const char *suffix, char join)
{
    int len = 0;
    char *new_str = NULL;

    CRM_ASSERT(prefix != NULL);
    CRM_ASSERT(suffix != NULL);
    len = strlen(prefix) + strlen(suffix) + 2;

    new_str = malloc(len);
    if(new_str) {
        sprintf(new_str, "%s%c%s", prefix, join, suffix);
        new_str[len - 1] = 0;
    }
    return new_str;
}

char *
crm_itoa_stack(int an_int, char *buffer, size_t len)
{
    if (buffer != NULL) {
        snprintf(buffer, len, "%d", an_int);
    }

    return buffer;
}

char *
crm_itoa(int an_int)
{
    int len = 32;
    char *buffer = NULL;

    buffer = malloc(len + 1);
    if (buffer != NULL) {
        snprintf(buffer, len, "%d", an_int);
    }

    return buffer;
}

void
g_hash_destroy_str(gpointer data)
{
    free(data);
}

long long
crm_int_helper(const char *text, char **end_text)
{
    long long result = -1;
    char *local_end_text = NULL;
    int saved_errno = 0;

    errno = 0;

    if (text != NULL) {
#ifdef ANSI_ONLY
        if (end_text != NULL) {
            result = strtol(text, end_text, 10);
        } else {
            result = strtol(text, &local_end_text, 10);
        }
#else
        if (end_text != NULL) {
            result = strtoll(text, end_text, 10);
        } else {
            result = strtoll(text, &local_end_text, 10);
        }
#endif

        saved_errno = errno;
        if (errno == EINVAL) {
            crm_err("Conversion of %s failed", text);
            result = -1;

        } else if (errno == ERANGE) {
            crm_err("Conversion of %s was clipped: %lld", text, result);

        } else if (errno != 0) {
            crm_perror(LOG_ERR, "Conversion of %s failed:", text);
        }

        if (local_end_text != NULL && local_end_text[0] != '\0') {
            crm_err("Characters left over after parsing '%s': '%s'", text, local_end_text);
        }

        errno = saved_errno;
    }
    return result;
}

int
crm_parse_int(const char *text, const char *default_text)
{
    int atoi_result = -1;

    if (text != NULL) {
        atoi_result = crm_int_helper(text, NULL);
        if (errno == 0) {
            return atoi_result;
        }
    }

    if (default_text != NULL) {
        atoi_result = crm_int_helper(default_text, NULL);
        if (errno == 0) {
            return atoi_result;
        }

    } else {
        crm_err("No default conversion value supplied");
    }

    return -1;
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
 * \internal
 * \brief Check whether a string ends with a certain sequence
 *
 * \param[in] s      String to check
 * \param[in] match  Sequence to match against end of s
 *
 * \return TRUE if s ends with match, FALSE otherwise
 */
gboolean
crm_ends_with(const char *s, const char *match)
{
    if ((s == NULL) || (match == NULL)) {
        return FALSE;
    } else {
        size_t slen = strlen(s);
        size_t mlen = strlen(match);

        return ((slen >= mlen) && !strcmp(s + slen - mlen, match));
    }
}

/*
 * This re-implements g_str_hash as it was prior to glib2-2.28:
 *
 *   http://git.gnome.org/browse/glib/commit/?id=354d655ba8a54b754cb5a3efb42767327775696c
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

guint
crm_strcase_hash(gconstpointer v)
{
    const signed char *p;
    guint32 h = 0;

    for (p = v; *p != '\0'; p++)
        h = (h << 5) - h + g_ascii_tolower(*p);

    return h;
}

char *
add_list_element(char *list, const char *value)
{
    int len = 0;
    int last = 0;

    if (value == NULL) {
        return list;
    }
    if (list) {
        last = strlen(list);
    }
    len = last + 2;             /* +1 space, +1 EOS */
    len += strlen(value);
    list = realloc_safe(list, len);
    sprintf(list + last, " %s", value);
    return list;
}

bool
crm_compress_string(const char *data, int length, int max, char **result, unsigned int *result_len)
{
    int rc;
    char *compressed = NULL;
    char *uncompressed = strdup(data);
    struct timespec after_t;
    struct timespec before_t;

    if(max == 0) {
        max = (length * 1.1) + 600; /* recomended size */
    }

#ifdef CLOCK_MONOTONIC
    clock_gettime(CLOCK_MONOTONIC, &before_t);
#endif

    /* coverity[returned_null] Ignore */
    compressed = malloc(max);

    *result_len = max;
    rc = BZ2_bzBuffToBuffCompress(compressed, result_len, uncompressed, length, CRM_BZ2_BLOCKS, 0,
                                  CRM_BZ2_WORK);

    free(uncompressed);

    if (rc != BZ_OK) {
        crm_err("Compression of %d bytes failed: %s (%d)", length, bz2_strerror(rc), rc);
        free(compressed);
        return FALSE;
    }

#ifdef CLOCK_MONOTONIC
    clock_gettime(CLOCK_MONOTONIC, &after_t);

    crm_info("Compressed %d bytes into %d (ratio %d:1) in %dms",
             length, *result_len, length / (*result_len),
             (after_t.tv_sec - before_t.tv_sec) * 1000 + (after_t.tv_nsec -
                                                          before_t.tv_nsec) / 1000000);
#else
    crm_info("Compressed %d bytes into %d (ratio %d:1)",
             length, *result_len, length / (*result_len));
#endif

    *result = compressed;
    return TRUE;
}
