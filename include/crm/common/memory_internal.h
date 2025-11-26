/*
 * Copyright 2015-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_MEMORY_INTERNAL__H
#define PCMK__CRM_COMMON_MEMORY_INTERNAL__H

#include <stddef.h>                         // size_t
#include <stdint.h>                         // uint32_t
#include <stdlib.h>                         // abort, calloc, free, realloc

#include <glib.h>                           // FALSE, TRUE

#include <crm/common/results.h>             // CRM_EX_OSERR, crm_abort, crm_exit
#include <crm/common/results_internal.h>    // pcmk__assert

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \internal
 * \brief Abort without dumping core if a pointer is \c NULL
 *
 * This is intended to check for memory allocation failure, rather than for null
 * pointers in general.
 *
 * \param[in] ptr  Pointer to check
 */
#define pcmk__mem_assert(ptr) do {                                          \
        if ((ptr) == NULL) {                                                \
            crm_abort(__FILE__, __func__, __LINE__, "Out of memory", FALSE, \
                      TRUE);                                                \
            crm_exit(CRM_EX_OSERR);                                         \
        }                                                                   \
    } while (0)

/*!
 * \internal
 * \brief Allocate new zero-initialized memory, asserting on failure
 *
 * \param[in] file      File where \p function is located
 * \param[in] function  Calling function
 * \param[in] line      Line within \p file
 * \param[in] nmemb     Number of elements to allocate memory for
 * \param[in] size      Size of each element
 *
 * \return Newly allocated memory of of size <tt>nmemb * size</tt> (guaranteed
 *         not to be \c NULL)
 *
 * \note The caller is responsible for freeing the return value using \c free().
 */
static inline void *
pcmk__assert_alloc_as(const char *file, const char *function, uint32_t line,
                      size_t nmemb, size_t size)
{
    void *ptr = calloc(nmemb, size);

    if (ptr == NULL) {
        crm_abort(file, function, line, "Out of memory", FALSE, TRUE);
        crm_exit(CRM_EX_OSERR);
    }
    return ptr;
}

/*!
 * \internal
 * \brief Allocate new zero-initialized memory, asserting on failure
 *
 * \param[in] nmemb  Number of elements to allocate memory for
 * \param[in] size   Size of each element
 *
 * \return Newly allocated memory of of size <tt>nmemb * size</tt> (guaranteed
 *         not to be \c NULL)
 *
 * \note The caller is responsible for freeing the return value using \c free().
 */
#define pcmk__assert_alloc(nmemb, size) \
    pcmk__assert_alloc_as(__FILE__, __func__, __LINE__, nmemb, size)

/*!
 * \internal
 * \brief Resize a dynamically allocated memory block
 *
 * \param[in] ptr   Memory block to resize (or NULL to allocate new memory)
 * \param[in] size  New size of memory block in bytes (must be > 0)
 *
 * \return Pointer to resized memory block
 *
 * \note This asserts on error, so the result is guaranteed to be non-NULL
 *       (which is the main advantage of this over directly using realloc()).
 */
static inline void *
pcmk__realloc(void *ptr, size_t size)
{
    void *new_ptr;

    // realloc(p, 0) can replace free(p) but this wrapper can't
    pcmk__assert(size > 0);

    new_ptr = realloc(ptr, size);
    if (new_ptr == NULL) {
        free(ptr);
        abort();
    }
    return new_ptr;
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_MEMORY_INTERNAL__H
