/*
 * Copyright 2015-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_FLAGS_INTERNAL__H
#define PCMK__CRM_COMMON_FLAGS_INTERNAL__H

#include <inttypes.h>                       // PRIx64
#include <stdbool.h>                        // bool
#include <stdint.h>                         // uint8_t, uint64_t

#include <crm/common/logging.h>             // do_crm_log_unlikely()
#include <crm/common/strings_internal.h>    // pcmk__s, pcmk__btoa

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \internal
 * \brief Set specified flags in a flag group
 *
 * \param[in] function    Function name of caller
 * \param[in] line        Line number of caller
 * \param[in] log_level   Log a message at this level
 * \param[in] flag_type   Label describing this flag group (for logging)
 * \param[in] target      Name of object whose flags these are (for logging)
 * \param[in] flag_group  Flag group being manipulated
 * \param[in] flags       Which flags in the group should be set
 * \param[in] flags_str   Readable equivalent of \p flags (for logging)
 *
 * \return Possibly modified flag group
 */
static inline uint64_t
pcmk__set_flags_as(const char *function, int line, uint8_t log_level,
                   const char *flag_type, const char *target,
                   uint64_t flag_group, uint64_t flags, const char *flags_str)
{
    uint64_t result = flag_group | flags;

    if (result != flag_group) {
        do_crm_log_unlikely(log_level,
                            "%s flags %#.8" PRIx64 " (%s) for %s set by %s:%d",
                            pcmk__s(flag_type, "Group of"), flags,
                            pcmk__s(flags_str, "flags"),
                            pcmk__s(target, "target"), function, line);
    }
    return result;
}

/*!
 * \internal
 * \brief Clear specified flags in a flag group
 *
 * \param[in] function    Function name of caller
 * \param[in] line        Line number of caller
 * \param[in] log_level   Log a message at this level
 * \param[in] flag_type   Label describing this flag group (for logging)
 * \param[in] target      Name of object whose flags these are (for logging)
 * \param[in] flag_group  Flag group being manipulated
 * \param[in] flags       Which flags in the group should be cleared
 * \param[in] flags_str   Readable equivalent of \p flags (for logging)
 *
 * \return Possibly modified flag group
 */
static inline uint64_t
pcmk__clear_flags_as(const char *function, int line, uint8_t log_level,
                     const char *flag_type, const char *target,
                     uint64_t flag_group, uint64_t flags, const char *flags_str)
{
    uint64_t result = flag_group & ~flags;

    if (result != flag_group) {
        do_crm_log_unlikely(log_level,
                            "%s flags %#.8" PRIx64
                            " (%s) for %s cleared by %s:%d",
                            pcmk__s(flag_type, "Group of"), flags,
                            pcmk__s(flags_str, "flags"),
                            pcmk__s(target, "target"), function, line);
    }
    return result;
}

/*!
 * \internal
 * \brief Check whether any of specified flags are set in a flag group
 *
 * \param[in] flag_group      Flag group to check whether \p flags_to_check are
 *                            set
 * \param[in] flags_to_check  Flags to check whether set in \p flag_group
 *
 * \retval \c true   if \p flags_to_check is nonzero and any of its flags are
 *                   set in \p flag_group
 * \retval \c false  otherwise
 */
static inline bool
pcmk__any_flags_set(uint64_t flag_group, uint64_t flags_to_check)
{
    return (flag_group & flags_to_check) != 0;
}

/*!
 * \internal
 * \brief Check whether all of specified flags are set in a flag group
 *
 * \param[in] flag_group      Flag group to check whether \p flags_to_check are
 *                            set
 * \param[in] flags_to_check  Flags to check whether set in \p flag_group
 *
 * \retval \c true   if all flags in \p flags_to_check are set in \p flag_group
 *                   or if \p flags_to_check is 0
 * \retval \c false  otherwise
 */
static inline bool
pcmk__all_flags_set(uint64_t flag_group, uint64_t flags_to_check)
{
    return (flag_group & flags_to_check) == flags_to_check;
}

/*!
 * \internal
 * \brief Convenience alias for \c pcmk__all_flags_set(), to check single flag
 *
 * This is truly identical to \c pcmk__all_flags_set() but allows a call that's
 * shorter and semantically clearer for checking a single flag.
 *
 * \param[in] flag_group  Flag group (check whether \p flag is set in this)
 * \param[in] flag        Flag (check whether this is set in \p flag_group)
 *
 * \retval \c true   if \p flag is set in \p flag_group or if \p flag is 0
 * \retval \c false  otherwise
 */
static inline bool
pcmk__is_set(uint64_t flag_group, uint64_t flag)
{
    return pcmk__all_flags_set(flag_group, flag);
}

/*!
 * \internal
 * \brief Get readable string for whether specified flags are set
 *
 * \param[in] flag_group    Group of flags to check
 * \param[in] flags         Which flags in \p flag_group should be checked
 *
 * \return "true" if all \p flags are set in \p flag_group, otherwise "false"
 */
static inline const char *
pcmk__flag_text(uint64_t flag_group, uint64_t flags)
{
    return pcmk__btoa(pcmk__all_flags_set(flag_group, flags));
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_FLAGS_INTERNAL__H
