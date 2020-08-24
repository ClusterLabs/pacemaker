/*
 * Copyright 2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

/*
 * Always use __func__ (which is in the C99 standard) instead of __FUNCTION__
 * (which is an older GNU C extension)
 */

virtual internal

@ use_func @
@@
(
- __FUNCTION__
+ __func__
)
