/*
 * Copyright 2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 *
 * Catch string comparisons where the pcmk__str_empty function could be used
 * instead.  Note that we are only catching uses involving identifiers (not
 * expressions), but I think this is probably fine - we are likely not using
 * the same expression multiple times in a single line of code.  If some are
 * found, it's easy enough to add another block here.
 */

virtual internal

@ string_empty depends on internal @
type t;
identifier func !~ "pcmk__str_empty";
char* I;
@@
t func(...) {
...
(
- (I == NULL) || (strlen(I) == 0)
+ pcmk__str_empty(I)
|
- (I == NULL) || !strlen(I)
+ pcmk__str_empty(I)
|
- (I == NULL) || (I[0] == 0)
+ pcmk__str_empty(I)
|
- (I == NULL) || (*I == 0)
+ pcmk__str_empty(I)
|
- (I == NULL) || (I[0] == '\0')
+ pcmk__str_empty(I)
|
- (I == NULL) || (*I == '\0')
+ pcmk__str_empty(I)
)
...
}
