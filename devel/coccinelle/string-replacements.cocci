/*
 * Copyright 2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 *
 * Catch string comparisons where the pcmk__str_eq function could be used
 * instead.  Note that we are only catching uses involving identifiers (not
 * expressions), but I think this is probably fine - we are likely not using
 * the same expression multiple times in a single line of code.  If some are
 * found, it's easy enough to add another block here.
 */

virtual internal

@ safe_str_neq_replacement depends on internal @
expression E1, E2;
@@
- safe_str_neq(E1, E2)
+ !pcmk__str_eq(E1, E2, pcmk__str_casei)

@ safe_str_eq_replacement_1 depends on internal @
expression E1, E2;
@@
- safe_str_eq(E1, E2)
+ pcmk__str_eq(E1, E2, pcmk__str_casei)

@ safe_str_eq_replacement_2 depends on internal @
expression E1, E2;
@@
- safe_str_eq(E1, E2) == FALSE
+ !pcmk__str_eq(E1, E2, pcmk__str_casei)

@ crm_str_eq_replacement_1 depends on internal @
expression E1, E2;
@@
- crm_str_eq(E1, E2, TRUE)
+ pcmk__str_eq(E1, E2, pcmk__str_none)

@ crm_str_eq_replacement_2 depends on internal @
expression E1, E2;
@@
- crm_str_eq(E1, E2, FALSE)
+ pcmk__str_eq(E1, E2, pcmk__str_casei)

@ crm_str_eq_replacement_3 depends on internal @
expression E1, E2;
@@
- crm_str_eq(E1, E2, TRUE) == FALSE
+ !pcmk__str_eq(E1, E2, pcmk__str_none)

@ crm_str_eq_replacement_4 depends on internal @
expression E1, E2;
@@
- crm_str_eq(E1, E2, FALSE) == FALSE
+ !pcmk__str_eq(E1, E2, pcmk__str_casei)
