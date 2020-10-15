/*
 * Copyright 2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 *
 * Catch string comparisons where the pcmk__str_any_of function could be used
 * instead.  Note that we are only catching uses involving identifiers (not
 * expressions), but I think this is probably fine - we are likely not using
 * the same expression multiple times in a single line of code.  If some are
 * found, it's easy enough to add another block here.
 */

virtual internal

@ any_of_1 depends on internal @
expression test_str, str, new_str;
identifier I =~ "pcmk__str_none";
@@
- pcmk__str_eq(test_str, str, I) || pcmk__str_eq(test_str, new_str, I)
+ pcmk__str_any_of(test_str, str, new_str, NULL)

@ any_of_2 depends on internal @
expression test_str, str, new_str;
identifier I =~ "pcmk__str_casei";
@@
- pcmk__str_eq(test_str, str, I) || pcmk__str_eq(test_str, new_str, I)
+ pcmk__strcase_any_of(test_str, str, new_str, NULL)

@ any_of_3 depends on internal @
expression test_str, new_str;
expression list strs;
identifier I =~ "pcmk__str_none";
@@
- pcmk__str_any_of(test_str, strs, NULL) || pcmk__str_eq(test_str, new_str, I)
+ pcmk__str_any_of(test_str, strs, new_str, NULL)

@ any_of_4 depends on internal @
expression test_str, new_str;
expression list strs;
identifier I =~ "pcmk__str_casei";
@@
- pcmk__strcase_any_of(test_str, strs, NULL) || pcmk__str_eq(test_str, new_str, I)
+ pcmk__strcase_any_of(test_str, strs, new_str, NULL)

@ none_of_1 depends on internal @
expression test_str, str, new_str;
identifier I =~ "pcmk__str_none";
@@
- !pcmk__str_eq(test_str, str, I) && !pcmk__str_eq(test_str, new_str, I)
+ !pcmk__str_any_of(test_str, str, new_str, NULL)

@ none_of_2 depends on internal @
expression test_str, str, new_str;
identifier I =~ "pcmk__str_casei";
@@
- !pcmk__str_eq(test_str, str, I) && !pcmk__str_eq(test_str, new_str, I)
+ !pcmk__strcase_any_of(test_str, str, new_str, NULL)

@ none_of_3 depends on internal @
expression test_str, new_str;
expression list strs;
identifier I =~ "pcmk__str_none";
@@
- !pcmk__str_any_of(test_str, strs, NULL) && !pcmk__str_eq(test_str, new_str, I)
+ !pcmk__str_any_of(test_str, strs, new_str, NULL)

@ none_of_4 depends on internal @
expression test_str, new_str;
expression list strs;
identifier I =~ "pcmk__str_casei";
@@
- !pcmk__strcase_any_of(test_str, strs, NULL) && !pcmk__str_eq(test_str, new_str, I)
+ !pcmk__strcase_any_of(test_str, strs, new_str, NULL)
