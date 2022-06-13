/*
 * Copyright 2020-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/acl.h>
#include "../../crmcommon_private.h"

#include "mock_private.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

// THe index of the group that is going to be returned next from "get group entry" (getgrent)
static int group_idx = 0;

// Data used for testing
static const char* grp0_members[] = {
    "user0", "user1", NULL
};

static const char* grp1_members[] = {
    "user1", NULL
};

static const char* grp2_members[] = {
    "user2", "user1", NULL
};

// an array of "groups" (a struct from grp.h), the members of the groups are initalized here to some testing data.
// Casting away the consts to make the compiler happy and simplify initialization. 
// We never actually change these variables during the test!
// string literal = const char* (cannot be changed b/c ? ) vs. char* (its getting casted to this)
static const int NUM_GROUPS = 3;
static struct group groups[] = {
    {(char*)"grp0", (char*)"", 0, (char**)grp0_members},
    {(char*)"grp1", (char*)"", 1, (char**)grp1_members},
    {(char*)"grp2", (char*)"", 2, (char**)grp2_members},
};

// This function resets the group_idx to 0.
void
__wrap_setgrent(void) {
    group_idx = 0;
}

// This function returns the next group entry in the list of groups, or
// NULL if there aren't any left.
// group_idx is a global variable which keeps track of where you are in the list
struct group *
__wrap_getgrent(void) {
    if(group_idx >= NUM_GROUPS) return NULL;
    return &groups[group_idx++];
}

void
__wrap_endgrent(void) {
}

static void
is_pcmk__is_user_in_group(void **state)
{
    // null user
    assert_false(pcmk__is_user_in_group(NULL, "grp0"));
    // null group
    assert_false(pcmk__is_user_in_group("user0", NULL));
    // nonexistent group
    assert_false(pcmk__is_user_in_group("user0", "nonexistent_group"));
    // user is in group
    assert_true(pcmk__is_user_in_group("user0", "grp0"));
    // user is not in group
    assert_false(pcmk__is_user_in_group("user2", "grp0"));
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(is_pcmk__is_user_in_group)
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
