/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/xml_internal.h>

static void
assert_sanitized(const char *str, const char *reference)
{
    char *buf = pcmk__str_copy(str);

    pcmk__xml_sanitize_id(buf);
    assert_string_equal(buf, reference);
    free(buf);
}

static void
null_empty(void **state)
{
    char *buf = pcmk__str_copy("");

    pcmk__assert_asserts(pcmk__xml_sanitize_id(NULL));
    pcmk__assert_asserts(pcmk__xml_sanitize_id(buf));

    free(buf);
}

static void
colon(void **state)
{
    const char *str = NULL;

    str = ":id";
    assert_sanitized(str, str);

    str = "i:d";
    assert_sanitized(str, str);

    str = "id:";
    assert_sanitized(str, str);
}

static void
underscore(void **state)
{
    const char *str = NULL;

    str = "_id";
    assert_sanitized(str, str);

    str = "i_d";
    assert_sanitized(str, str);

    str = "id_";
    assert_sanitized(str, str);
}

static void
hyphen(void **state)
{
    const char *str = NULL;

    str = "-id";
    assert_sanitized(str, "_id");

    str = "i-d";
    assert_sanitized(str, str);

    str = "id-";
    assert_sanitized(str, str);
}

static void
period(void **state)
{
    const char *str = NULL;

    str = ".id";
    assert_sanitized(str, "_id");

    str = "i.d";
    assert_sanitized(str, str);

    str = "id.";
    assert_sanitized(str, str);
}

static void
alpha(void **state)
{
    const char *str = NULL;

    str = "idd";
    assert_sanitized(str, str);

    str = "idD";
    assert_sanitized(str, str);

    str = "iDd";
    assert_sanitized(str, str);

    str = "iDD";
    assert_sanitized(str, str);

    str = "Idd";
    assert_sanitized(str, str);

    str = "IdD";
    assert_sanitized(str, str);

    str = "IDd";
    assert_sanitized(str, str);

    str = "IDD";
    assert_sanitized(str, str);
}

static void
digit(void **state)
{
    const char *str = NULL;

    str = "7id";
    assert_sanitized(str, "_id");

    str = "i7d";
    assert_sanitized(str, str);

    str = "id7";
    assert_sanitized(str, str);
}

static void
special(void **state)
{
    /* This isn't an exhaustive list of ASCII special characters anyway, so
     * don't bother testing each character in each position.
     */
    const char *ref = "_..";

    assert_sanitized("`~!", ref);
    assert_sanitized("@#$", ref);
    assert_sanitized("%^&", ref);
    assert_sanitized("*()", ref);
    assert_sanitized("=+/", ref);
    assert_sanitized("[]\\", ref);
    assert_sanitized("{}|", ref);
    assert_sanitized(";'\"", ref);
    assert_sanitized("<>?", ref);
    assert_sanitized(",\n\t", ref);
    assert_sanitized("\r\a ", ref);
    assert_sanitized("\x01\x02\x7F", ref);
}

static void
utf8_valid(void **state)
{
    const char *str = NULL;

    /* Check inside all ranges of valid characters (start, within, end).
     * Check as NameStartChar (if valid) and as NameChar.
     */

    // #xB7 (NameChar only)
    str = "_" "\xC2\xB7";           // #xB7
    assert_sanitized(str, str);

    // [#xC0-#xD6] (NameStartChar)
    str = "\xC3\x80";               // #xC0
    assert_sanitized(str, str);
    str = "_" "\xC3\x80";           // #xC0
    assert_sanitized(str, str);

    str = "\xC3\x90";               // #xD0
    assert_sanitized(str, str);
    str = "_" "\xC3\x90";           // #xD0
    assert_sanitized(str, str);

    str = "\xC3\x96";               // #xD6
    assert_sanitized(str, str);
    str = "_" "\xC3\x96";           // #xD6
    assert_sanitized(str, str);

    // [#xD8-#xF6] (NameStartChar)
    str = "\xC3\x98";               // #xD8
    assert_sanitized(str, str);
    str = "_" "\xC3\x98";           // #xD8
    assert_sanitized(str, str);

    str = "\xC3\xA0";               // #xE0
    assert_sanitized(str, str);
    str = "_" "\xC3\xA0";           // #xE0
    assert_sanitized(str, str);

    str = "\xC3\xB6";               // #xF6
    assert_sanitized(str, str);
    str = "_" "\xC3\xB6";           // #xF6
    assert_sanitized(str, str);

    // [#xF8-#x2FF] (NameStartChar)
    str = "\xC3\xB8";               // #xF8
    assert_sanitized(str, str);
    str = "_" "\xC3\xB8";           // #xF8
    assert_sanitized(str, str);

    str = "\xC4\x80";               // #x100
    assert_sanitized(str, str);
    str = "_" "\xC4\x80";           // #x100
    assert_sanitized(str, str);

    str = "\xCB\xBF";               // #x2FF
    assert_sanitized(str, str);
    str = "_" "\xCB\xBF";           // #x2FF
    assert_sanitized(str, str);

    // [#x300-#x36F] (NameChar only)
    str = "_" "\xCC\x80";           // #x300
    assert_sanitized(str, str);

    str = "_" "\xCC\xA0";           // #x320
    assert_sanitized(str, str);

    str = "_" "\xCD\xAF";           // #x36F
    assert_sanitized(str, str);

    // [#x370-#x37D] (NameStartChar)
    str = "\xCD\xB0";               // #x370
    assert_sanitized(str, str);
    str = "_" "\xCD\xB0";           // #x370
    assert_sanitized(str, str);

    str = "\xCD\xB8";               // #x378
    assert_sanitized(str, str);
    str = "_" "\xCD\xB8";           // #x378
    assert_sanitized(str, str);

    str = "\xCD\xBD";               // #x37D
    assert_sanitized(str, str);
    str = "_" "\xCD\xBD";           // #x37D
    assert_sanitized(str, str);

    // [#x37F-#x1FFF] (NameStartChar)
    str = "\xCD\xBF";               // #x37F
    assert_sanitized(str, str);
    str = "_" "\xCD\xBF";           // #x37F
    assert_sanitized(str, str);

    str = "\xE1\x80\x80";           // #x1000
    assert_sanitized(str, str);
    str = "_" "\xE1\x80\x80";       // #x1000
    assert_sanitized(str, str);

    str = "\xE1\xBF\xBF";           // #x1FFF
    assert_sanitized(str, str);
    str = "_" "\xE1\xBF\xBF";       // #x1FFF
    assert_sanitized(str, str);

    // [#x200C-#x200D] (NameStartChar)
    str = "\xE2\x80\x8C";           // #x200C
    assert_sanitized(str, str);
    str = "_" "\xE2\x80\x8C";       // #x200C
    assert_sanitized(str, str);

    str = "\xE2\x80\x8D";           // #x200D
    assert_sanitized(str, str);
    str = "_" "\xE2\x80\x8D";       // #x200D
    assert_sanitized(str, str);

    // [#x203F-#x2040] (NameChar only)
    str = "_" "\xE2\x80\xBF";       // #x203F
    assert_sanitized(str, str);

    str = "_" "\xE2\x81\x80";       // #x2040
    assert_sanitized(str, str);

    // [#x2070-#x218F] (NameStartChar)
    str = "\xE2\x81\xB0";           // #x2070
    assert_sanitized(str, str);
    str = "_" "\xE2\x81\xB0";       // #x2070
    assert_sanitized(str, str);

    str = "\xE2\x84\x80";           // #x2100
    assert_sanitized(str, str);
    str = "_" "\xE2\x84\x80";       // #x2100
    assert_sanitized(str, str);

    str = "\xE2\x86\x8F";           // #x218F
    assert_sanitized(str, str);
    str = "_" "\xE2\x86\x8F";       // #x218F
    assert_sanitized(str, str);

    // [#x2C00-#x2FEF] (NameStartChar)
    str = "\xE2\xB0\x80";           // #x2C00
    assert_sanitized(str, str);
    str = "_" "\xE2\xB0\x80";       // #x2C00
    assert_sanitized(str, str);

    str = "\xE2\xB4\x80";           // #x2D00
    assert_sanitized(str, str);
    str = "_" "\xE2\xB4\x80";       // #x2D00
    assert_sanitized(str, str);

    str = "\xE2\xBF\xAF";           // #x2FEF
    assert_sanitized(str, str);
    str = "_" "\xE2\xBF\xAF";       // #x2FEF
    assert_sanitized(str, str);

    // [#x3001-#xD7FF] (NameStartChar)
    str = "\xE3\x84\x80";           // #x3001
    assert_sanitized(str, str);
    str = "_" "\xE3\x84\x80";       // #x3001
    assert_sanitized(str, str);

    str = "\xEA\x80\x80";           // #xA000
    assert_sanitized(str, str);
    str = "_" "\xEA\x80\x80";       // #xA000
    assert_sanitized(str, str);

    str = "\xED\x9F\xBF";           // #xD7FF
    assert_sanitized(str, str);
    str = "_" "\xED\x9F\xBF";       // #xD7FF
    assert_sanitized(str, str);

    // [#xF900-#xFDCF] (NameStartChar)
    str = "\xEF\xA4\x80";           // #xF900
    assert_sanitized(str, str);
    str = "_" "\xEF\xA4\x80";       // #xF900
    assert_sanitized(str, str);

    str = "\xEF\xA8\x80";           // #xFA00
    assert_sanitized(str, str);
    str = "_" "\xEF\xA8\x80";       // #xFA00
    assert_sanitized(str, str);

    str = "\xEF\xB7\x8F";           // #xFDCF
    assert_sanitized(str, str);
    str = "_" "\xEF\xB7\x8F";       // #xFDCF
    assert_sanitized(str, str);

    // [#xFDF0-#xFFFD] (NameStartChar)
    str = "\xEF\xB7\xB0";           // #xFDF0
    assert_sanitized(str, str);
    str = "_" "\xEF\xB7\xB0";       // #xFDF0
    assert_sanitized(str, str);

    str = "\xEF\xB8\x80";           // #xFE00
    assert_sanitized(str, str);
    str = "_" "\xEF\xB8\x80";       // #xFE00
    assert_sanitized(str, str);

    str = "\xEF\xBF\xBD";           // #xFFFD
    assert_sanitized(str, str);
    str = "_" "\xEF\xBF\xBD";       // #xFFFD
    assert_sanitized(str, str);

    // [#x10000-#xEFFFF] (NameStartChar)
    str = "\xF0\x90\x80\x80";       // #x10000
    assert_sanitized(str, str);
    str = "_" "\xF0\x90\x80\x80";   // #x10000
    assert_sanitized(str, str);

    str = "\xF2\xA0\x80\x80";       // #xA0000
    assert_sanitized(str, str);
    str = "_" "\xF2\xA0\x80\x80";   // #xA0000
    assert_sanitized(str, str);

    str = "\xF3\xAF\xBF\xBF";       // #xEFFFF
    assert_sanitized(str, str);
    str = "_" "\xF3\xAF\xBF\xBF";   // #xEFFFF
    assert_sanitized(str, str);

    // Test with ASCII in string

    // First is NameStartChar
    str = "\xC3\x80" "a0";      // #xC0
    assert_sanitized(str, str);

    // Middle is NameStartChar
    str = "a" "\xC3\x80" "0";   // #xC0
    assert_sanitized(str, str);

    // Middle is NameChar but not NameStartChar
    str = "a" "\xC2\xB7" "0";   // #xB7
    assert_sanitized(str, str);

    // Last is NameStartChar
    str = "a0" "\xC3\x80";      // #xC0
    assert_sanitized(str, str);

    // Last is NameChar but not NameStartChar (tested with #xB7 earlier)

    // Test with multiple UTF-8 characters
    str = "\xCD\xB0" "\xC3\xB8" "\xE2\x80\xBF"; // #x370, #xF8, #x203F
    assert_sanitized(str, str);
}

static void
utf8_invalid(void **state)
{
    const char *str = NULL;

    /* Check outside all ranges of valid characters (before, after).
     * Check as NameStartChar and as NameChar (if invalid).
     * Check within range as NameStartChar if invalid in that context.
     */

    // #xB7 (NameChar only)
    str = "\xC2\xB7";               // #xB7
    assert_sanitized(str, "_.");

    // [#xC0-#xD6] (NameStartChar)
    str = "\xC2\xBF";               // #xBF
    assert_sanitized(str, "_.");
    str = "_" "\xC2\xBF";           // #xBF
    assert_sanitized(str, "_" "..");

    str = "\xC3\x97";               // #xD7
    assert_sanitized(str, "_.");
    str = "_" "\xC3\x97";           // #xD7
    assert_sanitized(str, "_" "..");

    // [#xD8-#xF6] (NameStartChar)
    // #xD7 tested above
    str = "\xC3\xB7";               // #xF7
    assert_sanitized(str, "_.");
    str = "_" "\xC3\xB7";           // #xF7
    assert_sanitized(str, "_" "..");

    // [#xF8-#x2FF] (NameStartChar)
    // #xF7 tested above
    // #x300 is a NameChar but not a NameStartChar
    str = "\xCC\x80";               // #x300
    assert_sanitized(str, "_.");

    // [#x300-#x36F] (NameChar only)
    // #x2FF is a NameStartChar, tested in utf8_valid()
    // #x370 is a NameStartChar, tested in utf8_valid()
    // #x300 is tested above as invalid NameStartChar
    str = "\xCC\xA0";               // #x320
    assert_sanitized(str, "_.");

    str = "\xCD\xAF";               // #x36F
    assert_sanitized(str, "_.");

    // [#x370-#x37D] (NameStartChar)
    // #x36F is a NameChar, tested above and in utf8_valid()
    str = "\xCD\xBE";               // #x37E
    assert_sanitized(str, "_.");
    str = "_" "\xCD\xBE";           // #x37E
    assert_sanitized(str, "_" "..");

    // [#x37F-#x1FFF] (NameStartChar)
    // #x37E tested above
    str = "\xE2\x80\x80";           // #x2000
    assert_sanitized(str, "_..");
    str = "_" "\xE2\x80\x80";       // #x2000
    assert_sanitized(str, "_" "...");

    // [#x200C-#x200D] (NameStartChar)
    str = "\xE2\x80\x8B";           // #x200B
    assert_sanitized(str, "_..");
    str = "_" "\xE2\x80\x8B";       // #x200B
    assert_sanitized(str, "_" "...");

    str = "\xE2\x80\x8E";           // #x200E
    assert_sanitized(str, "_..");
    str = "_" "\xE2\x80\x8E";       // #x200E
    assert_sanitized(str, "_" "...");

    // [#x203F-#x2040] (NameChar only)
    str = "\xE2\x80\xBE";           // #x203E
    assert_sanitized(str, "_..");
    str = "_" "\xE2\x80\xBE";       // #x203E
    assert_sanitized(str, "_" "...");

    str = "\xE2\x80\xBF";           // #x203F
    assert_sanitized(str, "_..");

    str = "\xE2\x81\x80";           // #x2040
    assert_sanitized(str, "_..");

    str = "\xE2\x81\x81";           // #x2041
    assert_sanitized(str, "_..");
    str = "_" "\xE2\x81\x81";       // #x2041
    assert_sanitized(str, "_" "...");

    // [#x2070-#x218F] (NameStartChar)
    str = "\xE2\x81\xAF";           // #x206F
    assert_sanitized(str, "_..");
    str = "_" "\xE2\x81\xAF";       // #x206F
    assert_sanitized(str, "_" "...");

    str = "\xE2\x86\x90";           // #x2190
    assert_sanitized(str, "_..");
    str = "_" "\xE2\x86\x90";       // #x2190
    assert_sanitized(str, "_" "...");

    // [#x2C00-#x2FEF] (NameStartChar)
    str = "\xE2\xAF\xBF";           // #x2BFF
    assert_sanitized(str, "_..");
    str = "_" "\xE2\xAF\xBF";       // #x2BFF
    assert_sanitized(str, "_" "...");

    str = "\xE2\xBF\xB0";           // #x2FF0
    assert_sanitized(str, "_..");
    str = "_" "\xE2\xBF\xB0";       // #x2FF0
    assert_sanitized(str, "_" "...");

    // [#x3001-#xD7FF] (NameStartChar)
    str = "\xE3\x80\x80";           // #x3000
    assert_sanitized(str, "_..");
    str = "_" "\xE3\x80\x80";       // #x3000
    assert_sanitized(str, "_" "...");

    str = "\xED\xA0\x80";           // #xD800
    assert_sanitized(str, "_..");
    str = "_"  "\xED\xA0\x80";      // #xD800
    assert_sanitized(str, "_" "...");

    // [#xF900-#xFDCF] (NameStartChar)
    str = "\xEF\xA3\xBF";           // #xF8FF
    assert_sanitized(str, "_..");
    str = "_" "\xEF\xA3\xBF";       // #xF8FF
    assert_sanitized(str, "_" "...");

    str = "\xEF\xB7\x90";           // #xFDD0
    assert_sanitized(str, "_..");
    str = "_" "\xEF\xB7\x90";       // #xFDD0
    assert_sanitized(str, "_" "...");

    // [#xFDF0-#xFFFD] (NameStartChar)
    str = "\xEF\xB7\xAF";           // #xFDF0
    assert_sanitized(str, "_..");
    str = "_" "\xEF\xB7\xAF";       // #xFDF0
    assert_sanitized(str, "_" "...");

    str = "\xEF\xBF\xBE";           // #xFFFE
    assert_sanitized(str, "_..");
    str = "_" "\xEF\xBF\xBE";       // #xFFFE
    assert_sanitized(str, "_" "...");

    /* [#x10000-#xEFFFF]
     * EF BF BF == FFFF, F3 B0 80 80 == F0000
     */
    str = "\xEF\xBF\xBF";           // #xFFFF
    assert_sanitized(str, "_..");
    str = "_" "\xEF\xBF\xBF";       // #xFFFF
    assert_sanitized(str, "_" "...");

    str = "\xF3\xB0\x80\x80";       // #xF0000
    assert_sanitized(str, "_...");
    str = "_" "\xF3\xB0\x80\x80";   // #xF0000
    assert_sanitized(str, "_" "....");

    // Test with ASCII in string

    // First is NameChar but not NameStartChar
    str = "\xC2\xB7" "a";           // #xB7
    assert_sanitized(str, "_." "a");

    // First is not NameChar
    str = "\xCD\xBE" "a";           // #x37E
    assert_sanitized(str, "_." "a");

    // Middle is not NameChar
    str = "a" "\xCD\xBE" "0";       // #x37E
    assert_sanitized(str, "a" ".." "0");

    // Last is not NameChar
    str = "a" "\xCD\xBE";           // #x37E
    assert_sanitized(str, "a" "..");

    // Test with multiple UTF-8 characters
    str = "\xC2\xB7" "\xCD\xBE" "\xF3\xB0\x80\x80"; // #xB7, #x37E, #xF0000
    assert_sanitized(str, "_." ".." "....");
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_empty),
                cmocka_unit_test(colon),
                cmocka_unit_test(underscore),
                cmocka_unit_test(hyphen),
                cmocka_unit_test(period),
                cmocka_unit_test(alpha),
                cmocka_unit_test(digit),
                cmocka_unit_test(special),
                cmocka_unit_test(utf8_valid),
                cmocka_unit_test(utf8_invalid));
