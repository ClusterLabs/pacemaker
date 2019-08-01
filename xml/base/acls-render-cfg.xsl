<!--
 Configuration for the ACLs visualization (as with cibadmin -L)
 ==============================================================

 To be deployed in Pacemaker configuration directory (normally /etc/pacemaker),
 but per-user configuration in "pacemaker" subdirectory of $XDG_CONFIG_HOME
 (normally ~/.config) takes a precedence when present.  To use that, just
 create that subdirectory and copy this file over, then adjust as needed.


 Minimal Guidance for the Configuration Format
 =============================================

 All that's needed is familiarity with XML[1] (how elements, attributes,
 and comment sections are constructed), then follow the hopefully intuitive
 commented out per-item configuration directives, that is, when you intend
 to override something, comment the respective part out (comment delimiters
 are on separate lines for convenience) and overwrite the value captured
 by the "select" element.

 Avoiding characters known to be sensitive in XML context is recommended,
 and should not be needed for the purpose at hand, anyway.

 Advanced use, which is intentionally not detailed here, comprises
 transitive "xsl:include" processing and some other tricks.


 Regarding Configuration of Color Codes to Be Emitted Respectively (c-*)
 =======================================================================

 Refer to https://en.wikipedia.org/wiki/ANSI_escape_code#3/4_bit.
 Note that we need to retain XML 1.0 (as opposed to 1.1, which in turn
 is not supported in libxml) compatibility in this very template, meaning
 we cannot output a superset of what's expressible in the template itself
 (escaped or not), hence we are forced to work that around for \x1b (ESC,
 unavoidable for ANSI colorized output) character with encoding it in some
 way (here using "\x1b" literal notation) and requiring a trivial
 "xsltproc ... | sed 's/\\x1b/\x1b/'" postprocessing (or client-side
 specific preprocessing when carried out programmatically).


 [1] https://www.w3.org/TR/xml/
 [2] https://www.w3.org/TR/1999/REC-xpath-19991116/
 [3] https://www.w3.org/TR/1999/REC-xslt-19991116

-->
<stylesheet version="1.0"
            xmlns="http://www.w3.org/1999/XSL/Transform"
            xmlns:aclrendercfg="http://clusterlabs.org/ns/pacemaker/acls-render-cfg">

<!--
  ANSI escape code encoded and escaped (see above) sequence for ...
 -->

<!-- ... writable entity (default: green, \x1b[32m) -->
<!--
<param name="aclrendercfg:c-writable">\x1b[32m</param>
-->

<!-- ... just readable entity (default: blue, \x1b[34m) -->
<!--
<param name="aclrendercfg:c-readable">\x1b[34m</param>
-->

<!-- ... completely denied entity (default: red, \x1b[31m) -->
<!--
<param name="aclrendercfg:c-denied">\x1b[31m</param>
-->

<!-- ... a final reset of the output at the end, for completeness (\x1b[0m) -->
<!--
<param name="aclrendercfg:c-reset">\x1b[0m</param>
-->

</stylesheet>
