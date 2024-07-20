<?xml version="1.0" encoding="UTF-8"?>

<!--
 Use comments liberally as future maintainers may be unfamiliar with XSLT.
 -->

<!--
 upgrade-3.10-2.xsl

 Guarantees after this transformation:
 * Within a given nvset, there is at most one nvpair with a given name. If there
   were duplicates prior to this transformation, only the first one is kept.
 -->

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:import href="upgrade-3.10-common.xsl"/>

<!-- Copy everything unaltered by default -->
<xsl:template match="/|@*|node()">
    <xsl:call-template name="identity"/>
</xsl:template>


<!-- Name/value pairs -->

<!--
 Ensure there is at most one nvpair with a given name in a given nvset.

 By dropping the ignored duplicates now, we facilitate later transformations in
 which we drop nvpairs with certain values. The later steps will involve
 comparisons among multiple nvsets. These are easier to reason about and to
 regression-test if, prior to that, we drop all but one nvpair with a given name
 in a given nvset.
 -->

<!--
 Drop nvpairs with value="#default" if there is a later nvpair with the same
 name. Value "#default" unsets the option, so any later nvpair takes precedence.
-->
<xsl:template match="nvpair[(@value = '#default')
                            and (@name = following-sibling::*/@name)]"/>

<!--
 Drop nvpairs with a value other than "#default" if certain conditions (detailed
 below) are satisfied.
 -->
<xsl:template match="nvpair[@value != '#default']">
    <!-- All preceding sibling nvpairs with the same name -->
    <xsl:variable name="before"
                  select="preceding-sibling::nvpair[@name = current()/@name]"/>

    <!-- All following sibling nvpairs with the same name -->
    <xsl:variable name="after"
                  select="following-sibling::nvpair[@name = current()/@name]"/>

    <!--
     Last preceding sibling nvpair with the same name and value "#default"
     -->
    <xsl:variable name="last_default_before"
                  select="$before[@value = '#default'][last()]"/>

    <xsl:choose>
        <!--
         Drop if there's a following sibling with the same name and value
         "#default". The later "#default" value would unset the current nvpair's
         value.
         -->
        <xsl:when test="$after[@value = '#default']"/>

        <!--
         Drop if both:
         * There's a preceding sibling nvpair with the same name
         * Either of the following:
           * There's no preceding sibling nvpair with the same name and value
             "#default"
           * There's a preceding sibling nvpair with the same name between the
             most recent "#default" and the current node.

         The preceding sibling nvpair would take effect, and there is no
         "#default" value to unset it before we reach the current nvpair.

         This uses an XPath 1.0 set intersection idiom.
         -->
        <xsl:when test="$before
                        and (not($last_default_before)
                             or $last_default_before/following-sibling::nvpair
                                [count(.|$before) = count($before)])"/>

        <!-- Otherwise, keep the nvpair -->
        <xsl:otherwise>
            <xsl:call-template name="identity"/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>

</xsl:stylesheet>
