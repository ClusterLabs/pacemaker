<?xml version="1.0" encoding="UTF-8"?>

<!--
 Use comments liberally as future maintainers may be unfamiliar with XSLT.
 -->

<!--
 upgrade-3.10-99.xsl

 Guarantees after this transformation:
 * All attributes of type ID are unique (assuming that was the case for the
   original input XML). Any elements with id-refs that were resolved in the
   first step of the transformation pipeline have been converted back to
   id-refs. See upgrade-3.10-common.xsl for details.

 This file is numbered 99 because it must be the last stylesheet in the
 pipeline. This numbering allows us to add more stylesheets without needing to
 continually rename this one. When all transformation development work is
 finished, we can re-number it.
 -->

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:import href="upgrade-3.10-common.xsl"/>

<!-- Copy everything unaltered by default -->
<xsl:template match="/|@*|node()">
    <xsl:call-template name="identity"/>
</xsl:template>

<!--
 If an element was converted from id-ref to the referenced element earlier in
 the upgrade transformation pipeline, convert it back to an id-ref as described
 in upgrade-3.10-common.xsl
 -->
<xsl:template match="*[@id]">
    <!--
     Convert to an id-ref if @original is 0 or unset and
     * there is any element with the same id value and original="1", or
     * there is any preceding element with the same id value

     The preceding axis doesn't include ancestors. While it would likely be
     nonsense to reference an ancestor, it is allowed by the schema.

     The idea for the second point is that if all elements with a given id value
     have original set to "0" or unset, the first one should remain a definition
     while the rest become references.
     -->
    <xsl:choose>
        <xsl:when test="not(number(@original))
                        and (//*[(@id = current()/@id) and number(@original)]
                             or preceding::*[@id = current()/@id]
                             or ancestor::*[@id = current()/@id])">
            <xsl:copy>
                <xsl:attribute name="id-ref">
                    <xsl:value-of select="@id"/>
                </xsl:attribute>
            </xsl:copy>
        </xsl:when>

        <xsl:otherwise>
            <xsl:call-template name="identity"/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>

<!-- Drop "original" attribute -->
<xsl:template match="@original"/>

</xsl:stylesheet>
