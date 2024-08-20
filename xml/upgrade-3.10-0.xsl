<?xml version="1.0" encoding="UTF-8"?>

<!--
 Use comments liberally as future maintainers may be unfamiliar with XSLT.
 -->

<!--
 upgrade-3.10-0.xsl

 Guarantees after this transformation:
 * There are no elements with the id-ref attribute. If there were any prior to
   this transformation, they have been resolved as described in
   upgrade-3.10-common.xsl.
 -->

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:import href="upgrade-3.10-common.xsl"/>

<!-- Index all elements in the document on the id attribute -->
<xsl:key name="element_id" match="*" use="@id"/>

<!--
 Copy everything unaltered by default, except that we set "original"

 Params:
 * original: See identity template
 -->
<xsl:template match="/|@*|node()">
    <!-- Default original="1" if unspecified -->
    <xsl:param name="original" select="'1'"/>

    <xsl:call-template name="identity">
        <!-- If an element gets original="0", so do its descendants -->
        <xsl:with-param name="original" select="$original"/>
    </xsl:call-template>
</xsl:template>

<!--
 If an element has an id-ref attribute, resolve it to a copy of the referenced
 element, with original="0". See upgrade-3.10-common.xsl for details.
 -->
<xsl:template match="*[@id-ref]">
    <xsl:variable name="referenced" select="key('element_id', @id-ref)"/>

    <xsl:choose>
        <xsl:when test="self::nvpair and @name">
            <!--
             nvpair with id-ref and name is an undocumented feature that allows
             the same nvpair value to be used with multiple names (see commit
             3912538 and associated pull request). The reference's name
             attribute overrides the referenced element's name attribute.

             We convert an nvpair with id-ref and name to a new nvpair with a
             different id. At the end of the transformation pipeline, behavior
             is preserved, and there are no longer any nvpair elements with both
             id-ref and name.
             -->
            <xsl:copy>
                <xsl:apply-templates select="$referenced/@*"/>

                <xsl:attribute name="original">0</xsl:attribute>
                <xsl:attribute name="id">
                    <xsl:value-of select="concat($upgrade_prefix,
                                                 $referenced/@id, '-',
                                                 @name)"/>
                </xsl:attribute>
                <xsl:attribute name="name">
                    <xsl:value-of select="@name"/>
                </xsl:attribute>

                <xsl:apply-templates select="node()"/>
            </xsl:copy>
        </xsl:when>

        <xsl:otherwise>
            <xsl:apply-templates select="$referenced">
                <xsl:with-param name="original" select="'0'"/>
            </xsl:apply-templates>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>

</xsl:stylesheet>
