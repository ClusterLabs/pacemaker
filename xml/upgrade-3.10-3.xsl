<?xml version="1.0" encoding="UTF-8"?>

<!--
 Use comments liberally as future maintainers may be unfamiliar with XSLT.
-->

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<!-- Strip whitespace-only text nodes but indent output -->
<xsl:strip-space elements="*"/>
<xsl:output encoding="UTF-8" indent="yes" omit-xml-declaration="yes"/>

<!-- Copy everything unaltered by default -->
<xsl:template match="/|@*|node()">
    <xsl:copy>
        <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
</xsl:template>

<!-- Index all resources by id -->
<xsl:key name="rsc_id" match="template|primitive|group|clone|master|bundle"
         use="@id"/>

<!-- Drop constraints that reference nonexistent resources -->
<xsl:template match="constraints">
    <xsl:copy>
        <xsl:for-each select="@*|node()">
            <xsl:variable name="set_idref"
                          select="resource_set/resource_ref/@id"/>
            <xsl:choose>
                <xsl:when test="@rsc and not(key('rsc_id', @rsc))"/>
                <xsl:when test="@with-rsc and not(key('rsc_id', @with-rsc))"/>
                <xsl:when test="@first and not(key('rsc_id', @first))"/>
                <xsl:when test="@then and not(key('rsc_id', @then))"/>
                <xsl:when test="count(key('rsc_id', $set_idref))
                                != count($set_idref)"/>
                <xsl:otherwise>
                    <xsl:apply-templates select="."/>
                </xsl:otherwise>
            </xsl:choose>
        </xsl:for-each>
    </xsl:copy>
</xsl:template>

</xsl:stylesheet>
