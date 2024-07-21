<?xml version="1.0" encoding="UTF-8"?>

<!--
 Use comments liberally as future maintainers may be unfamiliar with XSLT.
 -->

<!--
 upgrade-3.10-1.xsl

 Guarantees after this transformation:
 * The validate-with attribute of the cib element is set to "pacemaker-4.0".
 -->

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:import href="upgrade-3.10-common.xsl"/>

<!-- Copy everything unaltered by default -->
<xsl:template match="/|@*|node()">
    <xsl:call-template name="identity"/>
</xsl:template>

<!--
 Bump cib/@validate-with, or set it if not already set. Pacemaker does this, but
 doing it in the transformation is helpful for testing.
 -->
<xsl:template match="cib">
    <xsl:copy>
        <xsl:apply-templates select="@*"/>
        <xsl:attribute name="validate-with">pacemaker-4.0</xsl:attribute>
        <xsl:apply-templates select="node()"/>
    </xsl:copy>
</xsl:template>

</xsl:stylesheet>
