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

</xsl:stylesheet>
