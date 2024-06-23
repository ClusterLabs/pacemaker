<?xml version="1.0" encoding="UTF-8"?>

<!--
 Use comments liberally as future maintainers may be unfamiliar with XSLT.
 -->

<!--
 upgrade-3.10-common.xsl

 This stylesheet is intended to be imported by all other stylesheets in the
 upgrade-3.10-* pipeline. It provides variables and templates that are used by
 multiple stylesheets.

 This file should not contain any templates with a match attribute.
 -->

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<!-- Strip whitespace-only text nodes but indent output -->
<xsl:strip-space elements="*"/>
<xsl:output encoding="UTF-8" indent="yes" omit-xml-declaration="yes"/>

<!-- Identity transformation: copy everything unaltered by default -->
<xsl:template name="identity">
    <xsl:copy>
        <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
</xsl:template>

</xsl:stylesheet>
