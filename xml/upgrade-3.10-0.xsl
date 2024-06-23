<?xml version="1.0" encoding="UTF-8"?>

<!--
 Use comments liberally as future maintainers may be unfamiliar with XSLT.
 -->

<!--
 upgrade-3.10-0.xsl

 Guarantees after this transformation:
 -->

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:import href="upgrade-3.10-common.xsl"/>

<!-- Copy everything unaltered by default -->
<xsl:template match="/|@*|node()">
    <xsl:call-template name="identity"/>
</xsl:template>

</xsl:stylesheet>
