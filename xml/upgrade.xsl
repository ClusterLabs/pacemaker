<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
		xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method='xml' version='1.0' encoding='UTF-8' indent='yes'/>

<xsl:template match="status"/>

<xsl:template match="cib">
  <xsl:element name="{name()}">
    <xsl:apply-templates select="@*"/>
    <xsl:attribute name="validate-with">relax-ng</xsl:attribute>
    <xsl:apply-templates select="node()" />
  </xsl:element>
  <!--xsl:apply-templates/-->
</xsl:template>

<xsl:template match="/">
  <xsl:apply-templates select="@*"/>
  <xsl:apply-templates select="node()"/>
  <!--xsl:apply-templates/-->
</xsl:template>

<xsl:template match="@admin_epoch">
  <xsl:attribute name="admin-epoch">
    <xsl:value-of select="."/>
  </xsl:attribute>
</xsl:template>

<xsl:template match="@num_updates">
  <xsl:attribute name="num-updates">
    <xsl:value-of select="."/>
  </xsl:attribute>
</xsl:template>

<xsl:template match="@boolean_op">
  <xsl:attribute name="boolean-op">
    <xsl:value-of select="."/>
  </xsl:attribute>
</xsl:template>

<xsl:template match="@*">
  <xsl:attribute name="{name()}">
    <xsl:value-of select="."/>
  </xsl:attribute>
</xsl:template>

<xsl:template match="*">
  <xsl:element name="{name()}">
    <xsl:apply-templates select="@*"/>
    <xsl:apply-templates select="node()" />
  </xsl:element>
</xsl:template>

</xsl:stylesheet>
