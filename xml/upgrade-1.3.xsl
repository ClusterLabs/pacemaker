<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
		xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
		xmlns:fn="http://www.w3.org/2005/02/xpath-functions">
<xsl:output method='xml' version='1.0' encoding='UTF-8' indent='yes'/>

<xsl:template match="role_ref">
  <xsl:element name="role">
    <xsl:apply-templates select="@*"/>
    <xsl:apply-templates select="node()" />
  </xsl:element>
</xsl:template>

<xsl:template match="read|write|deny">
  <xsl:element name="acl_permission">

    <xsl:attribute name="id"><xsl:value-of select="@id"/></xsl:attribute>
    <xsl:attribute name="kind"><xsl:value-of select="name()"/></xsl:attribute>

    <xsl:if test="@ref">
      <xsl:attribute name="reference"><xsl:value-of select="@ref"/></xsl:attribute>
      <xsl:if test="@attribute">
	<xsl:attribute name="attribute"><xsl:value-of select="@attribute"/></xsl:attribute>
      </xsl:if>
    </xsl:if>
    <xsl:if test="not(@ref)">
      <xsl:if test="@tag">
	<xsl:attribute name="object-type"><xsl:value-of select="@tag"/></xsl:attribute>
      </xsl:if>
    </xsl:if>

    <xsl:if test="@xpath">
      <xsl:attribute name="xpath"><xsl:value-of select="@xpath"/></xsl:attribute>
    </xsl:if>

  </xsl:element>
</xsl:template>

<xsl:template match="acl_user[role_ref]">
  <!-- schema disallows role_ref's AND deny/reda/write -->
  <xsl:element name="acl_target">
    <xsl:apply-templates select="@*"/>
    <xsl:apply-templates select="node()" />
  </xsl:element>
</xsl:template>

<xsl:template match="acl_user[not(role_ref)]">

  <xsl:element name="acl_target">
    <xsl:for-each select="@*"> 
      <xsl:apply-templates select="."/>
    </xsl:for-each>

    <xsl:if test="count(deny|read|write)" > 
      <xsl:element name="role">
	<xsl:attribute name="id">
	  <xsl:text>auto-</xsl:text>
	  <xsl:value-of select="@id"/>
	</xsl:attribute>
      </xsl:element>
    </xsl:if>

  </xsl:element>

  <xsl:if test="count(deny|read|write)" > 
    <xsl:element name="acl_role">
      <xsl:attribute name="id">
	<xsl:text>auto-</xsl:text>
	<xsl:value-of select="@id"/>
      </xsl:attribute>
      <xsl:for-each select="node()"> 
	<xsl:choose>
	  <xsl:when test="starts-with(name(), 'role_ref')"/>
	  <xsl:otherwise>
	    <xsl:apply-templates select="."/>
	  </xsl:otherwise>
	</xsl:choose>
      </xsl:for-each>
    </xsl:element>
  </xsl:if>

</xsl:template>

<xsl:template match="@*">
  <xsl:attribute name="{name()}">
    <xsl:value-of select="."/>
  </xsl:attribute>
</xsl:template>

<xsl:template match="/">
  <xsl:apply-templates select="@*"/>
  <xsl:apply-templates select="node()"/>
</xsl:template>

<xsl:template match="*">
  <xsl:element name="{name()}">
    <xsl:apply-templates select="@*"/>
    <xsl:apply-templates select="node()" />
  </xsl:element>
</xsl:template>

</xsl:stylesheet>
