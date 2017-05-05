<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" encoding="UTF-8" indent="yes"/>

<xsl:template match="role_ref">
  <xsl:element name="role">
    <xsl:apply-templates select="@*|node()"/>
  </xsl:element>
</xsl:template>

<xsl:template match="read|write|deny">
  <xsl:element name="acl_permission">

    <xsl:copy-of select="@id"/>
    <xsl:attribute name="kind"><xsl:value-of select="name()"/></xsl:attribute>

    <xsl:if test="@ref">
      <xsl:attribute name="reference"><xsl:value-of select="@ref"/></xsl:attribute>
    </xsl:if>
    <xsl:if test="not(@ref)">
      <xsl:if test="@tag">
        <xsl:attribute name="object-type"><xsl:value-of select="@tag"/></xsl:attribute>
        <xsl:copy-of select="@attribute"/>
      </xsl:if>
    </xsl:if>

    <xsl:if test="@xpath">
      <xsl:copy-of select="@xpath"/>
    </xsl:if>

  </xsl:element>
</xsl:template>

<xsl:template match="acl_user[role_ref]">
  <!-- schema disallows role_ref's AND deny/read/write -->
  <xsl:element name="acl_target">
    <xsl:apply-templates select="@*|node()"/>
  </xsl:element>
</xsl:template>

<xsl:template match="acl_user[not(role_ref)]">

  <xsl:element name="acl_target">
    <xsl:apply-templates select="@*"/>

    <xsl:if test="count(deny|read|write)" > 
      <xsl:element name="role">
        <xsl:attribute name="id">
          <xsl:value-of select="concat('auto-', @id)"/>
        </xsl:attribute>
      </xsl:element>
    </xsl:if>

  </xsl:element>

  <xsl:if test="count(deny|read|write)" > 
    <xsl:element name="acl_role">
      <xsl:attribute name="id">
        <xsl:value-of select="concat('auto-', @id)"/>
      </xsl:attribute>
      <xsl:apply-templates select="*"/>
    </xsl:element>
  </xsl:if>

</xsl:template>

<xsl:template match="@*|*">
  <xsl:copy>
    <xsl:apply-templates select="@*|node()"/>
  </xsl:copy>
</xsl:template>

</xsl:stylesheet>
