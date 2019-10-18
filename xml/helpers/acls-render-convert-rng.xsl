<!--
 Copyright 2019 the Pacemaker project contributors

 The version control history for this file may have further details.

 Licensed under the GNU General Public License version 2 or later (GPLv2+).
 -->
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rng="http://relaxng.org/ns/structure/1.0"
  xmlns="http://relaxng.org/ns/structure/1.0">
<xsl:output method="xml" encoding="UTF-8" indent="yes" omit-xml-declaration="yes"/>

<xsl:param name="ns-full" select="'yes'"/>

<!-- drop these -->
<xsl:template match="@ns[. = '']"/>
<xsl:template match="@datatypeLibrary[. = '']"/>

<xsl:template match="rng:element[@name]">
  <xsl:copy>
    <xsl:apply-templates select="@*[name() != 'name']"/>
    <choice>
      <xsl:if test="$ns-full != 'yes'">
        <name ns=""><xsl:value-of select="@name"/></name>
      </xsl:if>
      <name ns="http://clusterlabs.org/ns/pacemaker/acl-2-writable">
        <xsl:value-of select="@name"/>
      </name>
      <name ns="http://clusterlabs.org/ns/pacemaker/acl-2-readable">
        <xsl:value-of select="@name"/>
      </name>
      <name ns="http://clusterlabs.org/ns/pacemaker/acl-2-denied">
        <xsl:value-of select="@name"/>
      </name>
    </choice>
    <xsl:apply-templates select="node()"/>
  </xsl:copy>
</xsl:template>

<xsl:template match="rng:attribute[not(.//rng:anyName)]">
  <xsl:copy>
    <xsl:apply-templates select="@*[name() != 'name']"/>
    <choice>
      <xsl:if test="$ns-full != 'yes'">
        <name ns=""><xsl:value-of select="@name"/></name>
      </xsl:if>
      <name ns="http://clusterlabs.org/ns/pacemaker/acl-2-writable">
        <xsl:value-of select="@name"/>
      </name>
      <name ns="http://clusterlabs.org/ns/pacemaker/acl-2-readable">
        <xsl:value-of select="@name"/>
      </name>
      <name ns="http://clusterlabs.org/ns/pacemaker/acl-2-denied">
        <xsl:value-of select="@name"/>
      </name>
    </choice>
    <xsl:apply-templates select="node()"/>
  </xsl:copy>
</xsl:template>

<xsl:template match="rng:attribute[
                       @name
                       and
                       rng:data[
                         (
                           @type='ID'
                           or
                           @type='IDREF'
                         )
                         and
                         @datatypeLibrary='http://www.w3.org/2001/XMLSchema-datatypes'
                       ]
                     ]">
  <xsl:copy>
    <xsl:apply-templates select="@*[name() != 'name']"/>
    <choice>
      <xsl:if test="$ns-full != 'yes'">
        <name ns=""><xsl:value-of select="@name"/></name>
      </xsl:if>
      <name ns="http://clusterlabs.org/ns/pacemaker/acl-2-writable">
        <xsl:value-of select="@name"/>
      </name>
      <name ns="http://clusterlabs.org/ns/pacemaker/acl-2-readable">
        <xsl:value-of select="@name"/>
      </name>
      <name ns="http://clusterlabs.org/ns/pacemaker/acl-2-denied">
        <xsl:value-of select="@name"/>
      </name>
    </choice>
    <xsl:for-each select="node()">
      <xsl:choose>
        <xsl:when test="self::rng:data[
                          @type='ID'
                          and
                          @datatypeLibrary='http://www.w3.org/2001/XMLSchema-datatypes'
                        ]">
          <xsl:copy>
            <xsl:attribute name="type">NCName</xsl:attribute>
            <xsl:apply-templates select="@*[name() != 'type']"/>
            <xsl:apply-templates select="node()"/>
          </xsl:copy>
        </xsl:when>
        <xsl:when test="self::rng:data[
                          @type='IDREF'
                          and
                          @datatypeLibrary='http://www.w3.org/2001/XMLSchema-datatypes'
                        ]">
          <xsl:copy>
            <xsl:attribute name="type">NCName</xsl:attribute>
            <xsl:apply-templates select="@*[name() != 'type']"/>
            <xsl:apply-templates select="node()"/>
          </xsl:copy>
        </xsl:when>
        <xsl:otherwise>
          <xsl:apply-templates select="."/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:for-each>
  </xsl:copy>
</xsl:template>

<xsl:template match="@*|node()">
  <xsl:copy>
    <xsl:apply-templates select="@*|node()"/>
  </xsl:copy>
</xsl:template>

</xsl:stylesheet>
