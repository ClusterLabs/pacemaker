<!--
 Copyright 2018 Red Hat, Inc.
 Author: Jan Pokorny <jpokorny@redhat.com>
 Part of pacemaker project
 SPDX-License-Identifier: GPL-2.0-or-later
 -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:cibtr-2="http://clusterlabs.org/ns/pacemaker/cibtr-2">
<xsl:output method="text" encoding="UTF-8"/>

<xsl:variable name="NL" select="'&#xA;'"/>

<xsl:template name="MapMsg-2">
  <xsl:param name="Replacement"/>
  <xsl:choose>
    <xsl:when test="not($Replacement)"/>
    <xsl:when test="count($Replacement) != 1">
      <xsl:message terminate="yes">
        <xsl:value-of select="concat('INTERNAL ERROR:',
                                     $Replacement/../@msg-prefix,
                                     ': count($Replacement) != 1',
                                     ' does not hold (',
                                     count($Replacement), ')')"/>
      </xsl:message>
    </xsl:when>
    <xsl:otherwise>
      <cibtr-2:noop>
        <xsl:choose>
          <xsl:when test="string($Replacement/@with)">
            <xsl:choose>
              <xsl:when test="string($Replacement/@where)">
                <xsl:if test="not(
                                contains(
                                  concat('|', $Replacement/../@where-cases, '|'),
                                  concat('|', $Replacement/@where, '|')
                                )
                              )">
                  <xsl:message terminate="yes">
                    <xsl:value-of select="concat('INTERNAL ERROR:',
                                                 $Replacement/../@msg-prefix,
                                                 ': $Replacement/@where (',
                                                 $Replacement/@where, ') not in ',
                                                 concat('|',
                                                 $Replacement/../@where-cases,
                                                 '|'))"/>
                  </xsl:message>
                </xsl:if>
                <xsl:value-of select="concat('moving ', $Replacement/@what,
                                             ' under ', $Replacement/@where)"/>
              </xsl:when>
              <xsl:when test="$Replacement/@with = $Replacement/@what">
                <xsl:value-of select="concat('keeping ', $Replacement/@what)"/>
              </xsl:when>
              <xsl:otherwise>
                <xsl:value-of select="concat('renaming ', $Replacement/@what)"/>
              </xsl:otherwise>
            </xsl:choose>
            <xsl:value-of select="concat(' as ', $Replacement/@with)"/>
            <xsl:if test="$Replacement/@where">
              <xsl:value-of select="' unless already defined there'"/>
            </xsl:if>
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="concat('dropping ', $Replacement/@what)"/>
          </xsl:otherwise>
        </xsl:choose>
        <xsl:if test="string($Replacement/@redefined-as)">
          <xsl:value-of select="concat(', redefined as ',
                                       $Replacement/@redefined-as)"/>
          <xsl:if test="$Replacement/@in-case-of">
            <xsl:value-of select="','"/>
          </xsl:if>
        </xsl:if>
	<xsl:choose>
          <xsl:when test="string($Replacement/@in-case-of)">
            <xsl:value-of select="concat(' for matching ',
                                         $Replacement/@in-case-of)"/>
          </xsl:when>
          <xsl:when test="$Replacement/@in-case-of">
            <xsl:value-of select="' for matching &quot;empty string&quot;'"/>
          </xsl:when>
	</xsl:choose>
      </cibtr-2:noop>
      <xsl:if test="$Replacement/@msg-extra">
        <cibtr-2:noop>
          <xsl:value-of select="concat($NL, '     ... ',
                                       $Replacement/@msg-extra)"/>
        </cibtr-2:noop>
      </xsl:if>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<xsl:template match="cibtr-2:map">
  <xsl:value-of select="concat('Translation tables v2 in detail', $NL,
                               '===============================', $NL, $NL)"/>
  <xsl:apply-templates select="*"/>
</xsl:template>

<xsl:template match="cibtr-2:table">
  <xsl:value-of select="concat('Details for the ', @for, ' table:', $NL)"/>
  <xsl:if test="@where-cases">
    <xsl:value-of select="concat($NL, '   Possible to-move specifiers:', $NL,
                                 '   ','   ',  @where-cases, $NL)"/>
  </xsl:if>
  <xsl:value-of select="concat(string(preceding-sibling::comment()[1]), $NL)"/>
  <xsl:apply-templates select="*"/>
  <xsl:value-of select="$NL"/>
</xsl:template>

<xsl:template match="cibtr-2:replace">
  <xsl:value-of select="'   - '"/>
  <xsl:call-template name="MapMsg-2">
    <xsl:with-param name="Replacement" select="."/>
  </xsl:call-template>
  <xsl:value-of select="$NL"/>
</xsl:template>

<xsl:template match="*">
  <xsl:apply-templates select="*"/>
</xsl:template>

</xsl:stylesheet>
