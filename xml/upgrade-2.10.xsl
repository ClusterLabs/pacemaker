<!--
 Copyright 2018 Red Hat, Inc.
 Author: Jan Pokorny <jpokorny@redhat.com>
 Part of pacemaker project
 SPDX-License-Identifier: GPL-2.0-or-later
 -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:cibtr="http://clusterlabs.org/ns/pacemaker/cibtr-2">
<xsl:output method="xml" encoding="UTF-8" indent="yes" omit-xml-declaration="yes"/>

<xsl:param name="cib-min-ver" select="'3.0'"/>

<!--

 HELPER DEFINITIONS

 -->

<cibtr:map>

  <!--
   Target tag:     rsc_colocation
   Object:         ./@*
   -->
  <cibtr:table for="constraints-colocation" msg-prefix="Constraints-colocation">
    <cibtr:replace what="score-attribute"
                   with=""
                   msg-extra="was actually never in effect"/>
    <cibtr:replace what="score-attribute-mangle"
                   with=""
                   msg-extra="was actually never in effect"/>
  </cibtr:table>

</cibtr:map>

<xsl:variable name="MapConstraintsColocation"
              select="document('')/xsl:stylesheet
                        /cibtr:map/cibtr:table[
                          @for = 'constraints-colocation'
                        ]"/>

<!--

 GENERIC UTILITIES

 -->

<!--
 Plain identity template

 Merely implicit-context-driven, no arguments.
 -->
<xsl:template name="HelperIdentity">
  <xsl:copy>
    <xsl:apply-templates select="@*|node()"/>
  </xsl:copy>
</xsl:template>

<!--
 Emit an message about the replacement, sanity checking the source definitions

 Merely parameter driven, no implicit context taken into account:
 - Context: optional message prefix
 - Replacement: selected subset of cibtr:map's leaves
                (it's considered a hard error if consists of more than 1 item)
 -->
<xsl:template name="MapMsg">
  <xsl:param name="Context" select="''"/>
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
      <xsl:variable name="MsgPrefix" select="concat(
                                               ($Replacement|$Replacement/..)
                                                 /@msg-prefix, ': '
                                             )"/>
      <xsl:message>
        <xsl:value-of select="$MsgPrefix"/>
        <xsl:if test="$Context">
          <xsl:value-of select="concat($Context, ': ')"/>
        </xsl:if>
        <xsl:choose>
          <xsl:when test="string($Replacement/@with)">
            <xsl:value-of select="concat('renaming ', $Replacement/@what,
                                         ' as ', $Replacement/@with)"/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="concat('dropping ', $Replacement/@what)"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:message>
      <xsl:if test="$Replacement/@msg-extra">
        <xsl:message>
          <xsl:value-of select="concat($MsgPrefix, '... ',
                                       $Replacement/@msg-extra)"/>
        </xsl:message>
      </xsl:if>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<!--

 ACTUAL TRANSFORMATION

 -->

<xsl:template match="cib">
  <xsl:copy>
    <xsl:apply-templates select="@*"/>
    <xsl:attribute name="validate-with">
      <xsl:value-of select="concat('pacemaker-', $cib-min-ver)"/>
    </xsl:attribute>
    <xsl:apply-templates select="node()"/>
  </xsl:copy>
</xsl:template>

<xsl:template match="rsc_colocation">
  <xsl:copy>
    <xsl:for-each select="@*">
      <xsl:variable name="Replacement"
                    select="$MapConstraintsColocation/cibtr:replace[
                              @what = name(current())
                            ]"/>
      <xsl:call-template name="MapMsg">
        <xsl:with-param name="Context" select="../@id"/>
        <xsl:with-param name="Replacement" select="$Replacement"/>
      </xsl:call-template>
      <xsl:choose>
        <xsl:when test="$Replacement
                        and
                        not(string($Replacement/@with))">
          <!-- drop -->
        </xsl:when>
        <xsl:when test="$Replacement">
          <!-- rename -->
          <xsl:attribute name="{name()}">
            <xsl:value-of select="$Replacement/@with"/>
          </xsl:attribute>
        </xsl:when>
        <xsl:otherwise>
          <xsl:copy/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:for-each>
    <xsl:apply-templates select="node()"/>
  </xsl:copy>
</xsl:template>

<xsl:template match="@*|node()">
  <xsl:call-template name="HelperIdentity"/>
</xsl:template>

</xsl:stylesheet>
