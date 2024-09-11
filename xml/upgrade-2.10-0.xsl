<!--
 Copyright 2018 Red Hat, Inc.
 Author: Jan Pokorny <jpokorny@redhat.com>
 Part of pacemaker project
 SPDX-License-Identifier: GPL-2.0-or-later
 -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:cibtr="http://clusterlabs.org/ns/pacemaker/cibtr-2"
                exclude-result-prefixes="cibtr"
                cibtr:filename="upgrade-2.10-enter.xsl">
<xsl:output method="xml" encoding="UTF-8" indent="yes" omit-xml-declaration="yes"/>


<!--

 GENERIC UTILITIES

 -->

<!--
 Recursive implementation of "basename"

 Merely parameter driven, no implicit context taken into account:
 - Uri: input in it's current phase of processing
-->
<xsl:template name="cibtr:WrapSpecificBasename">
  <xsl:param name="Uri"/>
  <xsl:choose>
    <xsl:when test="not(contains($Uri, '/'))">
      <xsl:value-of select="$Uri"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:call-template name="cibtr:WrapSpecificBasename">
        <xsl:with-param name="Uri"
                        select="substring-after($Uri, '/')"/>
      </xsl:call-template>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<!--
 Id-mangling-enriched identity template.
 -->
<xsl:template name="cibtr:HelperIdentityEnter">
  <xsl:param name="TargetIdPrefix" select="''"/>
  <xsl:copy>
    <xsl:apply-templates select="@*|node()"
                         mode="cibtr:enter">
      <xsl:with-param name="TargetIdPrefix" select="$TargetIdPrefix"/>
    </xsl:apply-templates>
  </xsl:copy>
</xsl:template>


<!--

 ACTUAL TRANSFORMATION

 Extra modes: cibtr:enter

 -->

<xsl:variable name="cibtr:WrapSpecificPrefix">
  <!-- no sleek way to fetch this, top-level xmlns:cibtr disappears early -->
  <xsl:call-template name="cibtr:WrapSpecificBasename">
    <xsl:with-param name="Uri"
      select="namespace-uri(document('')/xsl:stylesheet/@cibtr:filename)"/>
  </xsl:call-template>
</xsl:variable>

<xsl:variable name="cibtr:WrapSpecificPrefixInitialRoot"
              select="concat('_', $cibtr:WrapSpecificPrefix, '_')"/>

<!--
 cibtr:enter mode
 -->

<!--
 This is to cover elements with the internal structure characterized
 with the following RelaxNG Compact encoded grammar:

 > attribute id-ref { xsd:IDREF }
 > | (attribute id { xsd:ID },
 >    (rule?
 >     & nvpair*
 >     & attribute score {
 >         xsd:integer
 >         | xsd:token "INFINITY"
 >         | xsd:token "+INFINITY"
 >         | xsd:token "-INFINITY"
 >       }?))

 The context node corresponds to "@id-ref" branch, and Original to the other,
 and the task here is to recursively copy anything from Original to target
 (with new, unique IDs, of course), and to flip @id-ref to full-fledged,
 now valid @id, which will be likewise unique, and importantly, reversibly
 mappable back to original in "leave" XSLT counterpart.
 -->
<xsl:template match="*[
                       @id-ref
                       and
                       contains(
                         concat('|cluster_property_set',
                                '|instance_attributes|',
                                '|meta_attributes|'),
                         concat('|', name(), '|')
                       )
                     ]"
              mode="cibtr:enter">
  <xsl:variable name="Original"
                select="//*[
                          name() = name(current())
                          and
                          @id = current()/@id-ref
                        ]"/>
  <xsl:choose>
    <xsl:when test="count($Original) = 0">
      <xsl:message terminate="yes">
        <xsl:value-of select="concat('INTERNAL ERROR:',
                                     name(), ': dangling @id-ref (',
                                     @id-ref, '): no such @id found',
                                     ' within the same element class')"/>
      </xsl:message>
    </xsl:when>
    <xsl:when test="count($Original) != 1">
      <xsl:message terminate="yes">
        <xsl:value-of select="concat('INTERNAL ERROR:',
                                     name(), ': dangling @id-ref (',
                                     @id-ref, '): more than one @id found',
                                     ' within the same element class')"/>
      </xsl:message>
    </xsl:when>
    <xsl:otherwise>
      <xsl:copy>
        <xsl:attribute name="id">
          <xsl:value-of select="concat($cibtr:WrapSpecificPrefixInitialRoot,
                                       $Original/@id)"/>
        </xsl:attribute>
        <xsl:apply-templates select="$Original/@*[name() != 'id']
                                     |$Original/node()"
                             mode="cibtr:enter">
          <xsl:with-param name="TargetIdPrefix"
                          select="concat('__', $cibtr:WrapSpecificPrefix, '_',
                                         $Original/@id, '__')"/>
        </xsl:apply-templates>
      </xsl:copy>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<!--
 (uniformity as an unattainable goal)
 -->
<xsl:template match="@id[
                       name(..) != 'resource_ref'
                     ]"
              mode="cibtr:enter">
  <xsl:param name="TargetIdPrefix"/>
  <xsl:attribute name="{name()}">
    <xsl:value-of select="concat($TargetIdPrefix, .)"/>
  </xsl:attribute>
</xsl:template>

<xsl:template match="@*|node()" mode="cibtr:enter">
  <xsl:param name="TargetIdPrefix" select="''"/>
  <xsl:call-template name="cibtr:HelperIdentityEnter">
    <xsl:with-param name="TargetIdPrefix" select="$TargetIdPrefix"/>
  </xsl:call-template>
</xsl:template>

<!-- mode-less, easy to override kick-off -->
<xsl:template match="/">
  <xsl:call-template name="cibtr:HelperIdentityEnter"/>
</xsl:template>

</xsl:stylesheet>
