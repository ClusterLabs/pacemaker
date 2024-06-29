<!--
 Copyright 2018 Red Hat, Inc.
 Author: Jan Pokorny <jpokorny@redhat.com>
 Part of pacemaker project
 SPDX-License-Identifier: GPL-2.0-or-later
 -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:cibtr="http://clusterlabs.org/ns/pacemaker/cibtr-2"
                exclude-result-prefixes="cibtr"
		cibtr:filename="upgrade-2.10-leave.xsl">
<xsl:output method="xml" encoding="UTF-8" indent="yes" omit-xml-declaration="yes"/>

<xsl:param name="cibtr:label-debug"   select="'DEBUG: '"/>

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
<xsl:template name="cibtr:HelperIdentityLeave">
  <xsl:copy>
    <xsl:apply-templates select="@*|node()" mode="cibtr:leave"/>
  </xsl:copy>
</xsl:template>


<!--

 ACTUAL TRANSFORMATION

 Extra modes: cibtr:leave
              cibtr:leave-serialize

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
 cibtr:leave-serialize mode
 -->

<xsl:template match="@*|node()" mode="cibtr:leave-serialize">
  <xsl:choose>
    <xsl:when test="count(.|../@*)=count(../@*)
                    and
                    name() = 'id'">
      <!-- intentionally skip -->
    </xsl:when>
    <xsl:when test="count(.|../@*)=count(../@*)
                    or
                    self::processing-instruction()">
      <xsl:variable name="Mark">
        <xsl:if test="count(.|../@*)=count(../@*)">A</xsl:if>
        <xsl:if test="self::processing-instruction()">P</xsl:if>
      </xsl:variable>
      <xsl:value-of select="concat($Mark, '(', name(), '=', ., '),')"/>
    </xsl:when>
    <xsl:when test="self::*">
      <xsl:value-of select="concat('E(', name(), ',')"/>
      <xsl:apply-templates select="@*|node()"
                           mode="cibtr:leave-serialize"/>
      <xsl:value-of select="'),'"/>
    </xsl:when>
    <xsl:when test="self::comment()|self::text()">
      <xsl:variable name="Mark">
        <xsl:if test="self::comment()">C</xsl:if>
        <xsl:if test="self::text()">T</xsl:if>
      </xsl:variable>
      <xsl:value-of select="concat($Mark, '(', ., '),')"/>
    </xsl:when>
  </xsl:choose>
</xsl:template>

<!--
 cibtr:leave mode
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

 The context node corresponds to "@id-ref" branch prior to unfolding
 in the preceding "unfold" XSLT counterpart, and Original to the other,
 and the task here is to recursively (and deterministically) compare
 the content of the two, and when there's a match, to collapse the
 former back to a mere empty @id-ref link.

 NOTE: name of this template may be a bit misleading, but it's meant
       to really mean "after upgrade of the same trailing numbers",
       which effectively means we are playing per 3.X CIB schema
       rules, which needs to be considered, should any element be
       renamed, etc.
 -->
<xsl:template match="*[
                       contains(
                         concat('|cluster_property_set',
                                '|instance_attributes|',
                                '|meta_attributes|'),
                         concat('|', name(), '|')
                       )
                     ]"
              mode="cibtr:leave">
  <xsl:variable name="Original"
                select="//*[
                          name() = name(current())
                          and
                          @id = substring-after(current()/@id,
                                                $cibtr:WrapSpecificPrefixInitialRoot)
                        ]"/>
  <xsl:choose>
    <xsl:when test="not(
                      starts-with(@id, $cibtr:WrapSpecificPrefixInitialRoot)
                    )">
      <xsl:copy>
        <xsl:apply-templates select="@*|node()"
                             mode="cibtr:leave"/>
      </xsl:copy>
    </xsl:when>
    <xsl:when test="count($Original) = 0">
      <xsl:if test="string($cibtr:label-debug) != string(false())">
        <xsl:message>
          <xsl:value-of select="concat($cibtr:label-debug, name(),
                                       ': original element pointed to with',
                                       ' @id-ref (',
                                       substring-after(@id,
                                                       $cibtr:WrapSpecificPrefixInitialRoot),
                                       ') disappeared during upgrade')"/>
        </xsl:message>
      </xsl:if>
      <xsl:copy>
        <xsl:apply-templates select="@*|node()"
                             mode="cibtr:leave"/>
      </xsl:copy>
    </xsl:when>
    <xsl:when test="count($Original) != 1">
      <xsl:message terminate="yes">
        <xsl:value-of select="concat('INTERNAL ERROR:',
                                     name(), ': found several elements',
                                     ' that possibly were originally',
                                     ' pointed to with @id-ref (',
                                     substring-after(@id,
                                                     $cibtr:WrapSpecificPrefixInitialRoot),
                                     '); unexpected ambiguity')"/>
      </xsl:message>
    </xsl:when>
    <xsl:otherwise>
      <xsl:variable name="SerializedOriginal">
        <xsl:apply-templates select="$Original/@*[name() != 'id']
                                     |$Original/node()"
                             mode="cibtr:leave-serialize"/>
      </xsl:variable>
      <xsl:variable name="SerializedDependant">
        <xsl:apply-templates select="@*[name() != 'id']
                                     |node()"
                             mode="cibtr:leave-serialize"/>
      </xsl:variable>
      <xsl:copy>
        <xsl:choose>
          <xsl:when test="$SerializedOriginal = $SerializedDependant">
            <xsl:attribute name="id-ref">
              <xsl:value-of select="substring-after(@id,
                                                    $cibtr:WrapSpecificPrefixInitialRoot)"/>
            </xsl:attribute>
          </xsl:when>
          <xsl:otherwise>
            <xsl:apply-templates select="@*|node()"
                                 mode="cibtr:leave">
            </xsl:apply-templates>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:copy>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<xsl:template match="@*|node()" mode="cibtr:leave">
  <xsl:call-template name="cibtr:HelperIdentityLeave"/>
</xsl:template>

<!-- mode-less, easy to override kick-off -->
<xsl:template match="/">
  <xsl:call-template name="cibtr:HelperIdentityLeave"/>
</xsl:template>

</xsl:stylesheet>
