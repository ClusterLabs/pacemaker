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
   Target tag:     primitive
                   template
   Object:         ./operations/op/@*
                   ./operations/op/meta_attributes/nvpair/@name
   Selector ctxt:  ./operations/op/@name
   Move ctxt:      meta_attributes ~ ./meta_attributes/nvpair
   -->
  <cibtr:table for="resources-operation" msg-prefix="Resources-operation"
               where-cases="meta_attributes">
    <cibtr:replace what="requires"
                   with=""
                   msg-extra="only start/promote operation taken into account"/>
    <cibtr:replace what="requires"
                   with="requires"
                   in-case-of="start|promote"
                   where="meta_attributes"/>
  </cibtr:table>

  <!--
   Target tag:     rsc_colocation
   Object:         ./@*
   Selector ctxt:  N/A
   Move ctxt:      N/A
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

<xsl:variable name="MapResourcesOperation"
              select="document('')/xsl:stylesheet
                        /cibtr:map/cibtr:table[
                          @for = 'resources-operation'
                        ]"/>

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
	<xsl:choose>
          <xsl:when test="string($Replacement/@in-case-of)">
            <xsl:value-of select="concat(' for matching ',
                                         $Replacement/@in-case-of)"/>
          </xsl:when>
          <xsl:when test="$Replacement/@in-case-of">
            <xsl:value-of select="' for matching &quot;empty string&quot;'"/>
          </xsl:when>
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
 Produce a denormalized space if not present in the input (cf. trick A.)

 Merely parameter driven, no implicit context taken into account:
 - Source: input selection or result tree fragment to evaluate
 - ResultTreeFragment: optional self-explanatory flag related to Source
 -->
<xsl:template name="HelperDenormalizedSpace">
  <xsl:param name="Source"/>
  <xsl:param name="ResultTreeFragment" select="false()"/>
  <xsl:choose>
    <xsl:when test="not($ResultTreeFragment)">
      <!-- intention here is that immediately surrounding text (mostly expected
           to be just indenting whitespace) and comments will be preserved;
           in case no denormalized space is present, " " is injected -->
      <xsl:variable name="ExistingSpace"
                    select="$Source/preceding-sibling::node()[
                              (
                                self::comment()
                                or
                                self::text()
                              )
                              and
                              generate-id(following-sibling::*[1])
                              = generate-id($Source)
                            ]"/>
      <xsl:copy-of select="$ExistingSpace"/>
      <xsl:if test="not(
                      $ExistingSpace/self::text()[
                        normalize-space(.) != string(.)
                      ]
                    )">
        <xsl:text> </xsl:text>
      </xsl:if>
    </xsl:when>
    <xsl:when test="normalize-space($Source)
                    != string($Source)">
      <xsl:text> </xsl:text>
    </xsl:when>
  </xsl:choose>
</xsl:template>

<!--

 TRANSFORMATION HELPERS

 considerations, limitations, etc.:
 1. the transformations tries to preserve as much of the original XML
    as possible, incl. whitespace text/indentation and comments, but
    at times (corner cases of tricks A. + B. below), this needs to be
    sacrificed, e.g., distorting nice indentation, hence if the
    perfection is the goal:
    - user of the transformation can feed the minimized version of
      the XML (no denormalized/any white-space present)
    - user of the transformation can (re-)pretty-print the outcome
      afterwards

 tricks and conventions used:
 A. callable templates only return Result Tree Fragments, which means
    the only operations allowed are those looking at the underlying,
    virtual node-set, and since we need to discern their non-void
    production (i.e. on successful match/es), we use this trick:
    - ensure the template will not propagate any denormalized whitespace
    - inject denormalized whitespace (superfluous space) artificially
      to mark successful production (but see B. below)
    - with the template production, here stored as Var variable,
      we test "normalize-space($Var) != $Var" condition to detect
      non-void production, mainly intended to see whether to emit
      the enclosing element at all (with the goal of not leaving
      superfluous elements behind needlessly)
 B. [extension over A.] to eliminate distorted indentation
    (cf. consideration 1.), additional reuse of these callable
    templates is introduced: the template can recursively call
    itself with a special flag (InnerSimulation) as an oracle to
    see to whether non-void production will ensue (all pre-existing
    denormalized whitespace is forcefully removed in this mode),
    and if positive, all such inner pre-existing whitespace is
    then preserved in this outer=main invocation
 C. not only to honour DRY principle and to avoid inner entropy, it's
    often useful to make callable template bimodal, e.g., when the
    production is generated in the "what's to stay in place" vs.
    "what's to be propagated (combined with previous, effectively
    moved) at this other part of the tree" contexts; for such cases,
    there's usually InverseMode parameter to be assigned true()
    (implicit default) and false(), respectively

 -->

<!--
 Source ctxt:    (primitive|template)/operations/op/meta_attributes
 Target ctxt:    (primitive|template)/operations/op/meta_attributes
 Target-inv ctxt:(primitive|template)/meta_attributes
 Dependencies:   N/A
 -->
<xsl:template name="ProcessNonattrOpMetaAttributes">
  <xsl:param name="Source"/>
  <xsl:param name="InverseMode" select="false()"/>
  <xsl:param name="InnerSimulation" select="false()"/>

  <xsl:variable name="InnerPass">
    <xsl:choose>
      <xsl:when test="$InverseMode
                      or
                      $InnerSimulation">
        <xsl:value-of select="''"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="ProcessNonattrOpMetaAttributes">
          <xsl:with-param name="Source" select="$Source"/>
          <xsl:with-param name="InnerSimulation" select="true()"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:variable>

  <xsl:for-each select="$Source/node()">
    <xsl:choose>
      <xsl:when test="self::text()
                      and
                      not($InverseMode)">
        <!-- cf. trick A. (consideration 1.) -->
        <xsl:choose>
          <xsl:when test="normalize-space($InnerPass)
                          != $InnerPass
                          and
                          (
                            not(following-sibling::nvpair)
                            or
                            generate-id(following-sibling::nvpair[1])
                            != generate-id(following-sibling::*[1])
                          )">
            <xsl:value-of select="."/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="normalize-space(.)"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:when>
      <xsl:when test="self::nvpair">
        <xsl:variable name="Replacement"
                      select="$MapResourcesOperation/cibtr:replace[
                                @what = current()/@name
                                and
                                (
                                  (
                                    @in-case-of
                                    and
                                    contains(concat('|', @in-case-of, '|'),
                                             concat('|', current()/../../@name, '|'))
                                  )
                                  or
                                  (
                                    not(@in-case-of)
                                    and
                                    not(
                                      $MapResourcesOperation/cibtr:replace[
                                        @what = current()/@name
                                        and
                                        @in-case-of
                                        and
                                        contains(concat('|', @in-case-of, '|'),
                                                 concat('|', current()/../../@name, '|'))
                                      ]
                                    )
                                  )
                                )
                              ]"/>
        <xsl:if test="not($InverseMode or $InnerSimulation)">
          <xsl:call-template name="MapMsg">
            <xsl:with-param name="Context" select="../../@id"/>
            <xsl:with-param name="Replacement" select="$Replacement"/>
          </xsl:call-template>
        </xsl:if>
        <xsl:choose>
          <xsl:when test="$Replacement
                          and
                          (
                            not(string($Replacement/@with))
                            or
                            $Replacement/@where
                          )">
            <!-- drop (possibly just move over) -->
            <xsl:if test="$InverseMode
                          and
                          $Replacement/@where = 'meta_attributes'">
              <!-- cf. trick A. (indicate for inverse mode) -->
              <xsl:text> </xsl:text>
              <xsl:copy>
                <xsl:apply-templates select="@*"/>
              </xsl:copy>
            </xsl:if>
          </xsl:when>
          <xsl:when test="$Replacement">
            <xsl:message terminate="yes">
              <xsl:value-of select="concat('INTERNAL ERROR: ',
                                           $Replacement/../@msg-prefix,
                                           ': no in-situ rename',
                                           ' does not hold (',
                                           not(($InverseMode)), ')')"/>
            </xsl:message>
          </xsl:when>
          <xsl:when test="$InverseMode"/>
          <xsl:otherwise>
            <xsl:call-template name="HelperDenormalizedSpace">
              <xsl:with-param name="Source" select="."/>
            </xsl:call-template>
            <xsl:call-template name="HelperIdentity"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:when>
      <xsl:when test="$InverseMode
                      or
                      self::comment()">
        <!-- drop -->
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="HelperIdentity"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:for-each>
</xsl:template>

<!--
 Source ctxt:    (primitive|template)/operations/op
 Target ctxt:    (primitive|template)/operations/op/meta_attributes
 Target-inv ctxt:(primitive|template)/meta_attributes
 Dependencies:   ProcessNonattrOpMetaAttributes [non-inverse only]
 -->
<xsl:template name="ProcessAttrOpMetaAttributes">
  <xsl:param name="Source"/>
  <xsl:param name="InverseMode" select="false()"/>
  <xsl:param name="InnerSimulation" select="false()"/>

  <xsl:variable name="InnerPass">
    <xsl:choose>
      <xsl:when test="$InnerSimulation">
        <xsl:value-of select="''"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="ProcessAttrOpMetaAttributes">
          <xsl:with-param name="Source" select="$Source"/>
          <xsl:with-param name="InverseMode" select="$InverseMode"/>
          <xsl:with-param name="InnerSimulation" select="true()"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:variable>

  <xsl:if test="(
                  $InverseMode
                  and
                  (
                    $InnerSimulation
                    or
                    normalize-space($InnerPass)
                    != string($InnerPass)
                  )
                )
                or
                not($InverseMode)">
    <xsl:if test="$InverseMode
                  and
                  not($InnerSimulation)">
      <xsl:call-template name="HelperDenormalizedSpace">
        <xsl:with-param name="Source" select="$InnerPass"/>
        <xsl:with-param name="ResultTreeFragment" select="true()"/>
      </xsl:call-template>
    </xsl:if>

    <!-- cannot combine "copy" with creating a new element, hence we mimic
         "copy" with recreating the element anew, while still using just
         a single for-each loop -->
    <xsl:variable name="ParentName">
      <xsl:choose>
        <xsl:when test="not($InverseMode)">
          <xsl:value-of select="name()"/>
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="'nvpair'"/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:element name="{$ParentName}">
    <!-- B: special-casing @* -->
    <xsl:for-each select="@*">
      <xsl:variable name="Replacement"
                    select="$MapResourcesOperation/cibtr:replace[
                              @what = name(current())
                              and
                              (
                                (
                                  @in-case-of
                                  and
                                  contains(concat('|', @in-case-of, '|'),
                                           concat('|', current()/../@name, '|'))
                                )
                                or
                                (
                                  not(@in-case-of)
                                  and
                                  not(
                                    $MapResourcesOperation/cibtr:replace[
                                      @what = name(current())
                                      and
                                      @in-case-of
                                      and
                                      contains(concat('|', @in-case-of, '|'),
                                               concat('|', current()/../@name, '|'))
                                    ]
                                  )
                                )
                              )
                            ]"/>
      <xsl:if test="not($InverseMode or $InnerSimulation)">
        <xsl:call-template name="MapMsg">
          <xsl:with-param name="Context" select="../../@id"/>
          <xsl:with-param name="Replacement" select="$Replacement"/>
        </xsl:call-template>
      </xsl:if>
      <xsl:choose>
        <!-- use inner simulation to find out if success,
             then emit also extra denormalized space -->
        <xsl:when test="$InverseMode
                        and
                        $Replacement/@where = 'meta_attributes'">
          <xsl:choose>
            <xsl:when test="$InnerSimulation">
              <!-- cf. trick A. (indicate for inverse mode) -->
              <xsl:text> </xsl:text>
            </xsl:when>
            <xsl:otherwise>
              <xsl:attribute name="id">
                <xsl:value-of select="concat('_2TO3_', ../@id, '-meta-',
                                             $Replacement/@with)"/>
              </xsl:attribute>
              <xsl:attribute name="name">
                <xsl:value-of select="$Replacement/@with"/>
              </xsl:attribute>
              <xsl:attribute name="value">
                <xsl:value-of select="."/>
              </xsl:attribute>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:when>
        <xsl:when test="$InverseMode"/>
        <xsl:when test="$Replacement
                        and
                        (
                          not(string($Replacement/@with))
                          or
                          $Replacement/@where
                        )">
          <!-- drop (possibly just move over) -->
        </xsl:when>
        <xsl:when test="$Replacement">
          <xsl:message terminate="yes">
            <xsl:value-of select="concat('INTERNAL ERROR: ',
                                         $Replacement/../@msg-prefix,
                                         ': no in-situ rename',
                                         ' does not hold')"/>
          </xsl:message>
        </xsl:when>
        <xsl:otherwise>
          <!--xsl:attribute name="{name()}">
            <xsl:value-of select="."/>
          </xsl:attribute-->
          <xsl:copy/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:for-each>

    <xsl:if test="not($InverseMode)">
      <!-- B: special-casing meta_attributes -->
      <xsl:for-each select="$Source/node()">
        <xsl:choose>
          <xsl:when test="self::text()
                          and
                          not($InverseMode)">
            <!-- cf. trick A. (consideration 1.) -->
            <xsl:choose>
              <xsl:when test="normalize-space($InnerPass)
                              != $InnerPass
                              and
                              (
                                not(following-sibling::nvpair)
                                or
                                generate-id(following-sibling::nvpair[1])
                                != generate-id(following-sibling::*[1])
                              )">
                <xsl:value-of select="."/>
              </xsl:when>
              <xsl:otherwise>
                <xsl:value-of select="normalize-space(.)"/>
              </xsl:otherwise>
            </xsl:choose>
          </xsl:when>
          <xsl:when test="self::meta_attributes">
            <xsl:variable name="ProcessedOpMetaAttributes">
              <xsl:call-template name="ProcessNonattrOpMetaAttributes">
                <xsl:with-param name="Source" select="."/>
                <xsl:with-param name="InnerSimulation" select="$InnerSimulation"/>
              </xsl:call-template>
            </xsl:variable>
            <!-- cf. trick A. -->
            <xsl:if test="normalize-space($ProcessedOpMetaAttributes)
                          != $ProcessedOpMetaAttributes">
              <xsl:copy>
                <xsl:apply-templates select="@*"/>
                <xsl:copy-of select="$ProcessedOpMetaAttributes"/>
              </xsl:copy>
            </xsl:if>
          </xsl:when>
          <xsl:otherwise>
            <xsl:call-template name="HelperIdentity"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:for-each>
    </xsl:if>
    <!-- E: special-casing meta_attributes -->
    </xsl:element>
  </xsl:if>
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

<!--
 1a. propagate (primitive|template)/operations/
       op[name() = 'start' or name() = 'promote']/@requires
     under new ./meta_attributes/nvpair

 1b. "move" (primitive|template)/operations/
       op[name() = 'start' or name() = 'promote']/
       meta_attributes/nvpair[@requires]
     under ./meta_attributes

  otherwise, just

 2a.  drop (primitive|template)/operations/
        op/@requires

 2b.  drop (primitive|template)/operations/
        op/meta_attributes/nvpair[@requires]

 Not compatible with meta_attributes referenced via id-ref
 (would need external preprocessing).
 -->
<xsl:template match="primitive|template">
  <xsl:copy>
    <xsl:apply-templates select="@*"/>
    <!-- B: special-casing operations -->
    <xsl:for-each select="node()">
      <xsl:choose>
        <xsl:when test="self::operations">
          <xsl:copy>
            <xsl:apply-templates select="@*"/>
            <!-- B: special-casing op -->
            <xsl:for-each select="node()">
              <xsl:choose>
                <xsl:when test="self::op">
                  <!-- process @*|meta_attributes/nvpair
                       (keep/drop/move elsewhere) -->
                  <xsl:variable name="ProcessedOpMetaAttributes">
                    <xsl:call-template name="ProcessAttrOpMetaAttributes">
                      <xsl:with-param name="Source" select="."/>
                    </xsl:call-template>
                  </xsl:variable>
                  <xsl:copy-of select="$ProcessedOpMetaAttributes"/>
                </xsl:when>
                <xsl:otherwise>
                  <xsl:call-template name="HelperIdentity"/>
                </xsl:otherwise>
              </xsl:choose>
            </xsl:for-each>
            <!-- E: special-casing op -->
          </xsl:copy>
        </xsl:when>
        <xsl:otherwise>
          <xsl:call-template name="HelperIdentity"/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:for-each>
    <!-- E: special-casing operations -->

    <!-- add as last meta_attributes block... -->

    <!-- ...indirectly from op attributes -->
    <xsl:variable name="ToPropagateFromOp">
      <xsl:for-each select="operations/op">
        <xsl:call-template name="ProcessAttrOpMetaAttributes">
          <xsl:with-param name="Source" select="."/>
          <xsl:with-param name="InverseMode" select="true()"/>
        </xsl:call-template>
      </xsl:for-each>
    </xsl:variable>
    <!-- cf. trick A. -->
    <xsl:if test="normalize-space($ToPropagateFromOp)
                  != $ToPropagateFromOp">
      <meta_attributes id="{concat('_2TO3_', @id, '-meta')}">
        <xsl:copy-of select="$ToPropagateFromOp"/>
      </meta_attributes>
    </xsl:if>

    <!-- ...directly by picking existing nvpairs of meta_attributes -->
    <xsl:for-each select="operations/op/meta_attributes">
      <xsl:variable name="ProcessedOpMetaAttributes">
        <xsl:call-template name="ProcessNonattrOpMetaAttributes">
          <xsl:with-param name="Source" select="."/>
          <xsl:with-param name="InverseMode" select="true()"/>
        </xsl:call-template>
      </xsl:variable>
      <!-- cf. trick A. -->
      <xsl:if test="normalize-space($ProcessedOpMetaAttributes)
                    != $ProcessedOpMetaAttributes">
        <xsl:copy>
          <xsl:apply-templates select="@*[
                                         name() != 'id'
                                       ]"/>
          <xsl:attribute name='id'>
            <xsl:value-of select="concat('_2TO3_', @id)"/>
          </xsl:attribute>
          <xsl:apply-templates select="node()[
                                         name() != 'nvpair'
                                       ]"/>
          <xsl:copy-of select="$ProcessedOpMetaAttributes"/>
          <xsl:apply-templates select="text()[position() = last()]"/>
        </xsl:copy>
      </xsl:if>
    </xsl:for-each>
  </xsl:copy>
</xsl:template>

<xsl:template match="@*|node()">
  <xsl:call-template name="HelperIdentity"/>
</xsl:template>

</xsl:stylesheet>
