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
   Target tag:     cluster_property_set
   Object:         ./nvpair/@name
   Selector ctxt:  ./nvpair/@value
   Move ctxt:      op_defaults ~ /cib/configuration/op_defaults
                   rsc_defaults ~ /cib/configuration/rsc_defaults
   -->
  <cibtr:table for="cluster-properties" msg-prefix="Cluster properties"
               where-cases="op_defaults|rsc_defaults">
    <cibtr:replace what="cluster-infrastructure"
                   with=""
                   in-case-of="heartbeat|openais|classic openais|classic openais (with plugin)|cman"
                   msg-extra="corosync (2+) infrastructure can be used instead, though the value is not of significance"/>

    <cibtr:replace what="cluster_recheck_interval"
                   with="cluster-recheck-interval"/>
    <cibtr:replace what="dc_deadtime"
                   with="dc-deadtime"/>

    <cibtr:replace what="default-action-timeout"
                   with="timeout"
                   where="op_defaults"/>
    <cibtr:replace what="default_action_timeout"
                   with="timeout"
                   where="op_defaults"/>

    <cibtr:replace what="default-migration-threshold"
                   with=""
                   msg-extra="migration-threshold in rsc_defaults can be configured instead"/>
    <cibtr:replace what="default_migration_threshold"
                   with=""
                   msg-extra="migration-threshold in rsc_defaults can be configured instead"/>

    <cibtr:replace what="default-resource-stickiness"
                   with="resource-stickiness"
                   where="rsc_defaults"/>
    <cibtr:replace what="default_resource_stickiness"
                   with="resource-stickiness"
                   where="rsc_defaults"/>

    <cibtr:replace what="default-resource-failure-stickiness"
                   with="migration-threshold"
                   where="rsc_defaults"
                   in-case-of="-INFINITY"
                   redefined-as="1"/>
    <cibtr:replace what="default-resource-failure-stickiness"
                   with=""
                   msg-extra="migration-threshold in rsc_defaults can be configured instead"/>
    <cibtr:replace what="default_resource_failure_stickiness"
                   with="migration-threshold"
                   where="rsc_defaults"
                   in-case-of="-INFINITY"
                   redefined-as="1"/>
    <cibtr:replace what="default_resource_failure_stickiness"
                   with=""
                   msg-extra="migration-threshold in rsc_defaults can be configured instead"/>

    <cibtr:replace what="election_timeout"
                   with="election-timeout"/>
    <cibtr:replace what="expected-quorum-votes"
                   with=""
                   msg-extra="corosync (2+) infrastructure tracks quorum on its own"/>

    <cibtr:replace what="is-managed-default"
                   with="is-managed"
                   where="rsc_defaults"/>
    <cibtr:replace what="is_managed_default"
                   with="is-managed"
                   where="rsc_defaults"/>
    <cibtr:replace what="no_quorum_policy"
                   with="no-quorum-policy"/>

    <cibtr:replace what="notification-agent"
                   with=""
                   msg-extra="standalone alerts can be configured instead"/>
    <cibtr:replace what="notification-recipient"
                   with=""
                   msg-extra="standalone alerts can be configured instead"/>

    <cibtr:replace what="remove_after_stop"
                   with="remove-after-stop"/>
    <cibtr:replace what="shutdown_escalation"
                   with="shutdown-escalation"/>
    <cibtr:replace what="startup_fencing"
                   with="startup-fencing"/>
    <cibtr:replace what="stonith_action"
                   with="stonith-action"/>
    <cibtr:replace what="stonith_enabled"
                   with="stonith-enabled"/>
    <cibtr:replace what="stop_orphan_actions"
                   with="stop-orphan-actions"/>
    <cibtr:replace what="stop_orphan_resources"
                   with="stop-orphan-resources"/>
    <cibtr:replace what="symmetric_cluster"
                   with="symmetric-cluster"/>
    <cibtr:replace what="transition_idle_timeout"
                   with="cluster-delay"/>
  </cibtr:table>

  <!--
   Target tag:     node
   Object:         ./@*
   Selector ctxt:  ./@*
   Move ctxt:      N/A
   -->
  <cibtr:table for="cluster-node" msg-prefix="Cluster node">
    <cibtr:replace what="type"
                   with="type"
                   in-case-of="normal"
                   redefined-as="member"/>
  </cibtr:table>

  <!--
   Target tag:     primitive
                   template
   Object:         ./instance_attributes/nvpair/@name
   Selector ctxt:  N/A
   Move ctxt:      N/A
   -->
  <cibtr:table for="resource-instance-attributes" msg-prefix="Resource instance_attributes">
    <cibtr:replace what="pcmk_arg_map"
                   with=""/>
    <!-- simplified as pcmk_arg_map can encode multiple
         comma-separated pairs (everything would be dropped then,
         except for a single dangling case: "port" coming first) -->
    <cibtr:replace what="pcmk_arg_map"
                   with="pcmk_host_argument"
                   in-case-of-droppable-prefix="port:"/>

    <cibtr:replace what="pcmk_list_cmd"
                   with="pcmk_list_action"/>
    <cibtr:replace what="pcmk_monitor_cmd"
                   with="pcmk_monitor_action"/>
    <cibtr:replace what="pcmk_off_cmd"
                   with="pcmk_off_action"/>
    <cibtr:replace what="pcmk_on_cmd"
                   with="pcmk_on_action"/>
    <cibtr:replace what="pcmk_reboot_cmd"
                   with="pcmk_reboot_action"/>
    <cibtr:replace what="pcmk_status_cmd"
                   with="pcmk_status_action"/>
  </cibtr:table>

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

<xsl:variable name="MapClusterProperties"
              select="document('')/xsl:stylesheet
                        /cibtr:map/cibtr:table[
                          @for = 'cluster-properties'
                        ]"/>

<xsl:variable name="MapClusterNode"
              select="document('')/xsl:stylesheet
                        /cibtr:map/cibtr:table[
                          @for = 'cluster-node'
                        ]"/>

<xsl:variable name="MapResourceInstanceAttributes"
              select="document('')/xsl:stylesheet
                        /cibtr:map/cibtr:table[@for = 'resource-instance-attributes'
                      ]"/>

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
          <xsl:when test="$Replacement/@in-case-of-droppable-prefix">
            <xsl:value-of select="concat(' for matching ',
                                    $Replacement/@in-case-of-droppable-prefix,
                                    ' prefix that will, meanwhile, get dropped'
                                  )"/>
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
 C. [extension over B.] when checking the non-void production
    (via InnerSimulation), beside the injected denormalized whitespace,
    we can also inject particular strings, which the callsite of such
    simulation can, in addition, inspect for paricular string
    occurrences, e.g. to prevent clashes on the production coming
    from multiple sources
 D. not only to honour DRY principle and to avoid inner entropy, it's
    often useful to make callable template bimodal, e.g., when the
    production is generated in the "what's to stay in place" vs.
    "what's to be propagated (combined with previous, effectively
    moved) at this other part of the tree" contexts; for such cases,
    there's usually InverseMode parameter to be assigned true()
    (implicit default) and false(), respectively

 -->

<!--
 Source ctxt:    cluster_property_set
 Target ctxt:    cluster_property_set
 Target-inv ctxt:/cib/configuration/(op_defaults|rsc_defaults)
                 [cluster_property_set -> meta_attributes]
 Dependencies:   N/A
 -->
<xsl:template name="ProcessClusterProperties">
  <xsl:param name="Source"/>
  <xsl:param name="InverseMode" select="false()"/>
  <xsl:param name="InnerSimulation" select="false()"/>

  <xsl:variable name="InnerPass">
    <xsl:choose>
      <xsl:when test="$InnerSimulation">
        <xsl:value-of select="''"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="ProcessClusterProperties">
          <xsl:with-param name="Source" select="$Source"/>
          <xsl:with-param name="InverseMode" select="$InverseMode"/>
          <xsl:with-param name="InnerSimulation" select="true()"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:variable>

  <xsl:for-each select="$Source/node()">
    <xsl:choose>
      <xsl:when test="self::text()">
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
                      select="$MapClusterProperties/cibtr:replace[
                                @what = current()/@name
                                and
                                (
                                  (
                                    @in-case-of
                                    and
                                    contains(concat('|', @in-case-of, '|'),
                                             concat('|', current()/@value, '|'))
                                  )
                                  or
                                  (
                                    not(@in-case-of)
                                    and
                                    not(
                                      $MapClusterProperties/cibtr:replace[
                                        @what = current()/@name
                                        and
                                        @in-case-of
                                        and
                                        contains(concat('|', @in-case-of, '|'),
                                                 concat('|', current()/@value, '|'))
                                      ]
                                    )
                                  )
                                )
                              ]"/>
        <xsl:if test="$InverseMode = false()
                      and
                      not($InnerSimulation)">
          <xsl:call-template name="MapMsg">
            <xsl:with-param name="Context" select="@id"/>
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
            <xsl:if test="$Replacement/@where
                          and
                          (
                            (
                              normalize-space($InverseMode)
                              and
                              $Replacement/@where = $InverseMode
                            )
                            or
                            (
                              not(normalize-space($InverseMode))
                              and
                              (true() or count($InverseMode))
                              and
                              not(
                                $InverseMode/nvpair[
                                  @name = $Replacement/@with
                                ]
                              )
                              and
                              $Replacement/@where = name($InverseMode/..)
                            )
                          )">
              <xsl:call-template name="HelperDenormalizedSpace">
                <xsl:with-param name="Source" select="."/>
              </xsl:call-template>
              <xsl:copy>
                <xsl:for-each select="@*">
                  <xsl:choose>
                    <xsl:when test="name() = 'name'">
                      <xsl:attribute name="{name()}">
                        <xsl:value-of select="$Replacement/@with"/>
                      </xsl:attribute>
                    </xsl:when>
                    <xsl:when test="string($Replacement/@redefined-as)
                                    and
                                    name() = 'value'">
                      <xsl:attribute name="{name()}">
                        <xsl:value-of select="$Replacement/@redefined-as"/>
                      </xsl:attribute>
                    </xsl:when>
                    <xsl:otherwise>
                      <xsl:copy/>
                    </xsl:otherwise>
                  </xsl:choose>
                </xsl:for-each>
              </xsl:copy>
            </xsl:if>
          </xsl:when>
          <xsl:when test="$InverseMode"/>
          <xsl:when test="$Replacement">
            <xsl:call-template name="HelperDenormalizedSpace">
              <xsl:with-param name="Source" select="."/>
            </xsl:call-template>
            <xsl:copy>
              <xsl:for-each select="@*">
                <xsl:choose>
                  <xsl:when test="name() = 'name'">
                    <xsl:attribute name="{name()}">
                      <xsl:value-of select="$Replacement/@with"/>
                    </xsl:attribute>
                  </xsl:when>
                  <xsl:when test="string($Replacement/@redefined-as)
                                  and
                                  name() = 'value'">
                    <xsl:attribute name="{name()}">
                      <xsl:value-of select="$Replacement/@redefined-as"/>
                    </xsl:attribute>
                  </xsl:when>
                  <xsl:otherwise>
                    <xsl:copy/>
                  </xsl:otherwise>
                </xsl:choose>
              </xsl:for-each>
            </xsl:copy>
          </xsl:when>
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
 Source ctxt:    (primitive|template)/instance_attributes
 Target ctxt:    (primitive|template)/instance_attributes
 Target-inv ctxt:N/A
 Dependencies:   N/A
 -->
<xsl:template name="ProcessRscInstanceAttributes">
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
        <xsl:call-template name="ProcessRscInstanceAttributes">
          <xsl:with-param name="Source" select="$Source"/>
          <xsl:with-param name="InnerSimulation" select="true()"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:variable>

  <!-- B: special-casing nvpair -->
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
                      select="$MapResourceInstanceAttributes/cibtr:replace[
                                @what = current()/@name
                                and
                                (
                                  (
                                    @in-case-of
                                    and
                                    contains(concat('|', @in-case-of, '|'),
                                             concat('|', current()/@value, '|'))
                                  )
                                  or
                                  (
                                    @in-case-of-droppable-prefix
                                    and
                                    starts-with(current()/@value,
                                                @in-case-of-droppable-prefix)
                                    and
                                    not(
                                      contains(current()/@value, ',')
                                    )
                                  )
                                  or
                                  (
                                    not(@in-case-of)
                                    and
                                    not(@in-case-of-droppable-prefix)
                                    and
                                    not(
                                      $MapResourceInstanceAttributes/cibtr:replace[
                                        @what = current()/@name
                                        and
                                        (
                                          (
                                            @in-case-of
                                            and
                                            contains(concat('|', @in-case-of, '|'),
                                                     concat('|', current()/@value, '|'))
                                          )
                                          or
                                          (
                                            @in-case-of-droppable-prefix
                                            and
                                            starts-with(current()/@value,
                                                        @in-case-of-droppable-prefix)
                                            and
                                            not(
                                              contains(current()/@value, ',')
                                            )
                                          )
                                        )
                                      ]
                                    )
                                  )
                                )
                              ]"/>
        <xsl:if test="not($InverseMode or $InnerSimulation)">
          <xsl:call-template name="MapMsg">
            <xsl:with-param name="Context" select="@id"/>
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
            <!-- drop (move-over code missing) -->
          </xsl:when>
          <xsl:when test="$InverseMode"/>
          <xsl:when test="$Replacement">
            <!-- plain rename (space helper?) -->
            <xsl:call-template name="HelperDenormalizedSpace">
              <xsl:with-param name="Source" select="."/>
            </xsl:call-template>
            <xsl:copy>
              <xsl:for-each select="@*">
                <xsl:choose>
                  <xsl:when test="name() = 'name'">
                    <xsl:attribute name="{name()}">
                      <xsl:value-of select="$Replacement/@with"/>
                    </xsl:attribute>
                  </xsl:when>
                  <xsl:when test="string($Replacement/@redefined-as)
                                  and
                                  name() = 'value'">
                    <xsl:attribute name="{name()}">
                      <xsl:value-of select="$Replacement/@redefined-as"/>
                    </xsl:attribute>
                  </xsl:when>
                  <xsl:when test="string($Replacement/@in-case-of-droppable-prefix)
                                  and
                                  name() = 'value'">
                    <xsl:attribute name="{name()}">
                      <xsl:value-of select="substring-after(
                                              ., $Replacement/@in-case-of-droppable-prefix
                                            )"/>
                    </xsl:attribute>
                  </xsl:when>
                  <xsl:otherwise>
                    <xsl:copy/>
                  </xsl:otherwise>
                </xsl:choose>
              </xsl:for-each>
            </xsl:copy>
          </xsl:when>
          <xsl:otherwise>
            <xsl:call-template name="HelperDenormalizedSpace">
              <xsl:with-param name="Source" select="."/>
            </xsl:call-template>
            <xsl:copy>
              <xsl:apply-templates select="@*|node()"/>
            </xsl:copy>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:when>
      <xsl:when test="$InverseMode
                      or
                      self::comment()">
        <!-- drop -->
      </xsl:when>
      <xsl:otherwise>
        <xsl:copy>
          <xsl:apply-templates select="@*|node()"/>
        </xsl:copy>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:for-each>
  <!-- E: special-casing nvpair -->
</xsl:template>

<!--
 Source ctxt:    (primitive|template)/operations/op/meta_attributes
 Target ctxt:    (primitive|template)/operations/op/meta_attributes
 Target-inv ctxt:(primitive|template)/meta_attributes
 Dependencies:   ProcessAttrOpMetaAttributes
                 ProcessNonattrOpMetaAttributes
 -->
<xsl:template name="ProcessNonattrOpMetaAttributes">
  <xsl:param name="Source"/>
  <xsl:param name="InverseMode" select="false()"/>
  <xsl:param name="InnerSimulation" select="false()"/>

  <xsl:variable name="EnclosingTag" select="../../.."/>

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
            <xsl:variable name="SimulateAttrOverrides">
              <xsl:for-each select="../../../op">
                <xsl:call-template name="ProcessAttrOpMetaAttributes">
                  <xsl:with-param name="Source" select="."/>
                  <xsl:with-param name="InverseMode" select="true()"/>
                  <xsl:with-param name="InnerSimulation" select="true()"/>
                </xsl:call-template>
              </xsl:for-each>
            </xsl:variable>
            <xsl:if test="$InverseMode
                          and
                          not(
                            contains($SimulateAttrOverrides,
                                     concat(@name, ' '))
                          )">
              <!-- do not override; do not collide with:
                   - newly added from op/@* (see last condition above)
                   - existing - actually subsumed with the previous point
                   - successors sourced like this (see below) -->
              <xsl:variable name="SimulateFollowingSiblings">
                <!-- cf. similar handling in ProcessAttrOpMetaAttributes,
                     but this is more convoluted -->
                <xsl:for-each select="(../following-sibling::meta_attributes
                                       |../../following-sibling::op/meta_attributes)[
                                        not(rule)
                                      ]">
                  <xsl:call-template name="ProcessNonattrOpMetaAttributes">
                    <xsl:with-param name="Source" select="."/>
                    <xsl:with-param name="InverseMode" select="true()"/>
                    <xsl:with-param name="InnerSimulation" select="true()"/>
                  </xsl:call-template>
                </xsl:for-each>
              </xsl:variable>
              <xsl:if test="$Replacement/@where = 'meta_attributes'
                            and
                            not(
                              $EnclosingTag/meta_attributes[
                                not(rule)
                                and
                                nvpair/@name = $Replacement/@with
                              ]
                            )
                            and
                            not(
                              contains($SimulateFollowingSiblings,
                                       concat(@name, ' '))
                            )">
                <!-- cf. trick C. (indicate for inverse mode) -->
                <xsl:choose>
                  <xsl:when test="$InnerSimulation">
                    <xsl:value-of select="concat(@name, ' ')"/>
                  </xsl:when>
                  <xsl:otherwise>
                    <xsl:text> </xsl:text>
                    <xsl:copy>
                      <xsl:apply-templates select="@*"/>
                    </xsl:copy>
                  </xsl:otherwise>
                </xsl:choose>
              </xsl:if>
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

  <xsl:variable name="EnclosingTag" select="../.."/>

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
                        $Replacement/@where = 'meta_attributes'
                        and
                        not(
                          $EnclosingTag/meta_attributes[
                            not(rule)
                            and
                            nvpair/@name = $Replacement/@with
                          ]
                        )">
          <!-- do not override; do not collide with:
               - existing (see last condition above)
               - successors sourced like this (see below) -->
          <xsl:variable name="SimulateFollowingSiblings">
            <xsl:for-each select="../following-sibling::op">
              <xsl:call-template name="ProcessAttrOpMetaAttributes">
                <xsl:with-param name="Source" select="."/>
                <xsl:with-param name="InverseMode" select="true()"/>
                <xsl:with-param name="InnerSimulation" select="true()"/>
              </xsl:call-template>
            </xsl:for-each>
          </xsl:variable>
          <xsl:if test="not(contains($SimulateFollowingSiblings,
                                     concat(name(), ' ')))">
            <!-- fix concurrent op/@* sources (these themselves are winning
                 over sources from meta_attributes -->
            <xsl:choose>
              <xsl:when test="$InnerSimulation">
                <!-- cf. trick C. (indicate for inverse mode) -->
                <xsl:value-of select="concat(name(), ' ')"/>
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
          </xsl:if>
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

<xsl:template match="cluster_property_set">
  <xsl:variable name="ProcessedClusterProperties">
    <xsl:call-template name="ProcessClusterProperties">
      <xsl:with-param name="Source" select="."/>
    </xsl:call-template>
  </xsl:variable>
  <xsl:if test="normalize-space($ProcessedClusterProperties)
                != $ProcessedClusterProperties">
    <xsl:copy>
      <xsl:apply-templates select="@*"/>
      <xsl:copy-of select="$ProcessedClusterProperties"/>
    </xsl:copy>
  </xsl:if>
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

<xsl:template match="node">
  <xsl:copy>
    <xsl:for-each select="@*">
      <xsl:variable name="Replacement"
                    select="$MapClusterNode/cibtr:replace[
                              @what = name(current())
                              and
                              (
                                (
                                  @in-case-of
                                  and
                                  contains(concat('|', @in-case-of, '|'),
                                           concat('|', current(), '|'))
                                )
                                or
                                (
                                  not(@in-case-of)
                                  and
                                  not(
                                    $MapClusterNode/cibtr:replace[
                                      @what = current()/@name
                                      and
                                      @in-case-of
                                      and
                                      contains(concat('|', @in-case-of, '|'),
                                               concat('|', current(), '|'))
                                    ]
                                  )
                                )
                              )
                            ]"/>
      <xsl:call-template name="MapMsg">
        <xsl:with-param name="Context" select="concat(../@uname, ' (id=', ../@id, ')')"/>
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
          <xsl:attribute name="{$Replacement/@with}">
            <xsl:choose>
              <xsl:when test="$Replacement/@redefined-as">
                <xsl:value-of select="$Replacement/@redefined-as"/>
              </xsl:when>
              <xsl:otherwise>
                <xsl:value-of select="."/>
              </xsl:otherwise>
            </xsl:choose>
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
    <!-- B: special-casing operations|instance_attributes -->
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
        <xsl:when test="self::instance_attributes">
          <xsl:variable name="ProcessedRscInstanceAttributes">
            <xsl:call-template name="ProcessRscInstanceAttributes">
              <xsl:with-param name="Source" select="."/>
            </xsl:call-template>
          </xsl:variable>
          <!-- cf. trick A. -->
          <xsl:if test="normalize-space($ProcessedRscInstanceAttributes)
                        != $ProcessedRscInstanceAttributes">
            <xsl:copy>
              <xsl:apply-templates select="@*"/>
              <xsl:copy-of select="$ProcessedRscInstanceAttributes"/>
            </xsl:copy>
          </xsl:if>
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

<xsl:template match="configuration">
  <xsl:variable name="ProcessedOpDefaultsNonruleClusterProperties">
    <xsl:choose>
      <xsl:when test="op_defaults/meta_attributes[
                        not(@id-ref)
                        and
                        not(rule)
                      ]">
        <xsl:call-template name="ProcessClusterProperties">
          <xsl:with-param name="Source"
                          select="crm_config/cluster_property_set[
                                    not(@id-ref)
                                    and
                                    not(rule)
                                  ]"/>
          <xsl:with-param name="InverseMode"
                          select="op_defaults/meta_attributes[
                                    not(@id-ref)
                                    and
                                    not(rule)
                                  ]"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="ProcessClusterProperties">
          <xsl:with-param name="Source"
                          select="crm_config/cluster_property_set[
                                    not(@id-ref)
                                    and
                                    not(rule)
                                  ]"/>
          <xsl:with-param name="InverseMode"
                          select="'op_defaults'"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:variable>
  <xsl:variable name="ProcessedRscDefaultsNonruleClusterProperties">
    <xsl:choose>
      <xsl:when test="rsc_defaults/meta_attributes[
                        not(@id-ref)
                        and
                        not(rule)
                      ]">
        <xsl:call-template name="ProcessClusterProperties">
          <xsl:with-param name="Source"
                          select="crm_config/cluster_property_set[
                                    not(@id-ref)
                                    and
                                    not(rule)
                                  ]"/>
          <xsl:with-param name="InverseMode"
                          select="rsc_defaults/meta_attributes[
                                    not(@id-ref)
                                    and
                                    not(rule)
                                  ]"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="ProcessClusterProperties">
          <xsl:with-param name="Source"
                          select="crm_config/cluster_property_set[
                                    not(@id-ref)
                                    and
                                    not(rule)
                                  ]"/>
          <xsl:with-param name="InverseMode"
                          select="'rsc_defaults'"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:variable>
  <xsl:variable name="ProcessedOpDefaultsRuleClusterProperties">
    <xsl:for-each select="crm_config/cluster_property_set[
                            not(@id-ref)
                            and
                            rule
                          ]">

      <xsl:variable name="ProcessedPartial">
        <xsl:call-template name="ProcessClusterProperties">
          <xsl:with-param name="Source"
                          select="."/>
          <xsl:with-param name="InverseMode" select="'op_defaults'"/>
        </xsl:call-template>
      </xsl:variable>
      <xsl:if test="normalize-space($ProcessedPartial)
                    != $ProcessedPartial">
        <meta_attributes id="{concat('_2TO3_', @id)}">
          <xsl-copy-of select="rule"/>
          <xsl:copy-of select="$ProcessedPartial"/>
        </meta_attributes>
      </xsl:if>
    </xsl:for-each>
  </xsl:variable>
  <xsl:variable name="ProcessedRscDefaultsRuleClusterProperties">
    <xsl:for-each select="crm_config/cluster_property_set[
                            not(@id-ref)
                            and
                            rule
                          ]">
      <xsl:variable name="ProcessedPartial">
        <xsl:call-template name="ProcessClusterProperties">
          <xsl:with-param name="Source"
                          select="."/>
          <xsl:with-param name="InverseMode" select="'rsc_defaults'"/>
        </xsl:call-template>
      </xsl:variable>
      <xsl:if test="normalize-space($ProcessedPartial)
                    != $ProcessedPartial">
        <meta_attributes id="{concat('_2TO3_', @id)}">
          <xsl-copy-of select="rule"/>
          <xsl:copy-of select="$ProcessedPartial"/>
        </meta_attributes>
      </xsl:if>
    </xsl:for-each>
  </xsl:variable>

  <xsl:copy>
    <xsl:apply-templates select="@*"/>
    <!-- B: special-casing {op,rsc}_defaults -->
    <xsl:for-each select="node()">
      <xsl:choose>
        <xsl:when test="self::op_defaults|self::rsc_defaults">
          <xsl:variable name="WhichDefaults" select="name()"/>
          <xsl:copy>
            <xsl:apply-templates select="@*"/>
            <!-- B: special-casing meta_attributes -->
            <xsl:for-each select="node()">
              <xsl:copy>
                <xsl:choose>
                  <xsl:when test="self::meta_attributes[
                                    not(@id-ref)
                                    and
                                    not(rule)
                                    and
                                    not(
                                      preceding-sibling::meta_attributes[
                                        not(@id-ref)
                                        and
                                        not(rule)
                                      ]
                                    )
                                  ]">
                    <xsl:apply-templates select="@*|node()"/>
                    <xsl:if test="$WhichDefaults = 'op_defaults'">
                      <xsl:copy-of select="$ProcessedOpDefaultsNonruleClusterProperties"/>
                    </xsl:if>
                    <xsl:if test="$WhichDefaults = 'rsc_defaults'">
                      <xsl:copy-of select="$ProcessedRscDefaultsNonruleClusterProperties"/>
                    </xsl:if>
                  </xsl:when>
                  <xsl:otherwise>
                    <xsl:apply-templates select="@*|node()"/>
                  </xsl:otherwise>
                </xsl:choose>
                <xsl:if test="$WhichDefaults = 'op_defaults'
                              and
                              normalize-space($ProcessedOpDefaultsRuleClusterProperties)
                              != $ProcessedOpDefaultsRuleClusterProperties">
                  <xsl:copy-of select="$ProcessedOpDefaultsRuleClusterProperties"/>
                </xsl:if>
                <xsl:if test="$WhichDefaults = 'rsc_defaults'
                              and
                              normalize-space($ProcessedRscDefaultsRuleClusterProperties)
                              != $ProcessedRscDefaultsRuleClusterProperties">
                  <xsl:copy-of select="$ProcessedRscDefaultsRuleClusterProperties"/>
                </xsl:if>
              </xsl:copy>
            </xsl:for-each>
            <!-- E: special-casing meta_attributes -->
          </xsl:copy>
        </xsl:when>
        <xsl:otherwise>
          <xsl:copy>
            <xsl:apply-templates select="@*|node()"/>
          </xsl:copy>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:for-each>
    <!-- E: special-casing {op,rsc}_defaults -->
    <xsl:if test="not(op_defaults)
                  and
                  (
                    normalize-space($ProcessedOpDefaultsNonruleClusterProperties)
                    != $ProcessedOpDefaultsNonruleClusterProperties
                    or
                    normalize-space($ProcessedOpDefaultsRuleClusterProperties)
                    != $ProcessedOpDefaultsRuleClusterProperties
                  )">
      <op_defaults>
        <xsl:if test="normalize-space($ProcessedOpDefaultsNonruleClusterProperties)
                      != $ProcessedOpDefaultsNonruleClusterProperties">
          <meta_attributes id="{concat('_2TO3_', '-op-defaults')}">
            <xsl:copy-of select="$ProcessedOpDefaultsNonruleClusterProperties"/>
          </meta_attributes>
        </xsl:if>
        <xsl:copy-of select="$ProcessedOpDefaultsRuleClusterProperties"/>
        <xsl:apply-templates select="text()[position() = last()]"/>
      </op_defaults>
    </xsl:if>
    <xsl:if test="not(rsc_defaults)
                  and
                  (
                    normalize-space($ProcessedRscDefaultsNonruleClusterProperties)
                    != $ProcessedRscDefaultsNonruleClusterProperties
                    or
                    normalize-space($ProcessedRscDefaultsRuleClusterProperties)
                    != $ProcessedRscDefaultsRuleClusterProperties
                  )">
      <rsc_defaults>
        <xsl:if test="normalize-space($ProcessedRscDefaultsNonruleClusterProperties)
                      != $ProcessedRscDefaultsNonruleClusterProperties">
          <meta_attributes id="{concat('_2TO3_', '-rsc-defaults')}">
            <xsl:copy-of select="$ProcessedRscDefaultsNonruleClusterProperties"/>
          </meta_attributes>
        </xsl:if>
        <xsl:copy-of select="$ProcessedRscDefaultsRuleClusterProperties"/>
        <xsl:apply-templates select="text()[position() = last()]"/>
      </rsc_defaults>
    </xsl:if>
  </xsl:copy>
</xsl:template>

<xsl:template match="@*|node()">
  <xsl:call-template name="HelperIdentity"/>
</xsl:template>

</xsl:stylesheet>
