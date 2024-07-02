<!--
 Copyright 2018 Red Hat, Inc.
 Author: Jan Pokorny <jpokorny@redhat.com>
 Part of pacemaker project
 SPDX-License-Identifier: GPL-2.0-or-later
 -->

<!--
 Not compatible with @id-ref occurrences!  Normalize generic 2.X-compatible
 instances with upgrade-2.10-enter.xsl (optionally denormalize back akin
 to the original with upgrade-2.10-leave.xsl once the upgrade is finished).
-->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:cibtr="http://clusterlabs.org/ns/pacemaker/cibtr-2"
                exclude-result-prefixes="cibtr">
<xsl:output method="xml" encoding="UTF-8" indent="yes" omit-xml-declaration="yes"/>

<xsl:param name="cibtr:cib-min-ver" select="'3.0'"/>
<xsl:param name="cibtr:label-warning" select="'WARNING: '"/>
<xsl:param name="cibtr:label-info"    select="'INFO: '"/>
<xsl:param name="cibtr:label-debug"   select="'DEBUG: '"/>

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
   Related commit: c1c66fe13
                   +
                   7a9891f29
                   7d0d1b0eb
                   1f643d610
                   73a5d63a8
                   +
                   642a09b22
                   0c03e366d
                   a28a558f9
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
   Related commit: 55ab749bf
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
   Related commit: 06d4559cb
                   +
                   6c8e0be20
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
   Object:         ./meta_attributes/nvpair/@name
   Selector ctxt:  N/A
   Move ctxt:      N/A
   Related commit: c713bbe39
                   +
                   6052ad6da
   -->
  <cibtr:table for="resource-meta-attributes" msg-prefix="Resource meta_attributes">
    <cibtr:replace what="isolation"
                   with="target-role"
                   redefined-as="Stopped"
                   msg-extra="i.e. resource at hand disabled; isolation wrappers obsoleted with bundle resources"
                   msg-severity="WARNING"/>
    <cibtr:replace what="isolation-host"
                   with="target-role"
                   redefined-as="Stopped"
                   msg-extra="i.e. resource at hand disabled; isolation wrappers obsoleted with bundle resources"
                   msg-severity="WARNING"/>
    <cibtr:replace what="isolation-instance"
                   with="target-role"
                   redefined-as="Stopped"
                   msg-extra="i.e. resource at hand disabled; isolation wrappers obsoleted with bundle resources"
                   msg-severity="WARNING"/>
    <cibtr:replace what="isolation-wrapper"
                   with="target-role"
                   redefined-as="Stopped"
                   msg-extra="i.e. resource at hand disabled; isolation wrappers obsoleted with bundle resources"
                   msg-severity="WARNING"/>

    <cibtr:replace what="resource-failure-stickiness"
                   with="migration-threshold"
                   in-case-of="-INFINITY"
                   redefined-as="1"/>
    <cibtr:replace what="resource-failure-stickiness"
                   with=""
                   msg-extra="migration-threshold can be configured instead"/>
    <cibtr:replace what="resource_failure_stickiness"
                   with="migration-threshold"
                   in-case-of="-INFINITY"
                   redefined-as="1"/>
    <cibtr:replace what="resource_failure_stickiness"
                   with=""
                   msg-extra="migration-threshold can be configured instead"/>
  </cibtr:table>

  <!--
   Target tag:     primitive
                   template
   Object:         ./operations/op/@*
                   ./operations/op/meta_attributes/nvpair/@name
                   ./operations/op/instance_attributes/nvpair/@name
   Selector ctxt:  ./operations/op/@name
   Move ctxt:      meta_attributes ~ ./meta_attributes/nvpair
   Related commit: 014a543d5
   -->
  <cibtr:table for="resources-operation" msg-prefix="Resources-operation"
               where-cases="meta_attributes">
    <!-- keep this in sync with resource-operation-instance-attributes table -->
    <cibtr:replace what="requires"
                   with=""
                   msg-extra="only start/promote operation taken into account"/>
    <cibtr:replace what="requires"
                   with="requires"
                   in-case-of="start|promote"
                   where="meta_attributes"/>
  </cibtr:table>

  <!--
   Target tag:     primitive
                   template
   Object:         ./operations/op/instance_attributes/nvpair/@name
   Selector ctxt:  ./operations/op/@name
   Move ctxt:      per-resource-meta_attributes ~ ./meta_attributes/nvpair
                   meta_attributes ~ ./operations/op/meta_attributes/nvpair
   Related commit: 023897afc
                   3100c0e8b
   -->
  <cibtr:table for="resource-operation-instance-attributes"
               msg-prefix="Resources-operation instance_attributes"
               where-cases="meta_attributes|per-resource-meta_attributes">
    <!-- this is easier to solve through resources-operation table handling,
         in the inverse mode, but for compatibility purposes, we need to have
         it tracked here, so mark it the same way as if we were moving it over
         to sibling per-op meta_attributes (while in fact we move it up to
         per-resource meta_attributes, as if it was specified in per-op
         meta_attributes already), just use a dedicated "where-case" other
         than "meta_attributes" reserved for proper local move as mentioned;
         otherwise keep it in sync with said table -->
    <cibtr:replace what="requires"
                   with=""
                   msg-extra="only start/promote operation taken into account"/>
    <cibtr:replace what="requires"
                   with="requires"
                   in-case-of="start|promote"
                   where="per-resource-meta_attributes"/>

    <!-- these must have been, due to the value sourcing predence arrangement,
         shadowed by immediate op's attributes, so simply preserve their
         non-meta meaning -->
    <!--
    <cibtr:replace what="name"
                   with="name"
                   where="meta_attributes"/>
    <cibtr:replace what="interval"
                   with="interval"
                   where="meta_attributes"/>
    -->

    <cibtr:replace what="interval-origin"
                   with="interval-origin"
                   where="meta_attributes"/>
    <cibtr:replace what="start-delay"
                   with="start-delay"
                   where="meta_attributes"/>

    <cibtr:replace what="enabled"
                   with="enabled"
                   where="meta_attributes"/>
    <cibtr:replace what="on-fail"
                   with="on-fail"
                   where="meta_attributes"/>
    <cibtr:replace what="record-pending"
                   with="record-pending"
                   where="meta_attributes"/>
    <cibtr:replace what="role"
                   with="role"
                   where="meta_attributes"/>
    <cibtr:replace what="timeout"
                   with="timeout"
                   where="meta_attributes"/>
  </cibtr:table>

  <!--
   Target tag:     rsc_colocation
   Object:         ./@*
   Selector ctxt:  N/A
   Move ctxt:      N/A
   Related commit: 96d7ffedf
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

<xsl:variable name="cibtr:MapClusterProperties"
              select="document('')/xsl:stylesheet
                        /cibtr:map/cibtr:table[
                          @for = 'cluster-properties'
                        ]"/>

<xsl:variable name="cibtr:MapClusterNode"
              select="document('')/xsl:stylesheet
                        /cibtr:map/cibtr:table[
                          @for = 'cluster-node'
                        ]"/>

<xsl:variable name="cibtr:MapResourceInstanceAttributes"
              select="document('')/xsl:stylesheet
                        /cibtr:map/cibtr:table[
                          @for = 'resource-instance-attributes'
                        ]"/>

<xsl:variable name="cibtr:MapResourceMetaAttributes"
              select="document('')/xsl:stylesheet
                        /cibtr:map/cibtr:table[
                          @for = 'resource-meta-attributes'
                        ]"/>

<xsl:variable name="cibtr:MapResourcesOperation"
              select="document('')/xsl:stylesheet
                        /cibtr:map/cibtr:table[
                          @for = 'resources-operation'
                        ]"/>

<xsl:variable name="cibtr:MapResourcesOperationInstanceAttributes"
              select="document('')/xsl:stylesheet
                        /cibtr:map/cibtr:table[
                          @for = 'resource-operation-instance-attributes'
                        ]"/>

<xsl:variable name="cibtr:MapConstraintsColocation"
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
<xsl:template name="cibtr:HelperIdentity">
  <xsl:copy>
    <xsl:apply-templates select="@*|node()"
                         mode="cibtr:main"/>
  </xsl:copy>
</xsl:template>

<!--
 Emit an message about the replacement, sanity checking the source definitions

 Merely parameter driven, no implicit context taken into account:
 - Context: optional message prefix
 - Replacement: selected subset of cibtr:map's leaves
                (it's considered a hard error if consists of more than 1 item)

 Explanation wrt. how target severity gets selected, ordered by priority:
 - $Replacement/@msg-severity (WARNING/INFO/DEBUG)
 - $Replacement/@msg-extra defined -> INFO
 - otherwise -> DEBUG
 -->
<xsl:template name="cibtr:MapMsg">
  <xsl:param name="Context" select="''"/>
  <xsl:param name="Replacement"/>
  <xsl:choose>
    <xsl:when test="not($Replacement)"/>
    <xsl:when test="count($Replacement) != 1">
      <xsl:message terminate="yes">
        <xsl:value-of select="concat('INTERNAL ERROR: ',
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
      <xsl:variable name="MsgSeverity">
        <xsl:choose>
          <xsl:when test="$Replacement/@msg-severity">
            <xsl:value-of select="$Replacement/@msg-severity"/>
          </xsl:when>
          <xsl:when test="$Replacement/@msg-extra">
            <xsl:value-of select="'INFO'"/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="'DEBUG'"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <xsl:variable name="MsgSeverityLabel">
        <xsl:choose>
          <xsl:when test="$MsgSeverity = 'WARNING'">
            <xsl:value-of select="$cibtr:label-warning"/>
          </xsl:when>
          <xsl:when test="$MsgSeverity = 'INFO'">
            <xsl:value-of select="$cibtr:label-info"/>
          </xsl:when>
          <xsl:when test="$MsgSeverity = 'DEBUG'">
            <xsl:value-of select="$cibtr:label-debug"/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:message terminate="yes">
              <xsl:value-of select="concat('INTERNAL ERROR: not a valid',
                                           ' severity specification: ',
                                           $MsgSeverity)"/>
            </xsl:message>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <xsl:if test="string($MsgSeverityLabel) != string(false())">
        <xsl:message>
          <xsl:value-of select="concat($MsgSeverityLabel, $MsgPrefix)"/>
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
            <xsl:value-of select="concat($MsgSeverityLabel, $MsgPrefix, '... ',
                                         $Replacement/@msg-extra)"/>
          </xsl:message>
        </xsl:if>
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
<xsl:template name="cibtr:HelperDenormalizedSpace">
  <xsl:param name="Source"/>
  <xsl:param name="ResultTreeFragment" select="false()"/>
  <xsl:param name="InnerSimulation" select="false()"/>
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
                    ) and $InnerSimulation">
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
 E. the common idiom that emerges is: evaluate simulation value,
    depending on the presence of the "success mark" (cf. A.),
    possibly emit non-simulation value; since it would (likely)
    re-evaluate the simulation anew (wastefully) or perhaps
    this sort of dependency injection can just come handy,
    common transformation helpers below offer InnerPass
    parameter to be optionally passed, either as a string (when
    no-denormalized-space is an internal criterium for the template)
    or, conventionally, the result tree fragment representing the
    output of the template at hand called with a simulation flag
    * established signaling strings accompanying InnerSimulation=true:
      - TRIGGER-MSG ... make the template execution emit messages
                        describing changes being performed
      - TRIGGER-RECURSION
                    ... currently used in the oracle-like evaluation
                        of what's the situation with the sibling
                        elements as a recursion guard so that such
                        nested runs won't revisit the new set of
                        siblings per the respective nested context

 -->

<!--
 Source ctxt:    cluster_property_set
 Target ctxt:    cluster_property_set
 Target-inv ctxt:/cib/configuration/(op_defaults|rsc_defaults)
                 [cluster_property_set -> meta_attributes]
 Dependencies:   N/A
 -->
<xsl:template name="cibtr:ProcessClusterProperties">
  <xsl:param name="Source"/>
  <xsl:param name="InverseMode" select="false()"/>
  <xsl:param name="InnerSimulation" select="false()"/>
  <xsl:param name="InnerPass">
    <xsl:choose>
      <xsl:when test="$InnerSimulation">
        <xsl:value-of select="''"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="cibtr:ProcessClusterProperties">
          <xsl:with-param name="Source" select="$Source"/>
          <xsl:with-param name="InverseMode" select="$InverseMode"/>
          <xsl:with-param name="InnerSimulation" select="true()"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:param>

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
                      select="$cibtr:MapClusterProperties/cibtr:replace[
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
                                      $cibtr:MapClusterProperties/cibtr:replace[
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
        <xsl:if test="$InnerPass = 'TRIGGER-MSG'">
          <xsl:call-template name="cibtr:MapMsg">
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
              <xsl:call-template name="cibtr:HelperDenormalizedSpace">
                <xsl:with-param name="Source" select="."/>
                <xsl:with-param name="InnerSimulation" select="$InnerSimulation"/>
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
            <xsl:call-template name="cibtr:HelperDenormalizedSpace">
              <xsl:with-param name="Source" select="."/>
              <xsl:with-param name="InnerSimulation" select="$InnerSimulation"/>
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
            <xsl:call-template name="cibtr:HelperDenormalizedSpace">
              <xsl:with-param name="Source" select="."/>
              <xsl:with-param name="InnerSimulation" select="$InnerSimulation"/>
            </xsl:call-template>
            <xsl:call-template name="cibtr:HelperIdentity"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:when>
      <xsl:when test="$InverseMode
                      or
                      self::comment()">
        <!-- drop -->
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="cibtr:HelperIdentity"/>
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
<xsl:template name="cibtr:ProcessRscInstanceAttributes">
  <xsl:param name="Source"/>
  <xsl:param name="InnerSimulation" select="false()"/>
  <xsl:param name="InnerPass">
    <xsl:choose>
      <xsl:when test="$InnerSimulation">
        <xsl:value-of select="''"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="cibtr:ProcessRscInstanceAttributes">
          <xsl:with-param name="Source" select="$Source"/>
          <xsl:with-param name="InnerSimulation" select="true()"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:param>

  <!-- B: special-casing nvpair -->
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
                      select="$cibtr:MapResourceInstanceAttributes/cibtr:replace[
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
                                      $cibtr:MapResourceInstanceAttributes/cibtr:replace[
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
        <xsl:if test="$InnerPass = 'TRIGGER-MSG'">
          <xsl:call-template name="cibtr:MapMsg">
            <xsl:with-param name="Context" select="@id"/>
            <xsl:with-param name="Replacement" select="$Replacement"/>
          </xsl:call-template>
        </xsl:if>
        <xsl:choose>
          <xsl:when test="$Replacement
                          and
                          not(string($Replacement/@with))">
            <!-- drop (move-over code missing) -->
          </xsl:when>
          <xsl:when test="$Replacement">
            <!-- plain rename -->
            <xsl:call-template name="cibtr:HelperDenormalizedSpace">
              <xsl:with-param name="Source" select="."/>
              <xsl:with-param name="InnerSimulation" select="$InnerSimulation"/>
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
            <xsl:call-template name="cibtr:HelperDenormalizedSpace">
              <xsl:with-param name="Source" select="."/>
              <xsl:with-param name="InnerSimulation" select="$InnerSimulation"/>
            </xsl:call-template>
            <xsl:call-template name="cibtr:HelperIdentity"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="cibtr:HelperIdentity"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:for-each>
  <!-- E: special-casing nvpair -->
</xsl:template>

<!--
 Source ctxt:    (primitive|template)/meta_attributes
 Target ctxt:    (primitive|template)/meta_attributes
 Target-inv ctxt:N/A
 Dependencies:   N/A
 -->
<xsl:template name="cibtr:ProcessRscMetaAttributes">
  <xsl:param name="Source"/>
  <xsl:param name="InnerSimulation" select="false()"/>
  <xsl:param name="InnerPass">
    <xsl:choose>
      <xsl:when test="$InnerSimulation">
        <xsl:value-of select="''"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="cibtr:ProcessRscMetaAttributes">
          <xsl:with-param name="Source" select="$Source"/>
          <xsl:with-param name="InnerSimulation" select="true()"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:param>

  <!-- B: special-casing nvpair -->
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
                      select="$cibtr:MapResourceMetaAttributes/cibtr:replace[
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
                                      $cibtr:MapResourceMetaAttributes/cibtr:replace[
                                        @what = current()/@name
                                        and
                                        (
                                          @in-case-of
                                          and
                                          contains(concat('|', @in-case-of, '|'),
                                                   concat('|', current()/@value, '|'))
                                        )
                                      ]
                                    )
                                  )
                                )
                              ]"/>
        <xsl:if test="$InnerPass = 'TRIGGER-MSG'">
          <xsl:call-template name="cibtr:MapMsg">
            <xsl:with-param name="Context"
                            select="concat(../../@id,
                                           ' (meta=', ../@id,
                                           ')')"/>
            <xsl:with-param name="Replacement" select="$Replacement"/>
          </xsl:call-template>
        </xsl:if>
        <xsl:choose>
          <xsl:when test="$Replacement
                          and
                          not(string($Replacement/@with))">
            <!-- drop (move-over code missing) -->
          </xsl:when>
          <xsl:when test="$Replacement">
            <!-- plain rename -->
            <xsl:variable name="SimulateFollowingSiblings">
              <!-- prevent generating redundant name-value pairs -->
              <xsl:for-each select="(..|../following-sibling::meta_attributes)[
                                      not(rule)
                                    ]">
                <xsl:if test="$InnerPass != 'TRIGGER-RECURSION'">
                  <xsl:call-template name="cibtr:ProcessRscMetaAttributes">
                    <xsl:with-param name="Source" select="."/>
                    <xsl:with-param name="InnerSimulation" select="true()"/>
                    <xsl:with-param name="InnerPass" select="'TRIGGER-RECURSION'"/>
                  </xsl:call-template>
                </xsl:if>
              </xsl:for-each>
            </xsl:variable>
            <xsl:choose>
              <!-- instead of HelperDenormalizedSpace -->
              <xsl:when test="$InnerSimulation">
                <xsl:value-of select="concat(generate-id(), '@', $Replacement/@with, ' ')"/>
              </xsl:when>
              <xsl:otherwise>
                <xsl:if test="not(
                                contains($SimulateFollowingSiblings,
                                         concat($Replacement/@with, ' '))
                              )
                              or
                              generate-id()
                              =
                              substring-before($SimulateFollowingSiblings,
                                               concat('@', $Replacement/@with))">
                  <xsl:call-template name="cibtr:HelperDenormalizedSpace">
                    <xsl:with-param name="Source" select="."/>
                    <xsl:with-param name="InnerSimulation" select="$InnerSimulation"/>
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
              </xsl:otherwise>
            </xsl:choose>
          </xsl:when>
          <xsl:otherwise>
            <xsl:call-template name="cibtr:HelperDenormalizedSpace">
              <xsl:with-param name="Source" select="."/>
              <xsl:with-param name="InnerSimulation" select="$InnerSimulation"/>
            </xsl:call-template>
            <xsl:call-template name="cibtr:HelperIdentity"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="cibtr:HelperIdentity"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:for-each>
  <!-- E: special-casing nvpair -->
</xsl:template>

<!--
 Source ctxt:    (primitive|template)/operations/op/instance_attributes
 Target ctxt:    (primitive|template)/operations/op/instance_attributes
 Target-inv ctxt:(primitive|template)/operations/op/meta_attributes
 Dependencies:   ProcessNonattrOpMetaAttributes [inverse only]
 -->
<xsl:template name="cibtr:ProcessOpInstanceAttributes">
  <xsl:param name="Source"/>
  <xsl:param name="InverseMode" select="false()"/>
  <xsl:param name="InnerSimulation" select="false()"/>
  <xsl:param name="InnerPass">
    <xsl:choose>
      <xsl:when test="$InnerSimulation">
        <xsl:value-of select="''"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="cibtr:ProcessOpInstanceAttributes">
          <xsl:with-param name="Source" select="$Source"/>
          <xsl:with-param name="InnerSimulation" select="true()"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:param>

  <xsl:variable name="EnclosingTag" select="../../.."/>

  <!-- B: special-casing nvpair -->
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
                      select="$cibtr:MapResourcesOperationInstanceAttributes/cibtr:replace[
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
                                      $cibtr:MapResourcesOperationInstanceAttributes/cibtr:replace[
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
        <xsl:if test="$InnerPass = 'TRIGGER-MSG'">
          <xsl:call-template name="cibtr:MapMsg">
            <xsl:with-param name="Context"
                            select="concat(../../@id,
                                           ' (rsc=', $EnclosingTag/@id,
                                           ', meta=', ../@id,
                                           ')')"/>
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
                <xsl:call-template name="cibtr:ProcessAttrOpMetaAttributes">
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
              <xsl:variable name="SimulateFollowingSiblingsMeta">
                <!-- cf. similar handling in ProcessAttrOpMetaAttributes,
                     but this is more convoluted -->
                <xsl:for-each select="(../following-sibling::meta_attributes
                                       |../../following-sibling::op/meta_attributes)[
                                        not(rule)
                                      ]">
                  <xsl:call-template name="cibtr:ProcessNonattrOpMetaAttributes">
                    <xsl:with-param name="Source" select="."/>
                    <xsl:with-param name="InverseMode" select="true()"/>
                    <xsl:with-param name="InnerSimulation" select="true()"/>
                  </xsl:call-template>
                </xsl:for-each>
              </xsl:variable>
              <xsl:variable name="SimulateFollowingSiblingsInstance">
                <xsl:for-each select="../following-sibling::instance_attributes[
                                        not(rule)
                                      ]">
                  <xsl:call-template name="cibtr:ProcessOpInstanceAttributes">
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
                              contains($SimulateFollowingSiblingsInstance,
                                       concat(@name, ' '))
                            )">
                <!-- cf. trick C. (indicate for inverse mode) -->
                <xsl:choose>
                  <xsl:when test="$InnerSimulation">
                    <!-- instead of HelperDenormalizedSpace -->
                    <xsl:value-of select="concat(@name, ' ')"/>
                  </xsl:when>
                  <xsl:otherwise>
                    <xsl:call-template name="cibtr:HelperDenormalizedSpace">
                      <xsl:with-param name="Source" select="."/>
                      <xsl:with-param name="InnerSimulation" select="$InnerSimulation"/>
                    </xsl:call-template>
                    <xsl:copy>
                      <xsl:apply-templates select="@*"
                                           mode="cibtr:main"/>
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
            <xsl:call-template name="cibtr:HelperDenormalizedSpace">
              <xsl:with-param name="Source" select="."/>
              <xsl:with-param name="InnerSimulation" select="$InnerSimulation"/>
            </xsl:call-template>
            <xsl:call-template name="cibtr:HelperIdentity"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:when>
      <xsl:when test="$InverseMode
                      or
                      self::comment()">
        <!-- drop -->
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="cibtr:HelperIdentity"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:for-each>
  <!-- E: special-casing nvpair -->
</xsl:template>

<!--
 Source ctxt:    (primitive|template)/operations/op/meta_attributes
                 (primitive|template)/operations/op/instance_attributes (inverse only)
 Target ctxt:    (primitive|template)/operations/op/meta_attributes
 Target-inv ctxt:(primitive|template)/meta_attributes
 Dependencies:   ProcessAttrOpMetaAttributes
                 ProcessNonattrOpMetaAttributes
 -->
<xsl:template name="cibtr:ProcessNonattrOpMetaAttributes">
  <xsl:param name="Source"/>
  <xsl:param name="InverseMode" select="false()"/>
  <xsl:param name="InnerSimulation" select="false()"/>
  <xsl:param name="InnerPass">
    <xsl:choose>
      <xsl:when test="$InnerSimulation">
        <xsl:value-of select="''"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="cibtr:ProcessNonattrOpMetaAttributes">
          <xsl:with-param name="Source" select="$Source"/>
          <xsl:with-param name="InnerSimulation" select="true()"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:param>

  <xsl:variable name="EnclosingTag" select="../../.."/>

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
                      select="$cibtr:MapResourcesOperation/cibtr:replace[
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
                                      $cibtr:MapResourcesOperation/cibtr:replace[
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
        <xsl:if test="$InnerPass = 'TRIGGER-MSG'">
          <xsl:call-template name="cibtr:MapMsg">
            <xsl:with-param name="Context"
                            select="concat(../../@id,
                                           ' (rsc=', $EnclosingTag/@id,
                                           ', meta=', ../@id,
                                           ')')"/>
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
            <xsl:if test="$InverseMode">
              <xsl:variable name="SimulateAttrOverrides">
                <xsl:for-each select="../../../op">
                  <xsl:call-template name="cibtr:ProcessAttrOpMetaAttributes">
                    <xsl:with-param name="Source" select="."/>
                    <xsl:with-param name="InverseMode" select="true()"/>
                    <xsl:with-param name="InnerSimulation" select="true()"/>
                  </xsl:call-template>
                </xsl:for-each>
              </xsl:variable>
              <xsl:if test="not(
                              contains($SimulateAttrOverrides,
                                       concat(@name, ' '))
                            )">
                <!-- do not override; do not collide with:
                     - newly added from op/@* (see last condition above)
                     - existing - actually subsumed with the previous point
                     - successors sourced like this (see below)
                     and if coming from op/instance_attributes, add also
                     - any meta_attributes sourced like this -->
                <xsl:variable name="SimulateFollowingSiblings">
                  <!-- cf. similar handling in ProcessAttrOpMetaAttributes,
                       but this is more convoluted -->
                  <xsl:if test="name(..) = 'meta_attributes'">
                    <xsl:for-each select="(../following-sibling::meta_attributes
                                           |../../following-sibling::op/meta_attributes)[
                                            not(rule)
                                          ]">
                      <xsl:call-template name="cibtr:ProcessNonattrOpMetaAttributes">
                        <xsl:with-param name="Source" select="."/>
                        <xsl:with-param name="InverseMode" select="true()"/>
                        <xsl:with-param name="InnerSimulation" select="true()"/>
                      </xsl:call-template>
                    </xsl:for-each>
                  </xsl:if>
                  <xsl:if test="name(..) = 'instance_attributes'">
                    <xsl:for-each select="(../following-sibling::instance_attributes
                                           |../../following-sibling::op/instance_attributes
                                           |../../meta_attributes
                                           |../../../op/meta_attributes)[
                                            not(rule)
                                          ]">
                      <xsl:call-template name="cibtr:ProcessNonattrOpMetaAttributes">
                        <xsl:with-param name="Source" select="."/>
                        <xsl:with-param name="InverseMode" select="true()"/>
                        <xsl:with-param name="InnerSimulation" select="true()"/>
                      </xsl:call-template>
                    </xsl:for-each>
                  </xsl:if>
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
                    <!-- instead of HelperDenormalizedSpace -->
                    <xsl:when test="$InnerSimulation">
                      <xsl:value-of select="concat(@name, ' ')"/>
                    </xsl:when>
                    <xsl:otherwise>
                      <xsl:copy>
                        <xsl:apply-templates select="@*"
                                             mode="cibtr:main"/>
                      </xsl:copy>
                    </xsl:otherwise>
                  </xsl:choose>
                </xsl:if>
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
            <xsl:call-template name="cibtr:HelperDenormalizedSpace">
              <xsl:with-param name="Source" select="."/>
              <xsl:with-param name="InnerSimulation" select="$InnerSimulation"/>
            </xsl:call-template>
            <xsl:call-template name="cibtr:HelperIdentity"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:when>
      <xsl:when test="$InverseMode
                      or
                      self::comment()">
        <!-- drop -->
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="cibtr:HelperIdentity"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:for-each>
</xsl:template>

<!--
 Source ctxt:    (primitive|template)/operations/op
 Target ctxt:    (primitive|template)/operations/op/meta_attributes
 Target-inv ctxt:(primitive|template)/meta_attributes
 Dependencies:   ProcessNonattrOpMetaAttributes [non-inverse only]
                 ProcessOpInstanceAttributes [non-inverse only]
 -->
<xsl:template name="cibtr:ProcessAttrOpMetaAttributes">
  <xsl:param name="Source"/>
  <xsl:param name="InverseMode" select="false()"/>
  <xsl:param name="InnerSimulation" select="false()"/>
  <xsl:param name="InnerPass">
    <xsl:choose>
      <xsl:when test="$InnerSimulation">
        <xsl:value-of select="''"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="cibtr:ProcessAttrOpMetaAttributes">
          <xsl:with-param name="Source" select="$Source"/>
          <xsl:with-param name="InverseMode" select="$InverseMode"/>
          <xsl:with-param name="InnerSimulation" select="true()"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:param>

  <xsl:variable name="EnclosingTag" select="../.."/>

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
                  $InnerSimulation">
      <xsl:call-template name="cibtr:HelperDenormalizedSpace">
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
                    select="$cibtr:MapResourcesOperation/cibtr:replace[
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
                                    $cibtr:MapResourcesOperation/cibtr:replace[
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
      <xsl:if test="$InnerPass = 'TRIGGER-MSG'">
        <xsl:call-template name="cibtr:MapMsg">
          <xsl:with-param name="Context"
                                select="concat(../@id,
                                               ' (rsc=', $EnclosingTag/@id,
                                               ')')"/>
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
              <xsl:call-template name="cibtr:ProcessAttrOpMetaAttributes">
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
          <xsl:copy/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:for-each>
    <!-- E: special-casing @* -->

    <xsl:if test="not($InverseMode)">
      <!-- Look ahead if there are any meta-like instance_attibutes to
           be propagated next door, into existing/new meta_attributes -->
      <xsl:variable name="ProcessedInverseNonruleOpInstanceAttributes">
        <xsl:for-each select="instance_attributes[not(rule)]">
          <xsl:call-template name="cibtr:ProcessOpInstanceAttributes">
            <xsl:with-param name="Source" select="."/>
            <xsl:with-param name="InnerSimulation" select="true()"/>
            <xsl:with-param name="InverseMode" select="true()"/>
            <xsl:with-param name="InnerPass"
                            select="substring-after(
                                      concat(
                                        string($InnerSimulation),
                                        'TRIGGER-MSG'
                                      ),
                                     'true'
                                    )"/>
          </xsl:call-template>
        </xsl:for-each>
      </xsl:variable>
      <!-- B: special-casing instance_attributes|meta_attributes -->
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
          <xsl:when test="self::instance_attributes">
            <xsl:variable name="ProcessedOpInstanceAttributes">
              <xsl:call-template name="cibtr:ProcessOpInstanceAttributes">
                <xsl:with-param name="Source" select="."/>
                <xsl:with-param name="InnerSimulation" select="true()"/>
              </xsl:call-template>
            </xsl:variable>
            <!-- cf. trick A. -->
            <xsl:if test="normalize-space($ProcessedOpInstanceAttributes)
                          != $ProcessedOpInstanceAttributes">
              <xsl:copy>
                <xsl:apply-templates select="@*"
                                     mode="cibtr:main"/>
                <xsl:call-template name="cibtr:ProcessOpInstanceAttributes">
                  <xsl:with-param name="Source" select="."/>
                  <xsl:with-param name="InnerSimulation" select="$InnerSimulation"/>
                  <!-- cf. trick E. -->
                  <xsl:with-param name="InnerPass" select="$ProcessedOpInstanceAttributes"/>
                </xsl:call-template>
              </xsl:copy>
            </xsl:if>
          </xsl:when>
          <xsl:when test="self::meta_attributes">
            <xsl:variable name="ProcessedOpMetaAttributes">
              <xsl:call-template name="cibtr:ProcessNonattrOpMetaAttributes">
                <xsl:with-param name="Source" select="."/>
                <xsl:with-param name="InnerSimulation" select="true()"/>
                <xsl:with-param name="InnerPass"
                                select="substring-after(
                                          concat(
                                            string($InnerSimulation),
                                            'TRIGGER-MSG'
                                          ),
                                         'true'
                                        )"/>
              </xsl:call-template>
            </xsl:variable>
            <!-- cf. trick A.;
                 possibly piggy-back instance_attributes (if any per
                 above look ahead) to first suitable (not rules-driven)
                 meta_attributes set... -->
            <xsl:if test="normalize-space($ProcessedOpMetaAttributes)
                          != $ProcessedOpMetaAttributes
                          or
                          (
                            not(rule)
                            and
                            not(preceding-sibling::meta_attributes[not(rule)])
                            and
                            normalize-space($ProcessedInverseNonruleOpInstanceAttributes)
                            != $ProcessedInverseNonruleOpInstanceAttributes
                          )">
              <xsl:copy>
                <xsl:apply-templates select="@*"
                                     mode="cibtr:main"/>
                <xsl:if test="normalize-space($ProcessedOpMetaAttributes)
                              != $ProcessedOpMetaAttributes">
                  <xsl:call-template name="cibtr:ProcessNonattrOpMetaAttributes">
                    <xsl:with-param name="Source" select="."/>
                    <xsl:with-param name="InnerSimulation" select="$InnerSimulation"/>
                    <!-- cf. trick E. -->
                    <xsl:with-param name="InnerPass" select="$ProcessedOpMetaAttributes"/>
                  </xsl:call-template>
                </xsl:if>
                <xsl:if test="not(rule)
                              and
                              not(preceding-sibling::meta_attributes[not(rule)])
                              and
                              normalize-space($ProcessedInverseNonruleOpInstanceAttributes)
                              != $ProcessedInverseNonruleOpInstanceAttributes">
                  <xsl:for-each select="../instance_attributes[not(rule)]">
                    <xsl:call-template name="cibtr:ProcessOpInstanceAttributes">
                      <xsl:with-param name="Source" select="."/>
                      <xsl:with-param name="InnerSimulation" select="$InnerSimulation"/>
                      <xsl:with-param name="InverseMode" select="true()"/>
                    </xsl:call-template>
                  </xsl:for-each>
                </xsl:if>
              </xsl:copy>
            </xsl:if>
          </xsl:when>
          <xsl:otherwise>
            <xsl:call-template name="cibtr:HelperIdentity"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:for-each>
      <!-- E: special-casing instance_attributes|meta_attributes -->

      <!-- ...or roll out brand new meta_attributes, first collectively
           for no-rules instances... -->
      <xsl:if test="not(meta_attributes[not(rule)])
                    and
                    normalize-space($ProcessedInverseNonruleOpInstanceAttributes)
                    != $ProcessedInverseNonruleOpInstanceAttributes">
        <meta_attributes id="{concat('_2TO3_', @id, '-meta')}">
          <xsl:for-each select="instance_attributes[not(rule)]">
            <xsl:call-template name="cibtr:ProcessOpInstanceAttributes">
              <xsl:with-param name="Source" select="."/>
              <xsl:with-param name="InnerSimulation" select="$InnerSimulation"/>
              <xsl:with-param name="InverseMode" select="true()"/>
            </xsl:call-template>
          </xsl:for-each>
          <xsl:apply-templates select="text()[position() = last()]"
                               mode="cibtr:main"/>
        </meta_attributes>
        <xsl:apply-templates select="text()[position() = last()]"
                             mode="cibtr:main"/>
      </xsl:if>

      <!-- ...then individually for rules-driven ones -->
      <xsl:for-each select="instance_attributes[rule]">
        <xsl:variable name="ProcessedInverseRuleOpInstanceAttributes">
          <xsl:call-template name="cibtr:ProcessOpInstanceAttributes">
            <xsl:with-param name="Source" select="."/>
            <xsl:with-param name="InnerSimulation" select="true()"/>
            <xsl:with-param name="InverseMode" select="true()"/>
            <xsl:with-param name="InnerPass"
                            select="substring-after(
                                      concat(
                                        string($InnerSimulation),
                                        'TRIGGER-MSG'
                                      ),
                                     'true'
                                    )"/>
          </xsl:call-template>
        </xsl:variable>
        <!-- cf. trick A. -->
        <xsl:if test="normalize-space($ProcessedInverseRuleOpInstanceAttributes)
                      != $ProcessedInverseRuleOpInstanceAttributes">
          <meta_attributes>
            <xsl:apply-templates select="@*[
                                           name() != 'id'
                                         ]"
                                 mode="cibtr:main"/>
            <xsl:attribute name='id'>
              <xsl:value-of select="concat('_2TO3_', @id)"/>
            </xsl:attribute>
            <xsl:apply-templates select="node()[
                                           name() != 'nvpair'
                                         ]"
                                 mode="cibtr:main"/>
            <xsl:call-template name="cibtr:ProcessOpInstanceAttributes">
              <xsl:with-param name="Source" select="."/>
              <xsl:with-param name="InverseMode" select="true()"/>
              <!-- cf. trick E. -->
              <xsl:with-param name="InnerPass" select="$ProcessedInverseRuleOpInstanceAttributes"/>
            </xsl:call-template>
            <xsl:apply-templates select="text()[position() = last()]"
                                 mode="cibtr:main"/>
          </meta_attributes>
        </xsl:if>
      </xsl:for-each>
    </xsl:if>
    </xsl:element>
  </xsl:if>
</xsl:template>

<!--
 Source ctxt:    configuration
 Target ctxt:    {op,rsc}_defaults/meta_attributes [per $Variant, see below]
 Target-inv ctxt:N/A
 Dependencies:   ProcessClusterProperties

 Variant:        'op_defaults' | 'rsc_defaults'
 -->
<xsl:template name="cibtr:ProcessDefaultsNonruleClusterProperties">
  <xsl:param name="Source"/>
  <xsl:param name="Variant"/>
  <xsl:param name="InnerSimulation" select="false()"/>
  <xsl:param name="InnerPass">
    <xsl:choose>
      <xsl:when test="$InnerSimulation">
        <xsl:value-of select="''"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="cibtr:ProcessDefaultsNonruleClusterProperties">
          <xsl:with-param name="Source" select="$Source"/>
          <xsl:with-param name="Variant" select="$Variant"/>
          <xsl:with-param name="InnerSimulation" select="true()"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:param>

  <xsl:choose>
    <xsl:when test="$Source/*[name() = $Variant]/meta_attributes[
                      not(rule)
                    ]">
      <xsl:call-template name="cibtr:ProcessClusterProperties">
        <xsl:with-param name="Source"
                        select="$Source/crm_config/cluster_property_set[
                                  not(rule)
                                ]"/>
        <xsl:with-param name="InverseMode"
                        select="$Source/*[name() = $Variant]/meta_attributes[
                                  not(rule)
                                ]"/>
        <xsl:with-param name="InnerSimulation" select="$InnerSimulation"/>
      </xsl:call-template>
    </xsl:when>
    <xsl:otherwise>
      <xsl:call-template name="cibtr:ProcessClusterProperties">
        <xsl:with-param name="Source"
                      select="$Source/crm_config/cluster_property_set[
                                  not(rule)
                                ]"/>
        <xsl:with-param name="InverseMode"
                        select="$Variant"/>
        <xsl:with-param name="InnerSimulation" select="$InnerSimulation"/>
      </xsl:call-template>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<!--
 Source ctxt:    configuration
 Target ctxt:    {op,rsc}_defaults/meta_attributes [per $Variant, see below]
 Target-inv ctxt:N/A
 Dependencies:   ProcessClusterProperties

 Variant:        'op_defaults' | 'rsc_defaults'
 -->
<xsl:template name="cibtr:ProcessDefaultsRuleClusterProperties">
  <xsl:param name="Source"/>
  <xsl:param name="Variant"/>
  <xsl:param name="InnerSimulation" select="false()"/>
  <xsl:param name="InnerPass">
    <xsl:choose>
      <xsl:when test="$InnerSimulation">
        <xsl:value-of select="''"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="cibtr:ProcessDefaultsRuleClusterProperties">
          <xsl:with-param name="Source" select="$Source"/>
          <xsl:with-param name="Variant" select="$Variant"/>
          <xsl:with-param name="InnerSimulation" select="true()"/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:param>

  <xsl:for-each select="crm_config/cluster_property_set[
                          rule
                        ]">
    <xsl:variable name="ProcessedPartial">
      <xsl:call-template name="cibtr:ProcessClusterProperties">
        <xsl:with-param name="Source" select="$Source"/>
        <xsl:with-param name="InverseMode" select="$Variant"/>
        <xsl:with-param name="InnerSimulation" select="true()"/>
        <xsl:with-param name="InnerPass" select="'TRIGGER-MSG'"/>
      </xsl:call-template>
    </xsl:variable>
    <xsl:if test="normalize-space($ProcessedPartial)
                  != $ProcessedPartial">
      <meta_attributes id="{concat('_2TO3_', @id)}">
        <xsl-copy-of select="rule"/>
        <xsl:call-template name="cibtr:ProcessClusterProperties">
          <xsl:with-param name="Source" select="$Source"/>
          <xsl:with-param name="InverseMode" select="$Variant"/>
        </xsl:call-template>
      </meta_attributes>
    </xsl:if>
  </xsl:for-each>
</xsl:template>

<!--

 ACTUAL TRANSFORMATION

 -->

<xsl:template match="cib" mode="cibtr:main">
  <xsl:copy>
    <xsl:apply-templates select="@*"
                         mode="cibtr:main"/>
    <xsl:attribute name="validate-with">
      <xsl:value-of select="concat('pacemaker-', $cibtr:cib-min-ver)"/>
    </xsl:attribute>
    <xsl:apply-templates select="node()"
                         mode="cibtr:main"/>
  </xsl:copy>
</xsl:template>

<xsl:template match="cluster_property_set" mode="cibtr:main">
  <xsl:variable name="ProcessedClusterProperties">
    <xsl:call-template name="cibtr:ProcessClusterProperties">
      <xsl:with-param name="Source" select="."/>
      <xsl:with-param name="InnerSimulation" select="true()"/>
      <xsl:with-param name="InnerPass" select="'TRIGGER-MSG'"/>
    </xsl:call-template>
  </xsl:variable>
  <xsl:if test="normalize-space($ProcessedClusterProperties)
                != $ProcessedClusterProperties">
    <xsl:copy>
      <xsl:apply-templates select="@*"
                           mode="cibtr:main"/>
      <xsl:call-template name="cibtr:ProcessClusterProperties">
        <xsl:with-param name="Source" select="."/>
        <!-- cf. trick E. -->
        <xsl:with-param name="InnerPass" select="$ProcessedClusterProperties"/>
      </xsl:call-template>
    </xsl:copy>
  </xsl:if>
</xsl:template>

<xsl:template match="rsc_colocation" mode="cibtr:main">
  <xsl:copy>
    <xsl:for-each select="@*">
      <xsl:variable name="Replacement"
                    select="$cibtr:MapConstraintsColocation/cibtr:replace[
                              @what = name(current())
                            ]"/>
      <xsl:call-template name="cibtr:MapMsg">
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
    <xsl:apply-templates select="node()"
                         mode="cibtr:main"/>
  </xsl:copy>
</xsl:template>

<xsl:template match="node" mode="cibtr:main">
  <xsl:copy>
    <xsl:for-each select="@*">
      <xsl:variable name="Replacement"
                    select="$cibtr:MapClusterNode/cibtr:replace[
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
                                    $cibtr:MapClusterNode/cibtr:replace[
                                      @what = name(current())
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
      <xsl:call-template name="cibtr:MapMsg">
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
    <xsl:apply-templates select="node()"
                         mode="cibtr:main"/>
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
 -->
<xsl:template match="primitive|template" mode="cibtr:main">
  <xsl:copy>
    <xsl:apply-templates select="@*"
                         mode="cibtr:main"/>
    <!-- B: special-casing operations|instance_attributes|meta_attributes -->
    <xsl:for-each select="node()">
      <xsl:choose>
        <xsl:when test="self::operations">
          <xsl:copy>
            <xsl:apply-templates select="@*"
                                 mode="cibtr:main"/>
            <!-- B: special-casing op -->
            <xsl:for-each select="node()">
              <xsl:choose>
                <xsl:when test="self::op">
                  <!-- process @*|meta_attributes/nvpair
                       (keep/drop/move elsewhere) -->
                  <xsl:call-template name="cibtr:ProcessAttrOpMetaAttributes">
                    <xsl:with-param name="Source" select="."/>
                  </xsl:call-template>
                </xsl:when>
                <xsl:otherwise>
                  <xsl:call-template name="cibtr:HelperIdentity"/>
                </xsl:otherwise>
              </xsl:choose>
            </xsl:for-each>
            <!-- E: special-casing op -->
          </xsl:copy>
        </xsl:when>
        <xsl:when test="self::instance_attributes">
          <xsl:variable name="ProcessedRscInstanceAttributes">
            <xsl:call-template name="cibtr:ProcessRscInstanceAttributes">
              <xsl:with-param name="Source" select="."/>
              <xsl:with-param name="InnerSimulation" select="true()"/>
              <xsl:with-param name="InnerPass" select="'TRIGGER-MSG'"/>
            </xsl:call-template>
          </xsl:variable>
          <!-- cf. trick A. -->
          <xsl:if test="normalize-space($ProcessedRscInstanceAttributes)
                        != $ProcessedRscInstanceAttributes">
            <xsl:copy>
              <xsl:apply-templates select="@*"
                                   mode="cibtr:main"/>
              <xsl:call-template name="cibtr:ProcessRscInstanceAttributes">
                <xsl:with-param name="Source" select="."/>
                <!-- cf. trick E. -->
                <xsl:with-param name="InnerPass" select="$ProcessedRscInstanceAttributes"/>
              </xsl:call-template>
            </xsl:copy>
          </xsl:if>
        </xsl:when>
        <xsl:when test="self::meta_attributes">
          <xsl:variable name="ProcessedRscMetaAttributes">
            <xsl:call-template name="cibtr:ProcessRscMetaAttributes">
              <xsl:with-param name="Source" select="."/>
              <xsl:with-param name="InnerSimulation" select="true()"/>
              <xsl:with-param name="InnerPass" select="'TRIGGER-MSG'"/>
            </xsl:call-template>
          </xsl:variable>
          <!-- cf. trick A. -->
          <xsl:if test="normalize-space($ProcessedRscMetaAttributes)
                        != $ProcessedRscMetaAttributes">
            <xsl:copy>
              <xsl:apply-templates select="@*"
                                   mode="cibtr:main"/>
              <xsl:call-template name="cibtr:ProcessRscMetaAttributes">
                <xsl:with-param name="Source" select="."/>
                <!-- cf. trick E. -->
                <xsl:with-param name="InnerPass" select="$ProcessedRscMetaAttributes"/>
              </xsl:call-template>
            </xsl:copy>
          </xsl:if>
        </xsl:when>
        <xsl:otherwise>
          <xsl:call-template name="cibtr:HelperIdentity"/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:for-each>
    <!-- E: special-casing operations|instance_attributes|meta_attributes -->

    <!-- add as last meta_attributes block... -->

    <!-- ...indirectly from op attributes -->
    <xsl:variable name="ToPropagateFromOp">
      <xsl:for-each select="operations/op">
        <xsl:call-template name="cibtr:ProcessAttrOpMetaAttributes">
          <xsl:with-param name="Source" select="."/>
          <xsl:with-param name="InverseMode" select="true()"/>
          <xsl:with-param name="InnerSimulation" select="true()"/>
          <xsl:with-param name="InnerPass" select="'TRIGGER-MSG'"/>
        </xsl:call-template>
      </xsl:for-each>
    </xsl:variable>
    <!-- cf. trick A. -->
    <xsl:if test="normalize-space($ToPropagateFromOp)
                  != $ToPropagateFromOp">
      <meta_attributes id="{concat('_2TO3_', @id, '-meta')}">
        <xsl:for-each select="operations/op">
          <xsl:call-template name="cibtr:ProcessAttrOpMetaAttributes">
            <xsl:with-param name="Source" select="."/>
            <xsl:with-param name="InverseMode" select="true()"/>
          </xsl:call-template>
        </xsl:for-each>
        <xsl:apply-templates select="text()[position() = last()]"
                             mode="cibtr:main"/>
      </meta_attributes>
      <xsl:apply-templates select="text()[position() = last()]"
                           mode="cibtr:main"/>
    </xsl:if>

    <!-- ...directly by picking existing nvpairs of
         meta_attributes|instance_attributes -->
    <xsl:for-each select="operations/op/meta_attributes
                          |operations/op/instance_attributes">
      <xsl:variable name="ProcessedOpMetaAttributes">
        <xsl:call-template name="cibtr:ProcessNonattrOpMetaAttributes">
          <xsl:with-param name="Source" select="."/>
          <xsl:with-param name="InverseMode" select="true()"/>
          <xsl:with-param name="InnerSimulation" select="true()"/>
        </xsl:call-template>
      </xsl:variable>
      <!-- cf. trick A. -->
      <xsl:if test="normalize-space($ProcessedOpMetaAttributes)
                    != $ProcessedOpMetaAttributes">
        <!-- cannot xsl:copy, need to settle on meta_attributes -->
        <meta_attributes>
          <xsl:apply-templates select="@*[
                                         name() != 'id'
                                       ]"
                               mode="cibtr:main"/>
          <xsl:attribute name='id'>
            <xsl:value-of select="concat('_2TO3_', @id)"/>
          </xsl:attribute>
          <xsl:apply-templates select="node()[
                                         name() != 'nvpair'
                                       ]"
                               mode="cibtr:main"/>
          <xsl:call-template name="cibtr:ProcessNonattrOpMetaAttributes">
            <xsl:with-param name="Source" select="."/>
            <xsl:with-param name="InverseMode" select="true()"/>
            <!-- cf. trick E. -->
            <xsl:with-param name="InnerPass" select="$ProcessedOpMetaAttributes"/>
          </xsl:call-template>
          <xsl:apply-templates select="text()[position() = last()]"
                               mode="cibtr:main"/>
        </meta_attributes>
        <xsl:apply-templates select="text()[position() = last()]"
                             mode="cibtr:main"/>
      </xsl:if>
    </xsl:for-each>
  </xsl:copy>
</xsl:template>

<xsl:template match="configuration" mode="cibtr:main">
  <xsl:variable name="Configuration" select="."/>
  <xsl:variable name="ProcessedOpDefaultsNonruleClusterProperties">
    <xsl:call-template name="cibtr:ProcessDefaultsNonruleClusterProperties">
      <xsl:with-param name="Source" select="$Configuration"/>
      <xsl:with-param name="Variant" select="'op_defaults'"/>
      <xsl:with-param name="InnerSimulation" select="true()"/>
    </xsl:call-template>
  </xsl:variable>
  <xsl:variable name="ProcessedRscDefaultsNonruleClusterProperties">
    <xsl:call-template name="cibtr:ProcessDefaultsNonruleClusterProperties">
      <xsl:with-param name="Source" select="$Configuration"/>
      <xsl:with-param name="Variant" select="'rsc_defaults'"/>
      <xsl:with-param name="InnerSimulation" select="true()"/>
    </xsl:call-template>
  </xsl:variable>
  <xsl:variable name="ProcessedOpDefaultsRuleClusterProperties">
    <xsl:call-template name="cibtr:ProcessDefaultsNonruleClusterProperties">
      <xsl:with-param name="Source" select="$Configuration"/>
      <xsl:with-param name="Variant" select="'op_defaults'"/>
      <xsl:with-param name="InnerSimulation" select="true()"/>
    </xsl:call-template>
  </xsl:variable>
  <xsl:variable name="ProcessedRscDefaultsRuleClusterProperties">
    <xsl:call-template name="cibtr:ProcessDefaultsNonruleClusterProperties">
      <xsl:with-param name="Source" select="$Configuration"/>
      <xsl:with-param name="Variant" select="'rsc_defaults'"/>
      <xsl:with-param name="InnerSimulation" select="true()"/>
    </xsl:call-template>
  </xsl:variable>

  <xsl:copy>
    <xsl:apply-templates select="@*"
                         mode="cibtr:main"/>
    <!-- B: special-casing {op,rsc}_defaults -->
    <xsl:for-each select="node()">
      <xsl:choose>
        <xsl:when test="self::op_defaults|self::rsc_defaults">
          <xsl:variable name="WhichDefaults" select="name()"/>
          <xsl:copy>
            <xsl:apply-templates select="@*"
                                 mode="cibtr:main"/>
            <!-- B: special-casing meta_attributes -->
            <xsl:for-each select="node()">
              <xsl:copy>
                <xsl:choose>
                  <xsl:when test="self::meta_attributes[
                                    not(rule)
                                    and
                                    not(
                                      preceding-sibling::meta_attributes[
                                        not(rule)
                                      ]
                                    )
                                  ]">
                  <xsl:apply-templates select="@*|node()"
                                       mode="cibtr:main"/>
                    <xsl:if test="$WhichDefaults = 'op_defaults'
                                  or
                                  $WhichDefaults = 'rsc_defaults'">
                      <xsl:call-template name="cibtr:ProcessDefaultsNonruleClusterProperties">
                        <xsl:with-param name="Source" select="$Configuration"/>
                        <xsl:with-param name="Variant" select="$WhichDefaults"/>
                      </xsl:call-template>
                    </xsl:if>
                  </xsl:when>
                  <xsl:otherwise>
                    <xsl:apply-templates select="@*|node()"
                                         mode="cibtr:main"/>
                  </xsl:otherwise>
                </xsl:choose>
                <xsl:if test="(
                                $WhichDefaults = 'op_defaults'
                                and
                                normalize-space($ProcessedOpDefaultsRuleClusterProperties)
                                != $ProcessedOpDefaultsRuleClusterProperties
                              )
                              or
                              (
                                $WhichDefaults = 'rsc_defaults'
                                and
                                normalize-space($ProcessedRscDefaultsRuleClusterProperties)
                                != $ProcessedRscDefaultsRuleClusterProperties
                              )">
                  <xsl:call-template name="cibtr:ProcessDefaultsRuleClusterProperties">
                    <xsl:with-param name="Source" select="$Configuration"/>
                    <xsl:with-param name="Variant" select="$WhichDefaults"/>
                  </xsl:call-template>
                </xsl:if>
              </xsl:copy>
            </xsl:for-each>
            <!-- E: special-casing meta_attributes -->
          </xsl:copy>
        </xsl:when>
        <xsl:otherwise>
          <xsl:call-template name="cibtr:HelperIdentity"/>
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
            <xsl:call-template name="cibtr:ProcessDefaultsNonruleClusterProperties">
              <xsl:with-param name="Source" select="$Configuration"/>
              <xsl:with-param name="Variant" select="'op_defaults'"/>
            </xsl:call-template>
          </meta_attributes>
        </xsl:if>
        <xsl:call-template name="cibtr:ProcessDefaultsRuleClusterProperties">
          <xsl:with-param name="Source" select="$Configuration"/>
          <xsl:with-param name="Variant" select="'op_defaults'"/>
        </xsl:call-template>
        <xsl:apply-templates select="text()[position() = last()]"
                             mode="cibtr:main"/>
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
            <xsl:call-template name="cibtr:ProcessDefaultsNonruleClusterProperties">
              <xsl:with-param name="Source" select="$Configuration"/>
              <xsl:with-param name="Variant" select="'rsc_defaults'"/>
            </xsl:call-template>
          </meta_attributes>
        </xsl:if>
        <xsl:call-template name="cibtr:ProcessDefaultsRuleClusterProperties">
          <xsl:with-param name="Source" select="$Configuration"/>
          <xsl:with-param name="Variant" select="'rsc_defaults'"/>
        </xsl:call-template>
        <xsl:apply-templates select="text()[position() = last()]"
                             mode="cibtr:main"/>
      </rsc_defaults>
    </xsl:if>
  </xsl:copy>
</xsl:template>

<!-- used in test files to allow in-browser on-the-fly upgrade reports -->
<xsl:template match="processing-instruction()[
                       name() = 'xml-stylesheet'
                       and
                       count(..|/) = 1
                     ]"
              mode="cibtr:main"/>

<xsl:template match="@*|node()" mode="cibtr:main">
  <xsl:call-template name="cibtr:HelperIdentity"/>
</xsl:template>

<!-- mode-less, easy to override kick-off -->
<xsl:template match="/">
  <xsl:call-template name="cibtr:HelperIdentity"/>
</xsl:template>

</xsl:stylesheet>
