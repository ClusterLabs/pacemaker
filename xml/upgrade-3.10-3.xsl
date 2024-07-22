<?xml version="1.0" encoding="UTF-8"?>

<!--
 Use comments liberally as future maintainers may be unfamiliar with XSLT.
 -->

<!--
 upgrade-3.10-3.xsl

 Guarantees after this transformation:
 * There are no lifetime elements.
   * If a lifetime element existed in a location constraint prior to this
     transformation, we drop it. If the lifetime element had multiple top-level
     rules, we nest them inside a single "or" rule; otherwise, we keep the
     top-level lifetime rule as-is. Then we do the following with it:
     * If the constraint did not have a top-level rule, the lifetime-based rule
       becomes the constraint's top-level rule.
     * If the constraint already had a top-level rule, we create a new "and"
       top-level constraint rule, containing the existing top-level constraint
       rule and the lifetime-based rule.
   * If a lifetime element existed in a colocation or order constraint prior to
     this transformation, its rules are in a new location constraint that does
     not apply to any resources. This is in case some other rule references
     them. A rule in a lifetime element may contain a node attribute expression,
     which is now allowed only within a location constraint rule.
 -->

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:import href="upgrade-3.10-common.xsl"/>

<xsl:key name='rule_id' match="rule" use="@id"/>

<!-- Copy everything unaltered by default -->
<xsl:template match="/|@*|node()">
    <xsl:call-template name="identity"/>
</xsl:template>


<!-- Constraints -->

<!--
 Create a new location constraint that doesn't match any resources, to hold the
 defined rules from deleted lifetime elements in colocation and order
 constraints that are still referenced elsewhere (if any)
 -->
<xsl:template match="constraints">
    <!-- All colocation and ordering constraints -->
    <xsl:variable name="coloc_order" select="rsc_colocation|rsc_order"/>

    <!--
     All rules originally defined in colocation/ordering lifetime elements
     -->
    <xsl:variable name="co_lifetime_rules"
                  select="$coloc_order/lifetime/rule
                          [boolean(number(@original))]"/>

    <!--
     Rule IDs from $co_lifetime_rule_ids that will still be referenced somewhere
     after dropping colocation/ordering lifetime elements
     -->
    <xsl:variable name="co_lifetime_live_rules"
                  select="$co_lifetime_rules
                          [count(key('rule_id', @id)/ancestor::lifetime
                                 [parent::rsc_colocation or parent::rsc_order])
                           != count(key('rule_id', @id))]"/>

    <!--
     The rules in $co_lifetime_live_rules are referenced elsewhere, so they need
     definitions. The end of the transformation pipeline would ensure that the
     first remaining occurrence of the rule remains a definition while the rest
     become references. However, a lifetime rule may contain a node attribute
     expression, so its definition should go inside a rsc_location, the last
     remaining element type that supports rules with node attribute expressions.

     It is likely a mistake if some context besides a location constraint or a
     lifetime element references a rule with a node attribute expression in a
     lifetime element. However, it is allowed by the pacemaker-3.10 schema, and
     we want to ensure the upgraded CIB still validates against the
     pacemaker-4.0 schema provided the input CIB validates against the
     pacemaker-3.10 schema.
     -->
    <xsl:copy>
        <xsl:apply-templates select="@*|node()"/>

        <xsl:if test="$co_lifetime_live_rules">
            <xsl:variable name="location_id"
                          select="concat($upgrade_prefix,
                                         'coloc-order-lifetime-rules')"/>

            <!-- New location constraint to hold rules: matches no resources -->
            <xsl:element name="rsc_location">
                <xsl:attribute name="id">
                    <xsl:value-of select="$location_id"/>
                </xsl:attribute>

                <!-- Nothing can come before the beginning-of-string anchor -->
                <xsl:attribute name="rsc-pattern">a^</xsl:attribute>

                <!-- Top-level wrapper rule: score and boolean-op don't matter -->
                <xsl:element name="rule">
                    <xsl:attribute name="id">
                        <xsl:value-of select="concat($location_id, '-rule')"/>
                    </xsl:attribute>
                    <xsl:attribute name="score">-INFINITY</xsl:attribute>

                    <xsl:apply-templates select="$co_lifetime_live_rules"/>
                </xsl:element>
            </xsl:element>
        </xsl:if>
    </xsl:copy>
</xsl:template>

<!--
 Generate an equivalent rule from a constraint's node and score attributes.

 The context node is assumed to be a location constraint with node and score
 attributes.
 -->
<xsl:template name="node_score_rule">
    <xsl:variable name="rule_id"
                  select="concat($upgrade_prefix, @id, '-node-score-rule')"/>

    <xsl:element name="rule">
        <xsl:attribute name="id">
            <xsl:value-of select="$rule_id"/>
        </xsl:attribute>
        <xsl:apply-templates select="@score"/>

        <xsl:element name="expression">
            <xsl:attribute name="id">
                <xsl:value-of select="concat($rule_id, '-expr')"/>
            </xsl:attribute>
            <xsl:attribute name="attribute">#uname</xsl:attribute>
            <xsl:attribute name="operation">eq</xsl:attribute>
            <xsl:attribute name="value">
                <xsl:value-of select="@node"/>
            </xsl:attribute>
        </xsl:element>
    </xsl:element>
</xsl:template>

<!--
 For a lifetime element in a location constraint, nest its rules (joined into
 an "or" rule if there are multiple) inside a top-level rule of the
 constraint.
 * If there was already a top-level rule, nest it alongside the lifetime-based
   rule in a new top-level "and" rule.
 * Otherwise, create a new rule equivalent to the node and score XML attributes,
   and nest it alongside the lifetime-based rule in a new top-level "and" rule.

 For the constraint to apply, at least one of the lifetime rules must apply, and
 either the node XML attribute must match or the existing top-level rule must be
 satisfied.
 -->
<xsl:template match="rsc_location[lifetime]">
    <xsl:copy>
        <!-- Existing attributes (except node and score) and resource sets -->
        <xsl:apply-templates select="@*[(local-name() != 'node')
                                        and (local-name() != 'score')]
                                     |resource_set"/>

        <xsl:element name="rule">
            <!--
             Set a probably-unique ID for the new wrapper rule, based on the
             rsc_location ID
             -->
            <xsl:attribute name="id">
                <xsl:value-of select="concat($upgrade_prefix, @id,
                                             '-lifetime-and-rule')"/>
            </xsl:attribute>
            <xsl:attribute name="boolean-op">and</xsl:attribute>

            <!-- Include existing top-level rule or node/score attributes -->
            <xsl:choose>
                <xsl:when test="rule">
                    <!-- Existing top-level rule -->
                    <xsl:apply-templates select="rule"/>
                </xsl:when>

                <xsl:otherwise>
                    <!-- New rule from node and score attributes -->
                    <xsl:call-template name="node_score_rule"/>
                </xsl:otherwise>
            </xsl:choose>

            <!--
             Lifetime element's rules (either singleton or nested in a new "or"
             rule)
             -->
            <xsl:apply-templates select="lifetime"/>
        </xsl:element>
    </xsl:copy>
</xsl:template>

<!--
 For a lifetime element with multiple rules within a location constraint, nest
 the rules within an "or" wrapper and drop the lifetime element.
 -->
<xsl:template match="rsc_location/lifetime[count(rule) > 1]">
    <xsl:element name="rule">
        <!--
         Set a probably-unique ID for the new wrapper rule, based on the
         rsc_location ID
         -->
        <xsl:attribute name="id">
            <xsl:value-of select="concat($upgrade_prefix, ../@id,
                                         '-lifetime-or-rule')"/>
        </xsl:attribute>
        <xsl:attribute name="boolean-op">or</xsl:attribute>
        <xsl:apply-templates select="rule"/>
    </xsl:element>
</xsl:template>

<!--
 For a lifetime element with only one rule within a location constraint, simply
 drop the lifetime element and keep the rule.
 -->
<xsl:template match="rsc_location/lifetime[count(rule) = 1]">
    <xsl:apply-templates select="rule"/>
</xsl:template>

<!-- Drop lifetime elements within colocation and order constraints -->
<xsl:template match="rsc_colocation/lifetime"/>
<xsl:template match="rsc_order/lifetime"/>

</xsl:stylesheet>
