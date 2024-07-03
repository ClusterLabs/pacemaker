<?xml version="1.0" encoding="UTF-8"?>

<!--
 Use comments liberally as future maintainers may be unfamiliar with XSLT.
 -->

<!--
 upgrade-3.10-2.xsl

 Guarantees after this transformation:
 * Within a given nvset, there is at most one nvpair with a given name. If there
   were duplicates prior to this transformation, only the first one is kept.
 * There are no ping nodes. If a node was a ping node prior to this
   transformation, it is now a member (cluster) node with all resources banned
   and probes disabled.
 * There are no legacy promotable clone resources. If a resource was a legacy
   promotable clone prior to this transformation, it is now a standard
   promotable clone (that is, a clone with the meta-attribute "promotable" set
   to "true").
 * There is at most one top-level rule within a location constraint. If a
   location constraint had N top-level rules (N > 1) prior to this
   transformation, it is now converted to N location constraints, each with a
   single top-level rule.

 Anything that matches all resource types should be placed in a later
 transformation, so that it can ignore the possibility of legacy promotable
 clone resources.
 -->

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:import href="upgrade-3.10-common.xsl"/>

<!--
 Copy everything unaltered by default, except optionally set "original"

 Params:
 * original: See identity template
 -->
<xsl:template match="/|@*|node()">
    <xsl:param name="original"/>

    <xsl:call-template name="identity">
        <xsl:with-param name="original" select="$original"/>
    </xsl:call-template>
</xsl:template>


<!-- Name/value pairs -->

<!--
 Ensure there is at most one nvpair with a given name in a given nvset.

 By dropping the ignored duplicates now, we facilitate later transformations in
 which we drop nvpairs with certain values. The later steps will involve
 comparisons among multiple nvsets. These are easier to reason about and to
 regression-test if, prior to that, we drop all but one nvpair with a given name
 in a given nvset.
 -->

<!--
 Drop nvpairs with value="#default" if there is a later nvpair with the same
 name. Value "#default" unsets the option, so any later nvpair takes precedence.
-->
<xsl:template match="nvpair[(@value = '#default')
                            and (@name = following-sibling::*/@name)]"/>

<!--
 Drop nvpairs with a value other than "#default" if certain conditions (detailed
 below) are satisfied.
 -->
<xsl:template match="nvpair[@value != '#default']">
    <!-- All preceding sibling nvpairs with the same name -->
    <xsl:variable name="before"
                  select="preceding-sibling::nvpair[@name = current()/@name]"/>

    <!-- All following sibling nvpairs with the same name -->
    <xsl:variable name="after"
                  select="following-sibling::nvpair[@name = current()/@name]"/>

    <!--
     Last preceding sibling nvpair with the same name and value "#default"
     -->
    <xsl:variable name="last_default_before"
                  select="$before[@value = '#default'][last()]"/>

    <xsl:choose>
        <!--
         Drop if there's a following sibling with the same name and value
         "#default". The later "#default" value would unset the current nvpair's
         value.
         -->
        <xsl:when test="$after[@value = '#default']"/>

        <!--
         Drop if both:
         * There's a preceding sibling nvpair with the same name
         * Either of the following:
           * There's no preceding sibling nvpair with the same name and value
             "#default"
           * There's a preceding sibling nvpair with the same name between the
             most recent "#default" and the current node.

         The preceding sibling nvpair would take effect, and there is no
         "#default" value to unset it before we reach the current nvpair.

         This uses an XPath 1.0 set intersection idiom.
         -->
        <xsl:when test="$before
                        and (not($last_default_before)
                             or $last_default_before/following-sibling::nvpair
                                [count(.|$before) = count($before)])"/>

        <!-- Otherwise, keep the nvpair -->
        <xsl:otherwise>
            <xsl:call-template name="identity"/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>


<!-- Nodes -->

<!--
 Transform ping nodes to cluster (member) nodes. The constraints template bans
 all resources from the newly transformed nodes.
-->
<xsl:template match="node[@type = 'ping']">
    <xsl:copy>
        <xsl:apply-templates select="@*"/>
        <xsl:attribute name="type">member</xsl:attribute>
        <xsl:apply-templates select="node()"/>
    </xsl:copy>
</xsl:template>


<!-- Resources -->

<!--
 Convert master resources to clones with promotable meta-attribute set to "true"
 -->
<xsl:template match="master">
    <xsl:element name="clone">
        <xsl:apply-templates select="@*"/>

        <!--
         Prepend new meta_attributes element that takes precedence over all
         others, with promotable="true"
        -->
        <xsl:element name="meta_attributes">
            <xsl:variable name="meta_id"
                          select="concat($upgrade_prefix, 'promotable-legacy-',
                                         @id, '-meta_attributes')"/>

            <xsl:attribute name="id">
                <xsl:value-of select="$meta_id"/>
            </xsl:attribute>

            <!-- Override any manually configured meta-attributes -->
            <xsl:attribute name="score">INFINITY</xsl:attribute>

            <xsl:element name="nvpair">
                <xsl:attribute name="id">
                    <xsl:value-of select="concat($meta_id, '-promotable')"/>
                </xsl:attribute>
                <xsl:attribute name="name">promotable</xsl:attribute>
                <xsl:attribute name="value">true</xsl:attribute>
            </xsl:element>
        </xsl:element>

        <!-- Keep all existing children -->
        <xsl:apply-templates select="node()"/>
    </xsl:element>
</xsl:template>


<!-- Constraints -->

<xsl:template match="constraints">
    <xsl:copy>
        <!-- Existing contents -->
        <xsl:apply-templates select="@*|node()"/>

        <!--
         Ban all resources from each ping node (converted to a cluster node via
         another template)
         -->
        <xsl:for-each select="//node[@type = 'ping']">
            <xsl:element name="rsc_location">
                <xsl:attribute name="id">
                    <xsl:value-of select="concat($upgrade_prefix,
                                                 'ping-node-ban-', @uname)"/>
                </xsl:attribute>
                <xsl:attribute name="rsc-pattern">.*</xsl:attribute>
                <xsl:attribute name="node">
                    <xsl:value-of select="@uname"/>
                </xsl:attribute>
                <xsl:attribute name="score">-INFINITY</xsl:attribute>
                <xsl:attribute name="resource-discovery">never</xsl:attribute>
            </xsl:element>
        </xsl:for-each>
    </xsl:copy>
</xsl:template>

<!--
 If a location constraint contains multiple top-level rules, replace it with
 a set of new location constraints, one for each top-level rule.
 -->
<xsl:template match="rsc_location[count(rule) > 1]">
    <xsl:for-each select="rule">
        <xsl:element name="rsc_location">
            <!-- Copy attributes from the original rsc_location -->
            <xsl:apply-templates select="../@*"/>
            <xsl:attribute name="original">0</xsl:attribute>

            <!--
             Set a probably-unique ID for the new rsc_location, based on the
             existing rsc_location's ID and the rule's position
             -->
            <xsl:attribute name="id">
                <xsl:value-of select="concat($upgrade_prefix, ../@id, '-',
                                             position())"/>
            </xsl:attribute>

            <!-- Add resource sets, rule, and lifetime (in order) -->
            <xsl:choose>
                <!--
                 The descendants of the first rsc_location created should keep
                 their "original" values from the old rsc_location, if any
                 -->
                <xsl:when test="position() = 1">
                    <xsl:apply-templates select="../resource_set"/>
                    <xsl:apply-templates select="."/>
                    <xsl:apply-templates select="../lifetime"/>
                </xsl:when>

                <!--
                 The descendants of later rsc_location elements should all have
                 original="0"
                 -->
                <xsl:otherwise>
                    <xsl:apply-templates select="../resource_set">
                        <xsl:with-param name="original" select="'0'"/>
                    </xsl:apply-templates>
                    <xsl:apply-templates select=".">
                        <xsl:with-param name="original" select="'0'"/>
                    </xsl:apply-templates>
                    <xsl:apply-templates select="../lifetime">
                        <xsl:with-param name="original" select="'0'"/>
                    </xsl:apply-templates>
                </xsl:otherwise>
            </xsl:choose>
        </xsl:element>
    </xsl:for-each>
</xsl:template>

</xsl:stylesheet>
