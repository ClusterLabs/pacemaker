<?xml version="1.0" encoding="UTF-8"?>

<!--
 Use comments liberally as future maintainers may be unfamiliar with XSLT.
 -->

<!--
 upgrade-3.10-4.xsl

 Guarantees after this transformation:
 * There are no nagios-class or upstart-class resources. If there were any prior
   to this transformation, they have been dropped.
 * There are no bundle resources based on rkt containers. If there were any
   prior to this transformation, they have been dropped.
 * The restart-type resource meta-attribute is not present.
 * For the below resource meta-attributes, there are no nvpairs with value
   "default". If there were any prior to this transformation, new nvsets and
   rules have been added as needed to achieve the same behavior.
   * is-managed
   * migration-threshold
   * resource-stickiness
   * target-role
 * The can_fail operation meta-attribute is not present.
 * The role_after_failure operation meta-attribute is not present.
 -->

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:pcmk="http://clusterlabs.org/ns/pacemaker/pcmk"
                exclude-result-prefixes="pcmk">

<xsl:import href="upgrade-3.10-common.xsl"/>

<!-- XSLT 1.0 lacks upper-case() and lower-case() functions -->
<xsl:variable name="upper" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'"/>
<xsl:variable name="lower" select="'abcdefghijklmnopqrstuvwxyz'"/>

<!-- Index all resource templates by ID -->
<xsl:key name="template_id" match="template" use="@id"/>

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


<!-- Resources -->

<!-- The following XSL templates use XPath 1.0 set intersection idioms -->

<!-- Upstart-class templates -->
<xsl:variable name="dropped_templates"
              select="//template
                      [(translate(@class, $upper, $lower) = 'nagios')
                       or (translate(@class, $upper, $lower) = 'upstart')]"/>

<!-- Upstart-class primitives -->
<xsl:variable name="dropped_primitives"
              select="//primitive
                      [(translate(@class, $upper, $lower) = 'nagios')
                       or (translate(@class, $upper, $lower) = 'upstart')
                       or (@template
                           and (count(key('template_id', @template)
                                      |$dropped_templates)
                                = count($dropped_templates)))]"/>

<!-- Groups containing only nagios- and upstart-class primitives -->
<xsl:variable name="dropped_groups"
              select="//group[count(primitive|$dropped_primitives)
                              = count($dropped_primitives)]"/>

<!-- Clones containing only nagios- and upstart-class primitives -->
<xsl:variable name="dropped_clones"
              select="//clone[count(.//primitive|$dropped_primitives)
                              = count($dropped_primitives)]"/>

<!-- All dropped resources -->
<xsl:variable name="dropped_resources"
              select="$dropped_primitives
                      |$dropped_groups
                      |$dropped_clones
                      |//bundle[rkt]"/>

<!-- Drop nagios- and upstart-class resource templates -->
<xsl:template match="template">
    <xsl:if test="count(.|$dropped_templates) != count($dropped_templates)">
        <xsl:call-template name="identity"/>
    </xsl:if>
</xsl:template>

<!-- Drop nagios- and upstart-class primitives -->
<xsl:template match="primitive">
    <xsl:if test="count(.|$dropped_primitives) != count($dropped_primitives)">
        <xsl:call-template name="identity"/>
    </xsl:if>
</xsl:template>

<!-- Drop groups that would become empty -->
<xsl:template match="group">
    <xsl:if test="count(.|$dropped_groups) != count($dropped_groups)">
        <xsl:call-template name="identity"/>
    </xsl:if>
</xsl:template>

<!-- Drop clones that would become empty -->
<xsl:template match="clone">
    <xsl:if test="count(.|$dropped_clones) != count($dropped_clones)">
        <xsl:call-template name="identity"/>
    </xsl:if>
</xsl:template>

<!-- Drop rkt bundles -->
<xsl:template match="bundle[rkt]"/>

<!-- Drop restart-type resource meta-attribute -->
<xsl:template match="template/meta_attributes/nvpair[@name = 'restart-type']
                     |primitive/meta_attributes/nvpair[@name = 'restart-type']
                     |group/meta_attributes/nvpair[@name = 'restart-type']
                     |clone/meta_attributes/nvpair[@name = 'restart-type']
                     |bundle/meta_attributes/nvpair[@name = 'restart-type']
                     |rsc_defaults/meta_attributes/nvpair
                         [@name = 'restart-type']"/>

<!-- Resource meta-attributes with default values to transform -->
<pcmk:list id="default_overrides">
    <pcmk:item>is-managed</pcmk:item>
    <pcmk:item>migration-threshold</pcmk:item>
    <pcmk:item>resource-stickiness</pcmk:item>
    <pcmk:item>target-role</pcmk:item>
</pcmk:list>

<!--
 Drop nvpairs with certain "default" values for certain resource
 meta-attributes. As needed, create new meta_attributes blocks with rules to
 preserve behavior.
 -->
<xsl:template match="template/meta_attributes
                     |primitive/meta_attributes
                     |group/meta_attributes
                     |clone/meta_attributes
                     |bundle/meta_attributes
                     |rsc_defaults/meta_attributes">

    <xsl:call-template name="handle_defaults">
        <xsl:with-param name="candidate_default_nvsets"
                        select="preceding-sibling::meta_attributes"/>
        <xsl:with-param name="default_value" select="'default'"/>
        <xsl:with-param name="unset_names"
                        select="document('')/xsl:stylesheet
                                /pcmk:list[@id = 'default_overrides']/pcmk:item
                                /text()"/>
    </xsl:call-template>
</xsl:template>

<!-- Drop can_fail operation meta-attribute -->
<xsl:template match="op/meta_attributes/nvpair[@name = 'can_fail']
                     |op_defaults/meta_attributes/nvpair[@name = 'can_fail']"/>

<!-- Drop role_after_failure operation meta-attribute -->
<xsl:template match="op/meta_attributes/nvpair[@name = 'role_after_failure']
                     |op_defaults/meta_attributes/nvpair
                         [@name = 'role_after_failure']"/>


<!-- Constraints -->

<!-- Drop resource refs that refer to dropped resources -->
<xsl:variable name="dropped_resource_refs"
              select="//resource_ref[@id = $dropped_resources/@id]"/>

<xsl:template match="resource_ref">
    <xsl:if test="count(.|$dropped_resource_refs)
                  != count($dropped_resource_refs)">
        <xsl:call-template name="identity"/>
    </xsl:if>
</xsl:template>

<!-- Drop resource sets that would become empty -->
<xsl:variable name="dropped_resource_sets"
              select="//resource_set
                      [count(resource_ref|$dropped_resource_refs)
                       = count($dropped_resource_refs)]"/>

<xsl:template match="resource_set">
    <xsl:if test="count(.|$dropped_resource_sets)
                  != count($dropped_resource_sets)">
        <xsl:call-template name="identity"/>
    </xsl:if>
</xsl:template>

<!-- Drop constraints that would contain no valid resource references -->
<xsl:template match="rsc_location|rsc_ticket">
    <xsl:choose>
        <xsl:when test="@rsc = $dropped_resources/@id"/>

        <!-- The constraint contained resource sets, and they're all dropped -->
        <xsl:when test="resource_set
                        and (count(resource_set|$dropped_resource_sets)
                             = count($dropped_resource_sets))"/>

        <xsl:otherwise>
            <xsl:call-template name="identity"/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>

<xsl:template match="rsc_colocation">
    <xsl:choose>
        <xsl:when test="@rsc = $dropped_resources/@id"/>
        <xsl:when test="@with-rsc = $dropped_resources/@id"/>
        <xsl:when test="resource_set
                        and (count(resource_set|$dropped_resource_sets)
                             = count($dropped_resource_sets))"/>
        <xsl:otherwise>
            <xsl:call-template name="identity"/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>

<xsl:template match="rsc_order">
    <xsl:choose>
        <xsl:when test="@first = $dropped_resources/@id"/>
        <xsl:when test="@then = $dropped_resources/@id"/>
        <xsl:when test="resource_set
                        and (count(resource_set|$dropped_resource_sets)
                             = count($dropped_resource_sets))"/>
        <xsl:otherwise>
            <xsl:call-template name="identity"/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>

</xsl:stylesheet>
