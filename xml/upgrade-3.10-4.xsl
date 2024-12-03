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
 * The can_fail operation meta-attribute is not present.
 * The role_after_failure operation meta-attribute is not present.
 -->

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:import href="upgrade-3.10-common.xsl"/>

<!-- XSLT 1.0 lacks upper-case() and lower-case() functions -->
<xsl:variable name="upper" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'"/>
<xsl:variable name="lower" select="'abcdefghijklmnopqrstuvwxyz'"/>

<!-- Index all resource templates by ID -->
<xsl:key name="template_id" match="template" use="@id"/>

<!-- Copy everything unaltered by default -->
<xsl:template match="/|@*|node()">
    <xsl:call-template name="identity"/>
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
    <xsl:choose>
        <xsl:when test="count(.|$dropped_templates)
                        = count($dropped_templates)">
            <xsl:call-template name="warning">
                <xsl:with-param name="msg"
                                select="concat('Dropping template ', @id,
                                               ' because ', @class,
                                               ' resources are no longer',
                                               ' supported')"/>
            </xsl:call-template>
        </xsl:when>

        <xsl:otherwise>
            <xsl:call-template name="identity"/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>

<!-- Drop nagios- and upstart-class primitives -->
<xsl:template match="primitive">
    <xsl:choose>
        <xsl:when test="count(.|$dropped_primitives)
                        = count($dropped_primitives)">
            <xsl:variable name="class"
                          select="@class|key('template_id', @template)/@class"/>
            <xsl:call-template name="warning">
                <xsl:with-param name="msg"
                                select="concat('Dropping resource ', @id,
                                               ' because ', $class,
                                               ' resources are no longer',
                                               ' supported')"/>
            </xsl:call-template>
        </xsl:when>

        <xsl:otherwise>
            <xsl:call-template name="identity"/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>

<!-- Drop groups that would become empty -->
<xsl:template match="group">
    <xsl:choose>
        <xsl:when test="count(.|$dropped_groups) = count($dropped_groups)">
            <xsl:call-template name="info">
                <xsl:with-param name="msg"
                                select="concat('Dropping group ', @id,
                                               ' because it would become',
                                               ' empty')"/>
            </xsl:call-template>
        </xsl:when>

        <xsl:otherwise>
            <xsl:call-template name="identity"/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>

<!-- Drop clones that would become empty -->
<xsl:template match="clone">
    <xsl:choose>
        <xsl:when test="count(.|$dropped_clones) = count($dropped_clones)">
            <xsl:call-template name="info">
                <xsl:with-param name="msg"
                                select="concat('Dropping clone ', @id,
                                               ' because it would become',
                                               ' empty')"/>
            </xsl:call-template>
        </xsl:when>

        <xsl:otherwise>
            <xsl:call-template name="identity"/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>

<!-- Drop rkt bundles -->
<xsl:template match="bundle[rkt]">
    <xsl:call-template name="warning">
        <xsl:with-param name="msg"
                        select="concat('Dropping bundle resource ', @id,
                                       ' because rkt containers are no longer',
                                       ' supported')"/>
    </xsl:call-template>
</xsl:template>

<!-- Drop restart-type resource meta-attribute -->
<xsl:template match="template/meta_attributes/nvpair[@name = 'restart-type']
                     |primitive/meta_attributes/nvpair[@name = 'restart-type']
                     |group/meta_attributes/nvpair[@name = 'restart-type']
                     |clone/meta_attributes/nvpair[@name = 'restart-type']
                     |bundle/meta_attributes/nvpair[@name = 'restart-type']
                     |rsc_defaults/meta_attributes/nvpair
                         [@name = 'restart-type']">
    <xsl:call-template name="warning">
        <xsl:with-param name="msg"
                        select="concat('Dropping ', @name,
                                       ' meta-attribute from ', ../@id,
                                       ' because it is no longer supported.',
                                       ' Consider setting the &quot;kind&quot;',
                                       ' attribute for relevant constraints')"/>
    </xsl:call-template>
</xsl:template>

<!-- Drop can_fail and role_after_failure operation meta-attributes -->
<xsl:template match="op/meta_attributes/nvpair[@name = 'can_fail']
                     |op/meta_attributes/nvpair[@name = 'role_after_failure']
                     |op_defaults/meta_attributes/nvpair[@name = 'can_fail']
                     |op_defaults/meta_attributes/nvpair
                         [@name = 'role_after_failure']">
    <xsl:call-template name="warning">
        <xsl:with-param name="msg"
                        select="concat('Dropping ', @name,
                                       ' meta-attribute from ', ../@id,
                                       ' because it is no longer supported.',
                                       ' Consider setting the',
                                       ' &quot;on-fail&quot; operation',
                                       ' attribute instead')"/>
    </xsl:call-template>
</xsl:template>


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
