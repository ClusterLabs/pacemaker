<?xml version="1.0" encoding="UTF-8"?>

<!--
 Use comments liberally as future maintainers may be unfamiliar with XSLT.
 -->

<!--
 upgrade-3.10-4.xsl

 Guarantees after this transformation:
 * There are no nagios-class or upstart-class resources. If there were any prior
   to this transformation, they have been dropped.
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
              select="$dropped_primitives|$dropped_groups|$dropped_clones"/>

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
