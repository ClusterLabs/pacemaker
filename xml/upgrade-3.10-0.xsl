<?xml version="1.0" encoding="UTF-8"?>

<!--
 Use comments liberally as future maintainers may be unfamiliar with XSLT.
-->

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<!-- Strip whitespace-only text nodes but indent output -->
<xsl:strip-space elements="*"/>
<xsl:output encoding="UTF-8" indent="yes" omit-xml-declaration="yes"/>

<!-- XSLT 1.0 lacks upper-case() and lower-case() functions -->
<xsl:variable name="lowercase" select="'abcdefghijklmnopqrstuvwxyz'"/>
<xsl:variable name="uppercase" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'"/>

<!-- Copy everything unaltered by default -->
<xsl:template match="/|@*|node()" name="identity">
    <xsl:copy>
        <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
</xsl:template>


<!-- Cluster properties -->

<!-- Drop remove-after-stop property -->
<xsl:template match="cluster_property_set/nvpair[@name = 'remove-after-stop']"/>

<!-- Replace stonith-action="poweroff" with stonith-action="off" -->
<xsl:template match="cluster_property_set/nvpair[@name = 'stonith-action']
                     /@value[. = 'poweroff']">
    <xsl:attribute name="value">off</xsl:attribute>
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

<!-- Index all resource templates by ID -->
<xsl:key name="template_id" match="template" use="@id"/>

<xsl:template match="template">
    <xsl:variable name="class_lower"
                  select="translate(@class, $uppercase, $lowercase)"/>

    <!-- Drop nagios- and upstart-class resource templates -->
    <xsl:if test="$class_lower != 'nagios' and $class_lower != 'upstart'">
        <xsl:call-template name="identity"/>
    </xsl:if>
</xsl:template>

<xsl:template match="primitive">
    <!-- Get class from primitive or from template that it references -->
    <xsl:variable name="template" select="key('template_id', @template)"/>
    <xsl:variable name="class" select="(.|$template)/@class"/>
    <xsl:variable name="class_lower"
                  select="translate($class, $uppercase, $lowercase)"/>

    <!-- Drop nagios- and upstart-class resource templates -->
    <xsl:if test="$class_lower != 'nagios' and $class_lower != 'upstart'">
        <xsl:call-template name="identity"/>
    </xsl:if>
</xsl:template>

<!-- Drop rkt bundles -->
<xsl:template match="bundle[rkt]"/>

<!-- Drop "default" as value for certain resource meta-attributes -->
<xsl:template match="//meta_attributes/nvpair
                     [(@value = 'default')
                      and ((@name = 'is-managed')
                           or (@name = 'migration-threshold')
                           or (@name = 'resource-stickiness')
                           or (@name = 'target-role'))]">
    <xsl:choose>
        <xsl:when test="../../self::template"/>
        <xsl:when test="../../self::primitive"/>
        <xsl:when test="../../self::group"/>
        <xsl:when test="../../self::clone"/>
        <xsl:when test="../../self::master"/>
        <xsl:when test="../../self::bundle"/>
        <xsl:when test="../../self::rsc_defaults"/>
        <xsl:otherwise>
            <xsl:call-template name="identity"/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>


<!-- Constraints -->

<xsl:template match="constraints">
    <xsl:copy>
        <!-- Process existing constraints using matching templates -->
        <xsl:for-each select="@*|node()">
            <xsl:apply-templates select="."/>
        </xsl:for-each>

        <!--
         Ban all resources from each ping node (converted to a cluster node via
         another template)
         -->
        <xsl:for-each select="node[@type = 'ping']">
            <xsl:element name="rsc_location">
                <!--
                 The following XML ID may not be unique. There is no native way
                 to generate a UUID. If desired, we could try something like
                 https://stackoverflow.com/a/30775426/7660197, but the
                 scaffolding is verbose and requires EXSLT.
                 -->
                <xsl:attribute name="id">
                    <xsl:value-of select="concat('ping-node-ban-', @uname)"/>
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

</xsl:stylesheet>
