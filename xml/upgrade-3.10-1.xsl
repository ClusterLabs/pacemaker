<?xml version="1.0" encoding="UTF-8"?>

<!--
 Use comments liberally as future maintainers may be unfamiliar with XSLT.
 -->

<!--
 upgrade-3.10-1.xsl

 Guarantees after this transformation:
 * The validate-with attribute of the cib element is set to "pacemaker-4.0".
 * All nvset elements are sorted by score within their respective parent
   elements (remaining in document order in the case of a tie) and placed below
   all non-nvset siblings. Exception: a cluster_property_set with id
   "cib-bootstrap-options" always sorts first relative to its siblings.
 * Each nvpair has a value attribute. If an nvpair did not have a value
   attribute prior to this transformation, it is dropped.
 * The remove-after-stop cluster property is not present.
 * The stonith-action cluster property is set to "off" if it was previously set
   to "poweroff".

 nvset elements include the following:
 * cluster_property_set
 * instance_attributes
 * meta_attributes
 * utilization

 Any template that matches an element (for example, "primitive") that may
 contain an nvset should be placed in a later stylesheet. If such a template is
 placed in this stylesheet, its nvsets will not be sorted. We could avoid this
 with some refactoring, but it's cleaner this way.
 -->

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:import href="upgrade-3.10-common.xsl"/>

<!--
 Copy everything unaltered by default, except sort nvset elements by score.

 This doesn't affect behavior. nvset elements of a given type within a given
 parent element are processed in order of their score attributes, with a
 nonexistent score treated as 0. In the event of a tie, elements are processed
 in document order. The sort here preserves document order in the event of a
 tie.

 The order of nvset elements relative to non-nvset elements does not matter. So
 this template puts existing nvset elements after existing non-nvset elements.

 This facilitates later transformations, allowing us to more easily drop nvpairs
 with unsupported values without changing behavior.
 -->
<xsl:template match="/|@*|node()">
    <xsl:copy>
        <xsl:variable name="nvsets"
                      select="cluster_property_set
                              |instance_attributes
                              |meta_attributes
                              |utilization"/>

        <!-- XPath 1.0 set difference idiom -->
        <xsl:variable name="non_nvsets"
                      select="@*|node()[count(.|$nvsets) != count($nvsets)]"/>

        <xsl:apply-templates select="$non_nvsets"/>
        <xsl:apply-templates select="$nvsets">
            <!--
             Order cluster_property_set with id "cib-bootstrap-options" before
             siblings
             -->
            <xsl:sort select="self::cluster_property_set
                              and (@id = 'cib-bootstrap-options')"
                      order="descending"/>

            <!--
             Sort remaining elements by score.

             First, score="INFINITY" (including "+INFINITY").
             -->
            <xsl:sort select="@score[. = 'INFINITY'] or @score[. = '+INFINITY']"
                      order="descending"/>

            <!-- Then finite positive scores -->
            <xsl:sort select="@score[. &gt; 0]" data-type="number"
                      order="descending"/>

            <!-- Then score 0 (including implicit) -->
            <xsl:sort select="number(not(@score) or @score[. = 0])"
                      data-type="number" order="descending"/>

            <!-- Then finite negative scores -->
            <xsl:sort select="@score[. &lt; 0]" data-type="number"
                      order="descending"/>

            <!-- Then score="-INFINITY" -->
            <xsl:sort select="@score[. = '-INFINITY']" order="descending"/>
        </xsl:apply-templates>
    </xsl:copy>
</xsl:template>

<!--
 Bump cib/@validate-with, or set it if not already set. Pacemaker does this, but
 doing it in the transformation is helpful for testing.
 -->
<xsl:template match="cib">
    <xsl:copy>
        <xsl:apply-templates select="@*"/>
        <xsl:attribute name="validate-with">pacemaker-4.0</xsl:attribute>
        <xsl:apply-templates select="node()"/>
    </xsl:copy>
</xsl:template>


<!-- Name/value pairs -->

<!-- Drop any nvpair that does not have a value attribute -->
<xsl:template match="nvpair[not(@value)]"/>


<!-- Cluster properties -->

<!-- Drop remove-after-stop property -->
<xsl:template match="cluster_property_set/nvpair[@name = 'remove-after-stop']"/>

<!-- Replace stonith-action="poweroff" with stonith-action="off" -->
<xsl:template match="cluster_property_set/nvpair[@name = 'stonith-action']
                     /@value[. = 'poweroff']">
    <xsl:attribute name="value">off</xsl:attribute>
</xsl:template>

</xsl:stylesheet>
