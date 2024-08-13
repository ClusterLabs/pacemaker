<?xml version="1.0" encoding="UTF-8"?>

<!--
 Use comments liberally as future maintainers may be unfamiliar with XSLT.
 -->

<!--
 upgrade-3.10-4.xsl

 Guarantees after this transformation:
 * For the below resource meta-attributes, there are no nvpairs with value
   "default". If there were any prior to this transformation, new nvsets and
   rules have been added as needed to achieve the same behavior.
   * is-managed
   * migration-threshold
 -->

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:pcmk="http://clusterlabs.org/ns/pacemaker/pcmk"
                exclude-result-prefixes="pcmk">

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

<!-- Options with default values to transform -->
<pcmk:list id="default_overrides">
    <pcmk:item>is-managed</pcmk:item>
    <pcmk:item>migration-threshold</pcmk:item>
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

</xsl:stylesheet>
