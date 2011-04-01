<?xml version="1.0" ?>

<!-- Convert a flattened cluster.conf into a cib.xml -->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
		xmlns:cluster="http://dev/null"
		version="2.0">

<xsl:output method="xml" indent="yes"/>

<xsl:function name="cluster:normalize">
	<xsl:param name="val"/>
	<xsl:value-of select="translate($val, ': .=', '____')"/>
</xsl:function>

<xsl:function name="cluster:makeresname">
	<xsl:param name="ele" as="element()" />
        <xsl:choose>
		<xsl:when test="name($ele) = 'ip'">
			<xsl:sequence select="concat(name($ele),'_',cluster:normalize($ele/@address))"/>
		</xsl:when>
		<xsl:otherwise>
			<xsl:sequence select="concat(name($ele),'_',cluster:normalize($ele/@name))"/>
		</xsl:otherwise>
	</xsl:choose>
</xsl:function>

<xsl:template match="service">
	<group id="{concat('service_', @name)}">
	<xsl:for-each select="child::*">
	<xsl:variable name="resname" select="cluster:makeresname(self::node())"/>
	<primitive class="ocf" id="{$resname}" provider="redhat" type="{.}" >
	  <instance_attributes id="{$resname}_inst_attrs" >
	    <attributes>
	    <xsl:for-each select="@*">
	      <nvpair id="{$resname}_{name()}" name="{name()}" value="{.}" />
	    </xsl:for-each>

	    </attributes>
	  </instance_attributes>
	</primitive>
	</xsl:for-each>
	</group>
</xsl:template>

<xsl:template match="rm">
    <resources>
      <xsl:apply-templates/>
    </resources>
</xsl:template>

<xsl:template match="clusternode">
	<node id="{concat('node_', @nodeid)}" uname="{@name}" type="normal"/>
</xsl:template>

<xsl:template match="clusternodes">
    <nodes><xsl:apply-templates/>
    </nodes>
</xsl:template>

<xsl:template match="/cluster">
<cib><xsl:apply-templates/>
</cib>
</xsl:template>
</xsl:stylesheet>
