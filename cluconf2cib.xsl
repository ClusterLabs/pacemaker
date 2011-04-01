<?xml version="1.0" ?>

<!-- Convert a flattened cluster.conf into a cib.xml -->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:output method="text" indent="yes"/>

<xsl:template name="make-resource-name">
        <xsl:value-of select="name()"/>_<xsl:choose>
	  <xsl:when test="name() = 'ip'">
	    <xsl:value-of select="translate(@address, ': .=', '____')"/>
	  </xsl:when>
	  <xsl:otherwise>
	    <xsl:value-of select="translate(@name, ': .=', '____')"/>
	  </xsl:otherwise>
	</xsl:choose>
</xsl:template>

<xsl:template match="service">
      &lt;group id="service_<xsl:value-of select="@name"/>"&gt;<xsl:for-each select="child::*">
        &lt;primitive class="ocf" id="<xsl:call-template name="make-resource-name"/>" provider="redhat" type="<xsl:value-of select="name()"/>" >
	  &lt;instance_attributes id="<xsl:call-template name="make-resource-name"/>_inst_attrs" &gt;
	    &lt;attributes&gt;<xsl:for-each select="@*">
	      &lt;nvpair id="<xsl:value-of select="generate-id()" />" name="<xsl:value-of select="name()"/>" value="<xsl:value-of select="." />"/&gt;</xsl:for-each>
	    &lt;/attributes&gt;
	  &lt;/instance_attributes&gt;
	&lt;/primitive&gt;
	</xsl:for-each>
      &lt;/group&gt;
</xsl:template>

<xsl:template match="rm">
    &lt;resources&gt;<xsl:apply-templates/>
    &lt;/resources&gt;
</xsl:template>

<xsl:template match="clusternode">
      &lt;node id="node_<xsl:value-of select="@nodeid"/>" uname="<xsl:value-of select="@name"/>" type="normal"/>
</xsl:template>

<xsl:template match="clusternodes">
    &lt;nodes&gt;<xsl:apply-templates/>
    &lt;/nodes&gt;
</xsl:template>

<xsl:template match="cluster">
&lt;cib&gt;<xsl:apply-templates/>
&lt;/cib&gt;
</xsl:template>
</xsl:stylesheet>
