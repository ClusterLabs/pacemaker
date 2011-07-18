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


<!-- transpose failover domain score -->
<xsl:function name="cluster:domscore">
	<xsl:param name="val"/>
	<xsl:param name="prioritized"/>
	<xsl:choose>
		<xsl:when test="($prioritized = 1)">
			<xsl:choose>
				<xsl:when test="($val >= 1)">
					<xsl:value-of select="(101-$val)*10000"/>
				</xsl:when>
				<xsl:otherwise>
					500000
				</xsl:otherwise>
			</xsl:choose>
		</xsl:when>
		<xsl:otherwise>
			1000000
		</xsl:otherwise>
	</xsl:choose>
</xsl:function>

<xsl:function name="cluster:textify-score">
	<xsl:param name="val"/>
	<xsl:choose>
		<xsl:when test="(number($val) = 1000000)">INFINITY</xsl:when>
		<xsl:when test="(number($val) = -1000000)">-INFINITY</xsl:when>
		<xsl:otherwise>
			<xsl:value-of select="$val"/>
		</xsl:otherwise>
	</xsl:choose>
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

<!-- Failover Domains -->


<!-- Node definition:
     failoverdomainnode -> node
     priority (1..100) -> value, 1000000 .. 1000;
       (101-priority)*10000
 -->
<xsl:template match="failoverdomainnode">
      <node name="{@name}" score="{cluster:textify-score(format-number(cluster:domscore(@priority,../@ordered),'#'))}"/>
</xsl:template>

<!-- failoverdomain definition:
     failoverdomain -> domain
       name       -> id
       ordered    -> N/A
       restricted -> N/A
 -->
<xsl:template match="failoverdomain">
    <domain id="{@name}">
      <xsl:apply-templates select="failoverdomainnode"/>
    </domain>
</xsl:template>

<xsl:template match="failoverdomains">
  <domains><xsl:apply-templates select="failoverdomain"/>
  </domains>
</xsl:template>

<xsl:template match="rm">
    <xsl:apply-templates select="failoverdomains"/>
    <resources>
      <xsl:apply-templates select="service"/>
      <xsl:apply-templates select="vm"/>
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
