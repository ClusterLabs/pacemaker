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


<xsl:function name="cluster:getname">
	<xsl:param name="ele" as="element()" />
	<xsl:value-of select="$ele" />
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

<xsl:template match="service" mode="#default">
	<group id="{concat('service_', @name)}">
	<xsl:for-each select="child::*">
	<xsl:variable name="resname" select="cluster:makeresname(self::node())"/>
	<primitive class="ocf" id="{$resname}" provider="redhat" type="{.}" >
	  <instance_attributes id="{$resname}_inst_attrs" >
	    <xsl:for-each select="@*">
	      <nvpair id="{$resname}_{name()}" name="{name()}" value="{.}" />
	    </xsl:for-each>
	  </instance_attributes>
	</primitive>
	</xsl:for-each>
	</group>
</xsl:template>

<xsl:template match="vm" mode="#default">
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
<xsl:template match="failoverdomain" mode="#default">
    <domain id="{@name}">
      <xsl:apply-templates select="failoverdomainnode"/>
    </domain>
</xsl:template>

<xsl:template match="failoverdomains" mode="#default">
  <domains><xsl:apply-templates select="failoverdomain"/>
  </domains>
</xsl:template>

<xsl:template match="service|vm" mode="domlink">
  <xsl:variable name="resname" select="cluster:makeresname(self::node())"/>
  <xsl:if test="@domain">
    <rsc_location id="{generate-id()}" rsc="{$resname}" domain="{@domain}"/>
  </xsl:if>
</xsl:template>

<xsl:template match="rm" mode="#default">
    <xsl:apply-templates select="failoverdomains"/>
    <resources>
      <xsl:apply-templates select="service|vm" />
    </resources>
    <constraints>
      <xsl:apply-templates select="service|vm" mode="domlink"/>
    </constraints>
</xsl:template>

<xsl:template match="clusternode" mode="#default">
	<node id="{concat('node_', @nodeid)}" uname="{@name}" type="normal"/>
</xsl:template>

<xsl:template match="clusternodes" mode="#default">
    <nodes><xsl:apply-templates/>
    </nodes>
</xsl:template>

<xsl:template match="/cluster">
<cib validate-with="pacemaker-1.1" admin_epoch="1" epoch="1" num_updates="0" >
  <configuration>
    <crm_config>
      <cluster_property_set id="cib-bootstrap-options">
        <nvpair id="startup-fencing" name="startup-fencing" value="true"/>
        <!-- WARNING: dangerous; set to true before deploying -->
        <nvpair id="stonith-enabled" name="stonith-enabled" value="false"/>
        <nvpair id="default-resource-stickiness" name="default-resource-stickiness" value="INFINITY"/>
      </cluster_property_set>
    </crm_config>
    <xsl:apply-templates select="clusternodes"/>
    <xsl:apply-templates select="rm"/>
  </configuration>
  <status/>
</cib>
</xsl:template>
</xsl:stylesheet>
