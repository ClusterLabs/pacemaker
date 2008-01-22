<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
		xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method='xml' version='1.0' encoding='UTF-8' indent='yes'/>
<xsl:template match="status"/>

<xsl:template match="@admin_epoch|@num_updates|@boolean_op|@cib_feature_revision|@crm_feature_set">
  <xsl:attribute name="{translate(name(),'_','-')}">
    <xsl:value-of select="."/>
  </xsl:attribute>
</xsl:template>

<xsl:template match="@generated|@ccm_transition|@num_peers|@cib_last_written|@have_quorum|@dc_uuid">
  <!-- swallow -->
</xsl:template>

<xsl:template match="@score">
  <xsl:attribute name="{name()}">
    <xsl:value-of select="substring-before(.,'.')"/>
  </xsl:attribute>
</xsl:template>

<xsl:template name="create-as-attr"> 
  <xsl:param name="name"/> 
  <xsl:param name="value"/> 
  <xsl:element name="nvpair">
    <xsl:attribute name="id">
      <xsl:value-of select="name()"/>
      <xsl:text>.auto-</xsl:text>
      <xsl:number level="any" from="cib" count="nvpair"/>
    </xsl:attribute>
    <xsl:attribute name="name">
      <xsl:value-of select="translate($name,'_','-')"/>
    </xsl:attribute>
    <xsl:attribute name="value">
      <xsl:value-of select="$value"/>
    </xsl:attribute>
  </xsl:element>
</xsl:template> 

<xsl:template match="attributes">
  <xsl:element name="{name()}">
    <xsl:apply-templates select="@*"/>
    <xsl:apply-templates select="node()" />
    <xsl:for-each select="../../@*"> 
      <xsl:choose>
	<xsl:when test="contains(name(), 'is_managed') or contains(name(), 'resource_stickiness') or contains(name(), 'ordered') or contains(name(), 'collocated') or contains(name(), 'restart_type') or contains(name(), 'multiple_active') ">
	  <xsl:call-template name="create-as-attr">
	    <xsl:with-param name="name"><xsl:value-of select="name()"/></xsl:with-param>
	    <xsl:with-param name="value"><xsl:value-of select="."/></xsl:with-param>
	  </xsl:call-template>
	</xsl:when>
      </xsl:choose>
    </xsl:for-each>
  </xsl:element>
</xsl:template>

<xsl:template match="@is_managed|@resource_stickiness|@ordered|@collocated|@restart_type|@multiple_active">
  <xsl:if test="not(../instance_attributes)">
    <xsl:element name="instance_attributes">
      <xsl:attribute name="id">
	<xsl:value-of select="name()"/>
	<xsl:text>.auto-</xsl:text>
	<xsl:number level="any" from="cib"/>
      </xsl:attribute>
      <xsl:element name="attributes">
	<xsl:call-template name="create-as-attr">
	  <xsl:with-param name="name"><xsl:value-of select="name()"/></xsl:with-param>
	  <xsl:with-param name="value"><xsl:value-of select="."/></xsl:with-param>
	</xsl:call-template>
      </xsl:element>
    </xsl:element>
  </xsl:if>
</xsl:template>

<xsl:template match="@*">
  <xsl:attribute name="{name()}">
    <xsl:value-of select="."/>
  </xsl:attribute>
</xsl:template>

<xsl:template match="cib">
  <xsl:element name="{name()}">
    <xsl:apply-templates select="@*"/>
    <xsl:attribute name="validate-with">relax-ng</xsl:attribute>
    <xsl:apply-templates select="node()" />
  </xsl:element>
  <!--xsl:apply-templates/-->
</xsl:template>

<xsl:template match="/">
  <xsl:apply-templates select="@*"/>
  <xsl:apply-templates select="node()"/>
  <!--xsl:apply-templates/-->
</xsl:template>

<xsl:template match="configuration|nodes|node|crm_config|resources|constraints|operations">
  <xsl:element name="{name()}">
    <xsl:apply-templates select="@*"/>
    <xsl:apply-templates select="node()" />
  </xsl:element>
</xsl:template>

<xsl:template match="*">
  <xsl:element name="{name()}">
    <xsl:attribute name="id">
      <xsl:value-of select="name()"/>
      <xsl:text>.auto-</xsl:text>
      <xsl:number level="any" from="cib"/>
    </xsl:attribute>
    <xsl:apply-templates select="@*"/>
    <xsl:apply-templates select="node()" />
  </xsl:element>
  <!--xsl:apply-templates/-->
</xsl:template>

</xsl:stylesheet>
