<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
		xmlns:fn="http://www.w3.org/2005/02/xpath-functions"
		xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method='xml' version='1.0' encoding='UTF-8' indent='yes'/>
<xsl:template match="status"/>

<xsl:template match="@admin_epoch|@num_updates|@boolean_op|@cib_feature_revision|@crm_feature_set|@on_fail">
  <xsl:attribute name="{translate(name(),'_','-')}">
    <xsl:value-of select="."/>
  </xsl:attribute>
</xsl:template>

<xsl:template match="@prereq">
  <xsl:attribute name="requires">
    <xsl:value-of select="."/>
  </xsl:attribute>
</xsl:template>

<!-- sanitize IDs -->
<xsl:template match="@id">
  <xsl:attribute name="{translate(name(), ':', '-')}">
    <xsl:value-of select="."/>
  </xsl:attribute>
</xsl:template>

<xsl:template match="@generated|@ccm_transition|@num_peers|@cib_last_written|@have_quorum|@dc_uuid|@start_delay">
  <!-- swallow -->
</xsl:template>

<xsl:template match="@disabled">
  <xsl:attribute name="enabled">true</xsl:attribute>
  <xsl:if test="contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'true')">
    <xsl:attribute name="enabled">false</xsl:attribute>
  </xsl:if>
</xsl:template>

<xsl:template match="@to_role|@role|@from_role">
  <xsl:attribute name="{name()}">
    <xsl:value-of select="translate(substring(.,1,1), 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/>
    <xsl:value-of select="translate(substring(.,2), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"/>
  </xsl:attribute>
  
</xsl:template>

<xsl:template match="@score">
  <xsl:attribute name="{name()}">
    <xsl:if test="contains(., '.')">
      <xsl:value-of select="substring-before(.,'.')"/>
    </xsl:if>
    <xsl:if test="not(contains(., '.'))">
      <xsl:value-of select="translate(.,'infty','INFTY')"/>
    </xsl:if>
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

<xsl:template match="primitive|group|clone">
  <xsl:element name="{name()}">
    <xsl:apply-templates select="@id"/>
    <xsl:for-each select="@*"> 
      <xsl:choose>
	<xsl:when test="contains(name(), 'id')">
	  <xsl:apply-templates select="."/>
	</xsl:when>
	<xsl:when test="contains(name(), 'type')">
	  <xsl:apply-templates select="."/>
	</xsl:when>
	<xsl:when test="contains(name(), 'class')">
	  <xsl:apply-templates select="."/>
	</xsl:when>
	<xsl:when test="contains(name(), 'provider')">
	  <xsl:apply-templates select="."/>
	</xsl:when>
	<xsl:when test="contains(name(), 'description')">
	  <xsl:apply-templates select="."/>
	</xsl:when>
      </xsl:choose>
    </xsl:for-each>
    <xsl:apply-templates select="node()" />

    <xsl:element name="meta_attributes">
      <xsl:attribute name="id">
	<xsl:value-of select="@id"/>
	<xsl:text>.auto</xsl:text>
      </xsl:attribute>
      <xsl:element name="attributes">
	<xsl:for-each select="@*"> 
	  <xsl:choose>
	    <xsl:when test="contains(name(), 'id')"/>
	    <xsl:when test="contains(name(), 'type')"/>
	    <xsl:when test="contains(name(), 'class')"/>
	    <xsl:when test="contains(name(), 'provider')"/>
	    <xsl:when test="contains(name(), 'description')"/>
	    <xsl:otherwise>
	      <xsl:call-template name="create-as-attr">
		<xsl:with-param name="name"><xsl:value-of select="name()"/></xsl:with-param>
		<xsl:with-param name="value"><xsl:value-of select="."/></xsl:with-param>
	      </xsl:call-template>
	    </xsl:otherwise>
	  </xsl:choose>
	</xsl:for-each>
      </xsl:element>
    </xsl:element>
  </xsl:element>
  <!--xsl:apply-templates/-->
</xsl:template>

<xsl:template match="master_slave">
  <xsl:element name="master">
    <xsl:apply-templates select="@id"/>
    <xsl:apply-templates select="node()" />

    <xsl:element name="instance_attributes">
      <xsl:attribute name="id">
	<xsl:value-of select="@id"/>
	<xsl:text>.auto</xsl:text>
      </xsl:attribute>
      <xsl:element name="attributes">
	<xsl:for-each select="@*"> 
	  <xsl:choose>
	    <xsl:when test="not(contains(name(), 'id'))">
	      <xsl:call-template name="create-as-attr">
		<xsl:with-param name="name"><xsl:value-of select="name()"/></xsl:with-param>
		<xsl:with-param name="value"><xsl:value-of select="."/></xsl:with-param>
	      </xsl:call-template>
	    </xsl:when>
	  </xsl:choose>
	</xsl:for-each>
      </xsl:element>
    </xsl:element>
  </xsl:element>
  <!--xsl:apply-templates/-->
</xsl:template>

<xsl:template match="@is_managed|@resource_stickiness|@ordered|@collocated|@restart_type|@multiple_active|@globally_unique|@notify|@interleave">
  <xsl:if test="not(../instance_attributes)">
    <xsl:element name="instance_attributes">
      <xsl:attribute name="id">
	<xsl:value-of select="../@id"/>
	<xsl:text>.auto-</xsl:text>
	<xsl:number level="any" from="cib" count="primitive"/>
      </xsl:attribute>
      <xsl:element name="attributes">
	<xsl:element name="nvpair">
	  <xsl:attribute name="id">
	    <xsl:value-of select="../@id"/>
	    <xsl:text>.</xsl:text>
	    <xsl:value-of select="name()"/>
	    <xsl:text>.auto-</xsl:text>
	    <xsl:number level="any" from="cib" count="primitive"/>
	  </xsl:attribute>
	  <xsl:attribute name="name">
	    <xsl:value-of select="translate(name(),'_','-')"/>
	  </xsl:attribute>
	  <xsl:attribute name="value">
	    <xsl:value-of select="."/>
	  </xsl:attribute>
	</xsl:element>
	<!--xsl:call-template name="create-as-attr">
	  <xsl:with-param name="name"><xsl:value-of select="name()"/></xsl:with-param>
	  <xsl:with-param name="value"><xsl:value-of select="."/></xsl:with-param>
	</xsl:call-template-->
      </xsl:element>
    </xsl:element>
  </xsl:if>
</xsl:template>

<!-- only set provider for OCF resources -->
<xsl:template match="@provider">
  <xsl:if test="contains(../@class, 'ocf')">
    <xsl:attribute name="{name()}">
      <xsl:value-of select="."/>
    </xsl:attribute>
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

<!-- no ID required -->
<xsl:template match="configuration|nodes|node|crm_config|resources|constraints|operations|attributes">
  <xsl:element name="{name()}">
    <xsl:apply-templates select="@*"/>
    <xsl:apply-templates select="node()" />
  </xsl:element>
</xsl:template>

<!-- override the ID field for these objects -->
<xsl:template match="nvpair|instance_attributes|expression|meta_attributes">
  <xsl:element name="{name()}">
    <xsl:attribute name="id">
      <xsl:value-of select="name()"/>
      <xsl:text>.auto-</xsl:text>
      <xsl:number level="any" from="cib"/>
    </xsl:attribute>
    <xsl:for-each select="@*"> 
      <xsl:choose>
	<xsl:when test="not(contains(name(), 'id'))">
	  <xsl:apply-templates select="."/>
	</xsl:when>
      </xsl:choose>
    </xsl:for-each> 
    <xsl:apply-templates select="node()" />
  </xsl:element>
  <!--xsl:apply-templates/-->
</xsl:template>

<xsl:template match="rule">
  <xsl:element name="{name()}">

    <!-- set a automatic ID -->
    <xsl:attribute name="id">
      <xsl:value-of select="name()"/>
      <xsl:text>.auto-</xsl:text>
      <xsl:number level="any" from="cib"/>
    </xsl:attribute>

    <!-- make sure some sort of score is always set -->
    <xsl:if test="not(@score)">
      <xsl:if test="not(@score_attribute)">
	<xsl:attribute name="score">0</xsl:attribute>
      </xsl:if>
    </xsl:if>

    <!-- make sure our value for ID is used -->
    <xsl:for-each select="@*"> 
      <xsl:choose>
	<xsl:when test="not(contains(name(), 'id'))">
	  <xsl:apply-templates select="."/>
	</xsl:when>
      </xsl:choose>
    </xsl:for-each> 
    <xsl:apply-templates select="node()" />
  </xsl:element>
  <!--xsl:apply-templates/-->
</xsl:template>

<xsl:template match="date_expression">
  <xsl:element name="{name()}">

    <!-- set a automatic ID -->
    <xsl:attribute name="id">
      <xsl:value-of select="name()"/>
      <xsl:text>.auto-</xsl:text>
      <xsl:number level="any" from="cib"/>
    </xsl:attribute>

    <!-- make sure operation is always set -->
    <xsl:attribute name="operation">in_range</xsl:attribute>

    <!-- make sure our value for ID is used -->
    <xsl:for-each select="@*"> 
      <xsl:choose>
	<xsl:when test="not(contains(name(), 'id'))">
	  <xsl:apply-templates select="."/>
	</xsl:when>
      </xsl:choose>
    </xsl:for-each>
    <xsl:apply-templates select="node()" />
  </xsl:element>
  <!--xsl:apply-templates/-->
</xsl:template>

<xsl:template match="op">
  <xsl:element name="{name()}">

    <!-- set a automatic ID -->
    <xsl:attribute name="id">
      <xsl:value-of select="name()"/>
      <xsl:text>.auto-</xsl:text>
      <xsl:number level="any" from="cib"/>
    </xsl:attribute>

    <!-- arrange for the name to be before interval -->
    <xsl:attribute name="name"/>

    <!-- make sure interval is always set -->
    <xsl:attribute name="interval">0</xsl:attribute>

    <!-- make sure our value for ID is used -->
    <xsl:for-each select="@*"> 
      <xsl:choose>
	<xsl:when test="not(contains(name(), 'id'))">
	  <xsl:apply-templates select="."/>
	</xsl:when>
      </xsl:choose>
    </xsl:for-each> 
    <xsl:apply-templates select="node()" />
  </xsl:element>
  <!--xsl:apply-templates/-->
</xsl:template>

<xsl:template match="date_expression">
  <xsl:element name="{name()}">

    <!-- set a automatic ID -->
    <xsl:attribute name="id">
      <xsl:value-of select="name()"/>
      <xsl:text>.auto-</xsl:text>
      <xsl:number level="any" from="cib"/>
    </xsl:attribute>

    <!-- make sure operation is always set -->
    <xsl:attribute name="operation">in_range</xsl:attribute>

    <!-- make sure our value for ID is used -->
    <xsl:for-each select="@*"> 
      <xsl:choose>
	<xsl:when test="not(contains(name(), 'id'))">
	  <xsl:apply-templates select="."/>
	</xsl:when>
      </xsl:choose>
    </xsl:for-each>
    <xsl:apply-templates select="node()" />
  </xsl:element>
  <!--xsl:apply-templates/-->
</xsl:template>

<xsl:template match="rsc_order">
  <xsl:element name="{name()}">

    <!-- set a automatic ID -->
    <xsl:attribute name="id">
      <xsl:value-of select="name()"/>
      <xsl:text>.auto-</xsl:text>
      <xsl:number level="any" from="cib"/>
    </xsl:attribute>

    <xsl:for-each select="@*"> 
      <xsl:choose>
	<xsl:when test="not(contains(name(), 'type'))">
	  <xsl:apply-templates select="."/>
	</xsl:when>
      </xsl:choose>
    </xsl:for-each>

    <!-- normalize ordering  -->
    <xsl:if test="contains(@type, 'before')">
      <xsl:attribute name="from">
	<xsl:value-of select="@to"/>
      </xsl:attribute>
      <xsl:attribute name="to">
	<xsl:value-of select="@from"/>
      </xsl:attribute>
      <xsl:if test="@to_role">
	  <xsl:attribute name="from_role">
	    <xsl:value-of select="@to_role"/>
	  </xsl:attribute>
      </xsl:if>
      <xsl:if test="@from_role">
	<xsl:attribute name="to_role">
	  <xsl:value-of select="@from_role"/>
	</xsl:attribute>
      </xsl:if>
    </xsl:if>

    <xsl:apply-templates select="node()" />
  </xsl:element>
  <!--xsl:apply-templates/-->
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
