<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
 version="1.0">

 <xsl:output indent="yes"
             doctype-public="-//OASIS//DTD DocBook XML V4.4//EN"
             doctype-system="docbookx.dtd"/>

 <!--<xsl:strip-space elements="longdesc shortdesc"/>-->


 <!--  -->
 <xsl:param name="man.name">NA</xsl:param>

 <!--  -->
 <xsl:param name="man.vol">7</xsl:param>

 <!--  -->
 <xsl:param name="variable.prefix"> </xsl:param>
 
 <!--  -->
 <xsl:param name="command.prefix"> </xsl:param>
 
 <!-- Separator between different action/@name -->
 <xsl:param name="separator"> | </xsl:param>

 <xsl:template match="/">
  <refentry>
    <xsl:apply-templates mode="root"/>
  </refentry>
 </xsl:template>

 <xsl:template match="resource-agent" mode="root">
  <xsl:param name="this" select="self::resource-agent"/>
  <info>
    <author>
      <personname>
	<firstname>Andrew</firstname>
	<surname>Beekhof</surname>
	<email>andrew@beekhof.net</email>
      </personname>
    </author>
  </info>
  <refmeta>
    <refentrytitle><xsl:value-of select="concat($command.prefix, @name)"/></refentrytitle>
    <manvolnum><xsl:value-of select="$man.vol"/></manvolnum>
    <refmiscinfo>
      <source></source>
      <manual>Pacemaker Configuration</manual>
    </refmiscinfo>
  </refmeta>
  <refnamediv>
    <refname>
      <xsl:choose>
	<xsl:when test="$man.name = 'NA'">
	  <xsl:value-of select="concat($command.prefix, @name)"/>
	</xsl:when>
	<xsl:otherwise>
	  <xsl:value-of select="$man.name"/>
	</xsl:otherwise>
      </xsl:choose>
    </refname>
    <refpurpose><xsl:apply-templates select="shortdesc"/></refpurpose>
  </refnamediv>
  <xsl:apply-templates select="$this" mode="synopsis"/>
  <xsl:apply-templates select="$this" mode="description"/>
  <xsl:apply-templates select="$this" mode="parameters"/>
 </xsl:template>


 <!-- Empty Templates -->
 <xsl:template match="node()" mode="root"/>
 
 <xsl:template match="*" mode="synopsis"/>
 <xsl:template match="*" mode="description"/>
 <xsl:template match="*" mode="parameters"/>
 
 <!-- Mode synopsis -->
 <xsl:template match="resource-agent" mode="synopsis">
  <xsl:text>&#10;</xsl:text>
  <refsect1><xsl:text>&#10;  </xsl:text>
   <title>Synopsis</title>
   <xsl:text>&#10;  </xsl:text>
   <para>
    <xsl:apply-templates select="parameters/parameter" mode="synopsis"/>
    <xsl:text>&#10;  </xsl:text>
    <literal/>
    <xsl:text>&#10;  </xsl:text>
    <xsl:apply-templates select="actions" mode="synopsis">
     <xsl:with-param name="name" select="@name"/>
    </xsl:apply-templates>
   </para>
   <xsl:text>&#10;</xsl:text>
  </refsect1>
 </xsl:template>

 <xsl:template match="parameters/parameter" mode="synopsis">
  <xsl:if test="not(@unique='1')">
   <xsl:text>[</xsl:text>
  </xsl:if>
  
  <command><xsl:value-of select="concat($variable.prefix, @name)"/></command>
  <xsl:text>=</xsl:text>
  <xsl:value-of select="content/@type"/>
  
  <xsl:if test="not(@unique='1')">
   <xsl:text>]</xsl:text>
  </xsl:if>
  
  <xsl:text> </xsl:text>
 </xsl:template>


  <xsl:template match="actions" mode="synopsis">
   <xsl:param name="name"/>
   
   <command><xsl:value-of select="$name"/></command>
   <xsl:text> [</xsl:text>
   <xsl:apply-templates select="action" mode="synopsis"/>
   <xsl:text>]</xsl:text>
  </xsl:template>
 
 
  <xsl:template match="action" mode="synopsis">
   <xsl:value-of select="@name"/>
   <xsl:if test="following-sibling::action">
     <xsl:value-of select="$separator"/>
   </xsl:if>
  </xsl:template>


 <!-- Mode Description --> 
 <xsl:template match="resource-agent" mode="description">
    <xsl:text>&#10;&#10;</xsl:text>
    <refsect1><xsl:text>&#10;  </xsl:text>
      <title>Description</title>
      <xsl:apply-templates mode="description"/>
    </refsect1>
    <xsl:text>&#10;</xsl:text>
  </xsl:template>
 
  <xsl:template match="longdesc" mode="description">
    <para>
     <xsl:apply-templates mode="description"/>
    </para>
  </xsl:template>
 
 
  <!-- Mode Parameters -->
  <xsl:template match="resource-agent" mode="parameters">
   <xsl:text>&#10;&#10;</xsl:text>
    <refsect1><xsl:text>&#10;  </xsl:text>
      <title>Supported Parameters</title>
      <xsl:apply-templates mode="parameters"/>
    </refsect1>
    <xsl:text>&#10;</xsl:text>
  </xsl:template>
 
 <xsl:template match="resource-agent/shortdesc|resource-agent/longdesc" mode="parameters"/>
 
  <xsl:template match="parameters" mode="parameters">
   <variablelist>
    <xsl:apply-templates mode="parameters"/>
   </variablelist>
  </xsl:template>
  
  
  <xsl:template match="parameter" mode="parameters">
   <varlistentry>
    <term>
      <command><xsl:value-of select="concat($variable.prefix, @name)"/></command>
      <xsl:text> = </xsl:text>
      <xsl:value-of select="content/@type"/>
      <xsl:if test="content/@default">
	<xsl:text> [</xsl:text>
	<xsl:value-of select="content/@default"/>
	<xsl:text>]</xsl:text>
      </xsl:if>
    </term>
    <xsl:text>&#10;</xsl:text>
    <xsl:choose>
      <xsl:when test="longdesc/text() = shortdesc/text()">
	<listitem>
	  <para>
	    <xsl:value-of select="shortdesc/text()"/>
	  </para>
	</listitem>
      </xsl:when>
      <xsl:otherwise>
	<listitem>
	  <para>
	    <xsl:value-of select="shortdesc/text()"/>
	  </para>
	  <para>
	    <xsl:value-of select="longdesc/text()"/>
	  </para>
	</listitem>
      </xsl:otherwise>
    </xsl:choose>
    <!--xsl:if test="longdesc">
      <xsl:if test="longdesc != shortdesc">
	<listitem>
	  <xsl:text>&#10;</xsl:text>
	  <xsl:apply-templates select="longdesc" mode="parameters"/>
	</listitem>
      </xsl:if>
    </xsl:if-->
    <xsl:text>&#10;</xsl:text>
   </varlistentry>
  </xsl:template>
  
  
   <xsl:template match="longdesc" mode="parameters">
    <para>
      <xsl:apply-templates select="text()" mode="parameters"/>
    </para>
  </xsl:template>
 
  
  <xsl:template match="shortdesc" mode="parameters">
   <xsl:apply-templates select="text()" mode="parameters"/>
  </xsl:template>
  
</xsl:stylesheet>
