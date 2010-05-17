<?xml version='1.0'?>
 
<!--
        Copyright 2009 Andrew Beekhof
        License: GPL
        Author: Andrew Beekhof <andrew@beekhof.net>
-->

<!DOCTYPE xsl:stylesheet [
<!ENTITY lowercase "'abcdefghijklmnopqrstuvwxyz'">
<!ENTITY uppercase "'ABCDEFGHIJKLMNOPQRSTUVWXYZ'">
 ]>

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                version='1.0'
                xmlns="http://www.w3.org/TR/xhtml1/transitional"
                xmlns:fo="http://www.w3.org/1999/XSL/Format"
                exclude-result-prefixes="#default">

<xsl:param name="title.color">#843A39</xsl:param>
<!-- http://docbook.sourceforge.net/release/xsl/current/doc/html/generate.toc.html -->
<xsl:param name="generate.toc">
appendix  toc,title
article/appendix  nop
article   toc,title
book      toc,title,figure,table,example,equation
chapter   toc,title
part      toc,title
preface   toc,title
qandadiv  nop
qandaset  nop
reference toc,title
sect1	  nop
sect2	  nop
sect3	  nop
sect4	  nop
sect5	  nop
section   nop
set       toc,title
<!-- publican defaults
set toc
book toc,qandadiv
article toc
chapter nop
qandadiv nop
qandaset nop
sect1 nop
sect2 nop
sect3 nop
sect4 nop
sect5 nop
section nop
part nop
-->
</xsl:param>

<xsl:template name="tr.attributes">
  <xsl:param name="row" select="."/>
  <xsl:param name="rownum" select="0"/>

  <xsl:if test="$rownum mod 2 = 0">
    <xsl:attribute name="class">even</xsl:attribute>
  </xsl:if>

</xsl:template>


</xsl:stylesheet>
