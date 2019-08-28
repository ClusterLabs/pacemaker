<!--
 Copyright 2019 the Pacemaker project contributors

 The version control history for this file may have further details.

 Licensed under the GNU General Public License version 2 or later (GPLv2+).
 -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                              xmlns:aclsrender="http://clusterlabs.org/ns/pacemaker/aclsrender-2"
                              xmlns:aclsrendercfg="http://clusterlabs.org/ns/pacemaker/acls-render-cfg">

<xsl:output method="text" encoding="UTF-8"/>

<!--
 see https://en.wikipedia.org/wiki/ANSI_escape_code#3/4_bith;
 note that we need to retain XML 1.0 (as opposed to 1.1, which in turn
 is not supported in libxml) compatibility in this very template, meaning
 we cannot output a superset of what's expressible in the template itself
 (escaped or not), hence we are forced to work that around for \x1b (ESC,
 unavoidable for ANSI colorized output) character with encoding it in some
 way (here using "\x1b" literal notation) and requiring a trivial
 "xsltproc ... | sed 's/\\x1b/\x1b/'" postprocessing;
 the above, however, only applies when used directly (which may be the
 reason to pay attention to this comment to begin with), but fortunately
 it is conveniently avoidable when XSLT triggered programatically (see
 pcmk__acl_evaled_render), since libxslt allows for passing raw (further
 unchecked) parameter strings, in which case the actual content of those
 parameters is decoded on the fly, meaning that this file is still open
 to compilation-free customizations if there's an irresistible need...
-->
<xsl:param name="aclsrendercfg:c-writable"><!-- green -->\x1b[32m</xsl:param>
<xsl:param name="aclsrendercfg:c-readable"><!-- blue  -->\x1b[34m</xsl:param>
<xsl:param name="aclsrendercfg:c-denied"><!--   red   -->\x1b[31m</xsl:param>
<xsl:param name="aclsrendercfg:c-reset"><!--    reset -->\x1b[0m</xsl:param>

<xsl:param name="aclsrender:extra-spacing">
  <xsl:value-of select="'no'"/>
</xsl:param>
<xsl:param name="aclsrender:self-reproducing-prefix">
  <xsl:value-of select="''"/>
</xsl:param>

<xsl:variable name="aclsrender:ns-writable" select="'http://clusterlabs.org/ns/pacemaker/acl-2-writable'"/>
<xsl:variable name="aclsrender:ns-readable" select="'http://clusterlabs.org/ns/pacemaker/acl-2-readable'"/>
<xsl:variable name="aclsrender:ns-denied" select="'http://clusterlabs.org/ns/pacemaker/acl-2-denied'"/>

<!--

 aclsrender:namespaces mode

 -->

<xsl:template match="*" mode="aclsrender:namespaces">
  <xsl:if test="//*[namespace-uri() = $aclsrender:ns-writable]">
    <xsl:value-of select="concat(' xmlns:', $aclsrender:self-reproducing-prefix,
                                 $aclsrendercfg:c-writable,
                                 '=&quot;', $aclsrender:ns-writable, '&quot;')"/>
  </xsl:if>
  <xsl:if test="//*[namespace-uri() = $aclsrender:ns-readable]">
    <xsl:value-of select="concat(' xmlns:', $aclsrender:self-reproducing-prefix,
                                 $aclsrendercfg:c-readable,
                                 '=&quot;', $aclsrender:ns-readable, '&quot;')"/>
  </xsl:if>
  <xsl:if test="//*[namespace-uri() = $aclsrender:ns-denied]">
    <xsl:value-of select="concat(' xmlns:', $aclsrender:self-reproducing-prefix,
                                 $aclsrendercfg:c-denied,
                                 '=&quot;', $aclsrender:ns-denied, '&quot;')"/>
  </xsl:if>
</xsl:template>

<!--

 aclsrender:proceed mode

 -->

<xsl:template match="*" mode="aclsrender:proceed">
  <xsl:variable name="whitespace-before">
    <!-- ensure newline also for the root element -->
    <xsl:choose>
      <xsl:when test="preceding-sibling::text()[last()] != ''">
        <xsl:value-of select="preceding-sibling::text()[last()]"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="'&#xA;'"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:variable>
  <xsl:variable name="extra-annotation">
    <xsl:if test="namespace-uri() != namespace-uri(..)">
      <xsl:value-of select="$aclsrender:self-reproducing-prefix"/>
      <xsl:choose>
        <xsl:when test="namespace-uri() = $aclsrender:ns-writable">
          <xsl:value-of select="$aclsrendercfg:c-writable"/>
        </xsl:when>
        <xsl:when test="namespace-uri() = $aclsrender:ns-readable">
          <xsl:value-of select="$aclsrendercfg:c-readable"/>
        </xsl:when>
        <xsl:when test="namespace-uri() = $aclsrender:ns-denied">
          <xsl:value-of select="$aclsrendercfg:c-denied"/>
        </xsl:when>
      </xsl:choose>
    </xsl:if>
  </xsl:variable>
  <!-- tag opening -->
  <xsl:if test="$extra-annotation != ''">
    <xsl:if test="$aclsrender:extra-spacing = 'yes'">
      <xsl:value-of select="preceding-sibling::text()[last()]"/>
    </xsl:if>
    <xsl:if test="$aclsrender:self-reproducing-prefix != ''">
      <xsl:value-of select="'&lt;'"/>
    </xsl:if>
    <xsl:value-of select="$extra-annotation"/>
    <xsl:if test="$aclsrender:extra-spacing = 'yes'">
      <xsl:value-of select="$whitespace-before"/>
    </xsl:if>
  </xsl:if>
  <xsl:choose>
    <xsl:when test="$aclsrender:self-reproducing-prefix != ''
                    and
                    $extra-annotation != ''">
      <xsl:value-of select="concat(':', local-name())"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:value-of select="concat('&lt;', local-name())"/>
    </xsl:otherwise>
  </xsl:choose>
  <xsl:apply-templates mode="aclsrender:proceed" select="@*"/>
  <!-- for root and true XML output, figure out the namespaces used -->
  <xsl:if test=". = /*
               and
               $aclsrender:self-reproducing-prefix != ''">
    <xsl:apply-templates mode="aclsrender:namespaces" select="."/>
  </xsl:if>
  <!-- tag closing -->
  <xsl:choose>
    <xsl:when test="*|comment()|processing-instruction()">
      <xsl:value-of select="'&gt;'"/>
      <xsl:apply-templates mode="aclsrender:proceed" select="node()"/>
      <xsl:choose>
        <xsl:when test="$aclsrender:self-reproducing-prefix != ''
                        and
                        $extra-annotation != ''">
          <xsl:value-of select="concat('&lt;/', $extra-annotation, ':',
                                local-name(), '&gt;')"/>
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="concat('&lt;/', local-name(), '&gt;')"/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:when>
    <xsl:otherwise>
      <xsl:value-of select="'/&gt;'"/>
      <xsl:apply-templates mode="aclsrender:proceed" select="node()"/>
    </xsl:otherwise>
  </xsl:choose>
  <!-- possibly restore the color -->
  <xsl:if test="$aclsrender:extra-spacing = 'no'
                and
                $aclsrender:self-reproducing-prefix = ''">
    <xsl:choose>
      <xsl:when test="namespace-uri(..) = $aclsrender:ns-writable">
        <xsl:value-of select="$aclsrendercfg:c-writable"/>
      </xsl:when>
      <xsl:when test="namespace-uri(..) = $aclsrender:ns-readable">
        <xsl:value-of select="$aclsrendercfg:c-readable"/>
      </xsl:when>
      <xsl:when test="namespace-uri(..) = $aclsrender:ns-denied">
        <xsl:value-of select="$aclsrendercfg:c-denied"/>
      </xsl:when>
    </xsl:choose>
  </xsl:if>
</xsl:template>

<xsl:template match="@*" mode="aclsrender:proceed">
  <!-- XXX especially "text" output untest{ed,able} since no support for
           attribute granularity for now -->
  <xsl:choose>
    <xsl:when test="namespace-uri() != namespace-uri(..)
                    and
                    $aclsrender:self-reproducing-prefix != ''">
      <xsl:value-of select="concat(
                              ' ',
                              $aclsrender:self-reproducing-prefix
                            )"/>
      <xsl:choose>
        <xsl:when test="namespace-uri() = $aclsrender:ns-writable">
          <xsl:value-of select="$aclsrendercfg:c-writable"/>
        </xsl:when>
        <xsl:when test="namespace-uri() = $aclsrender:ns-readable">
          <xsl:value-of select="$aclsrendercfg:c-readable"/>
        </xsl:when>
        <xsl:when test="namespace-uri() = $aclsrender:ns-denied">
          <xsl:value-of select="$aclsrendercfg:c-denied"/>
        </xsl:when>
      </xsl:choose>
      <xsl:value-of select="concat(':', local-name(), '=&quot;', ., '&quot;')"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:value-of select="concat(' ', local-name(), '=&quot;', ., '&quot;')"/>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<xsl:template match="comment()|processing-instruction()|text()" mode="aclsrender:proceed">
  <xsl:choose>
    <xsl:when test="self::comment()">
      <xsl:value-of select="'&lt;!-- '"/>
    </xsl:when>
    <xsl:when test="self::processing-instruction()">
      <xsl:value-of select="'&lt;? '"/>
    </xsl:when>
  </xsl:choose>
  <xsl:value-of select="."/>
  <xsl:choose>
    <xsl:when test="self::comment()">
      <xsl:value-of select="' --&gt;&#xA;'"/>
    </xsl:when>
    <xsl:when test="self::processing-instruction()">
      <xsl:value-of select="'?&gt;'&#xA;"/>
    </xsl:when>
  </xsl:choose>
</xsl:template>

<!-- mode-less, easy to override kick-off -->
<xsl:template match="/">
  <xsl:apply-templates mode="aclsrender:proceed" select="@*|node()"/>
  <!-- do not taint any subsequent terminal session -->
  <xsl:value-of select="$aclsrendercfg:c-reset"/>
</xsl:template>

</xsl:stylesheet>
