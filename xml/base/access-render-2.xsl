<!--
 Copyright 2019 the Pacemaker project contributors

 The version control history for this file may have further details.

 Licensed under the GNU General Public License version 2 or later (GPLv2+).
 -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                              xmlns:accessrender="http://clusterlabs.org/ns/pacemaker/access/render/2"
                              xmlns:accessrendercfg="http://clusterlabs.org/ns/pacemaker/access/render/cfg">

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
<xsl:param name="accessrendercfg:c-writable"><!-- green -->\x1b[32m</xsl:param>
<xsl:param name="accessrendercfg:c-readable"><!-- blue  -->\x1b[34m</xsl:param>
<xsl:param name="accessrendercfg:c-denied"><!--   red   -->\x1b[31m</xsl:param>
<xsl:param name="accessrendercfg:c-reset"><!--    reset -->\x1b[0m</xsl:param>

<xsl:param name="accessrender:extra-spacing">
  <xsl:value-of select="'no'"/>
</xsl:param>
<xsl:param name="accessrender:self-reproducing-prefix">
  <xsl:value-of select="''"/>
</xsl:param>

<xsl:variable name="accessrender:ns-writable" select="'http://clusterlabs.org/ns/pacemaker/access/writable'"/>
<xsl:variable name="accessrender:ns-readable" select="'http://clusterlabs.org/ns/pacemaker/access/readable'"/>
<xsl:variable name="accessrender:ns-denied"   select="'http://clusterlabs.org/ns/pacemaker/access/denied'"/>

<!--

 accessrender:interpolate-annotation named template

 -->

<xsl:template name="accessrender:interpolate-annotation">
  <xsl:choose>
    <xsl:when test="namespace-uri() = $accessrender:ns-writable">
      <xsl:value-of select="$accessrendercfg:c-writable"/>
    </xsl:when>
    <xsl:when test="namespace-uri() = $accessrender:ns-readable">
      <xsl:value-of select="$accessrendercfg:c-readable"/>
    </xsl:when>
    <xsl:when test="namespace-uri() = $accessrender:ns-denied">
      <xsl:value-of select="$accessrendercfg:c-denied"/>
    </xsl:when>
  </xsl:choose>
</xsl:template>

<!--

 accessrender:namespaces mode

 -->

<xsl:template match="*" mode="accessrender:namespaces">
  <!-- assume c-writable is representative of others (c-readable, c-denied) -->
  <xsl:if test="concat(
                  substring-before($accessrendercfg:c-writable, ':'),
                  ':'
                ) = $accessrendercfg:c-writable">
    <xsl:if test="//*[namespace-uri() = $accessrender:ns-writable]
                  or
                  //@*[namespace-uri() = $accessrender:ns-writable]">
      <xsl:value-of select="concat(' xmlns:',
                                   substring-before($accessrendercfg:c-writable, ':'),
                                   '=&quot;', $accessrender:ns-writable, '&quot;')"/>
    </xsl:if>
    <xsl:if test="//*[namespace-uri() = $accessrender:ns-readable]
                  or
                  //@*[namespace-uri() = $accessrender:ns-readable]">
      <xsl:value-of select="concat(' xmlns:',
                                   substring-before($accessrendercfg:c-readable, ':'),
                                   '=&quot;', $accessrender:ns-readable, '&quot;')"/>
    </xsl:if>
    <xsl:if test="//*[namespace-uri() = $accessrender:ns-denied]
                  or
                  //@*[namespace-uri() = $accessrender:ns-denied]">
      <xsl:value-of select="concat(' xmlns:',
                                   substring-before($accessrendercfg:c-denied, ':'),
                                   '=&quot;', $accessrender:ns-denied, '&quot;')"/>
    </xsl:if>
  </xsl:if>
</xsl:template>

<!--

 accessrender:proceed mode

 -->

<xsl:template match="*" mode="accessrender:proceed">
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
    <xsl:if test="namespace-uri() != namespace-uri(..)
                  or
                  $accessrendercfg:c-reset != ''">
      <xsl:call-template name="accessrender:interpolate-annotation"/>
    </xsl:if>
  </xsl:variable>
  <!-- tag opening -->
  <xsl:choose>
    <!-- special-casing based on $extra-annotation ending with colon -->
    <xsl:when test="$accessrender:self-reproducing-prefix != ''
                    and
                    concat(
                      substring-before($extra-annotation, ':'),
                      ':'
                    ) = $extra-annotation">
      <xsl:value-of select="concat('&lt;', $extra-annotation, local-name())"/>
    </xsl:when>
    <xsl:when test="$accessrender:extra-spacing = 'yes'
                    and
                    $extra-annotation != ''">
      <xsl:value-of select="concat(
                              preceding-sibling::text()[last()],
                              $extra-annotation,
                              $whitespace-before,
                              '&lt;',
                              local-name()
                            )"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:value-of select="concat($extra-annotation, '&lt;', local-name())"/>
    </xsl:otherwise>
  </xsl:choose>

  <xsl:apply-templates mode="accessrender:proceed" select="@*"/>

  <!-- for root and true XML output, figure out the namespaces used -->
  <xsl:if test=". = /*
               and
               $accessrender:self-reproducing-prefix != ''">
    <xsl:apply-templates mode="accessrender:namespaces" select="."/>
  </xsl:if>

  <!-- tag closing -->
  <xsl:choose>
    <xsl:when test="*|comment()|processing-instruction()">
      <xsl:value-of select="'&gt;'"/>
      <xsl:apply-templates mode="accessrender:proceed" select="node()"/>
      <xsl:choose>
        <!-- special-casing based on $extra-annotation ending with colon -->
        <xsl:when test="$accessrender:self-reproducing-prefix != ''
                        and
                        concat(
                          substring-before($extra-annotation, ':'),
                          ':'
                        ) = $extra-annotation">
          <xsl:value-of select="concat(
                                  '&lt;/',
                                  $extra-annotation,
                                  local-name(), '&gt;'
                                )"/>
        </xsl:when>
        <xsl:otherwise>
          <xsl:if test="$accessrender:extra-spacing = 'no'">
            <xsl:value-of select="$extra-annotation"/>
          </xsl:if>
          <xsl:value-of select="concat(
                                  '&lt;/',
                                  local-name(),
                                  '&gt;'
                                )"/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:when>
    <xsl:otherwise>
      <xsl:value-of select="'/&gt;'"/>
      <xsl:apply-templates mode="accessrender:proceed" select="node()"/>
    </xsl:otherwise>
  </xsl:choose>
  <!-- do not taint any subsequent terminal session -->
  <xsl:value-of select="$accessrendercfg:c-reset"/>
</xsl:template>

<xsl:template match="@*" mode="accessrender:proceed">
  <!-- XXX especially "text" output untest{ed,able} since no support for
           attribute granularity for now -->
  <xsl:variable name="extra-annotation">
    <xsl:if test="namespace-uri() != namespace-uri(..)">
      <xsl:call-template name="accessrender:interpolate-annotation"/>
    </xsl:if>
  </xsl:variable>
  <xsl:choose>
    <xsl:when test="namespace-uri() != namespace-uri(..)
                    and
                    $accessrender:self-reproducing-prefix != ''">
      <xsl:value-of select="' '"/>
      <xsl:choose>
        <xsl:when test="concat(
                          substring-before($extra-annotation, ':'),
                          ':'
                        ) = $extra-annotation">
          <xsl:value-of select="substring-before($extra-annotation, ':')"/>
        </xsl:when>
      </xsl:choose>
      <xsl:value-of select="concat(':', local-name(), '=&quot;', ., '&quot;')"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:value-of select="concat(' ', local-name(), '=&quot;', ., '&quot;')"/>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<xsl:template match="comment()|processing-instruction()|text()" mode="accessrender:proceed">
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
  <xsl:apply-templates mode="accessrender:proceed" select="@*|node()"/>
  <!-- do not taint any subsequent terminal session -->
  <xsl:value-of select="$accessrendercfg:c-reset"/>
</xsl:template>

</xsl:stylesheet>
