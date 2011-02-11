<html>
<head>
	<link href="/stylesheets/getpacemaker.css" media="screen, projection" rel="stylesheet" type="text/css" />
</head>
<body>
  <?php include '../../html/banner-small.php' ?>
 <div id="inner-body">
   <div class="coda-slider" style="padding: 20px; width: 800px;">
<p>
The following <a href="http://www.clusterlabs.org/wiki/Pacemaker">Pacemaker</a> documentation was generated from the upstream sources
</p>
<?php

 function get_versions($base) {
   $versions = array();
   foreach (glob("$base/*/Pacemaker/*") as $item)
     if ($item != '.' && $item != '..' && is_dir($item))
       $versions[] = basename($item);

   return array_unique($versions);
 }

 function docs_for_version($base, $version) {
   echo "<br/><li>Version: $version<br/>";
   foreach (glob("build-$version.txt") as $filename) {
      readfile($filename);
   }
   echo "<ul>";

   foreach (glob("$base/*/Pacemaker/$version") as $item) {
     $lang = basename(dirname(dirname($item)));

     $books = array();
     foreach (glob("$base/$lang/Pacemaker/$version/pdf/*") as $filename) {
       $books[] = basename($filename);
     }
     
     foreach ($books as $b) {
       echo "<li>".str_replace("_", " ", $b)." ($lang)";
       foreach (glob("$base/$lang/Pacemaker/$version/epub/$b/*.epub") as $filename) {
	 echo " [<a href=$filename>epub</a>]";
       }
       foreach (glob("$base/$lang/Pacemaker/$version/pdf/$b/*.pdf") as $filename) {
	 echo " [<a href=$filename>pdf</a>]";
       }
       foreach (glob("$base/$lang/Pacemaker/$version/html/$b/index.html") as $filename) {
	 echo " [<a href=$filename>html</a>]";
       }
       foreach (glob("$base/$lang/Pacemaker/$version/html-single/$b/index.html") as $filename) {
	 echo " [<a href=$filename>html-single</a>]";
       }
       foreach (glob("$base/$lang/Pacemaker/$version/txt/$b/*.txt") as $filename) {
	 echo " [<a href=$filename>txt</a>]";
       }
     }
     echo "</li><br/>";
   }
   echo "</ul>";
 }

$docs = array();

foreach (glob("*.html") as $file) {
  $fields = explode(".", $file, -1);
  $docs[] = implode(".", $fields);
}

foreach (glob("*.pdf") as $file) {
  $fields = explode(".", $file, -1);
  $docs[] = implode(".", $fields);
}

echo "<ul>";

foreach(array_unique($docs) as $doc) {
  echo "<li>$doc";
  foreach (glob("$doc.pdf") as $filename) {
    echo " [<a href=$filename>pdf</a>]";
  }
  foreach (glob("$doc.html") as $filename) {
    echo " [<a href=$filename>html</a>]";
  }
  foreach (glob("$doc.txt") as $filename) {
    echo " [<a href=$filename>txt</a>]";
  }
  echo "</li>";
}

foreach(get_versions(".") as $v) {
  docs_for_version(".", $v);
}

echo "</ul>";
?>
<p>
You can find <a href="http://www.clusterlabs.org/wiki/Documentation">additional documentation</a> and details about the Pacemaker project at <a href="http://www.clusterlabs.org">http://www.clusterlabs.org</a>.
  </p>
  </div>
  </div>
  <script type="text/javascript">
var gaJsHost = (("https:" == document.location.protocol) ? "https://ssl." : "http://www.");
document.write(unescape("%3Cscript src='" + gaJsHost + "google-analytics.com/ga.js' type='text/javascript'%3E%3C/script%3E"));
</script>
<script type="text/javascript">
try{
var pageTracker = _gat._getTracker("UA-8156370-1");
pageTracker._trackPageview();
} catch(err) {}</script>
</body>
</html>
