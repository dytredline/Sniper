<?php
// Olumsuz: yazan dosya girdiyi izin listesiyle doğruluyor / HTML kaçışlıyor; okuyan dosya önce düz atama yapıyor.
switch ($_GET['lvl']) {
    case 'c': $file = 'c.php'; break;
    default: $file = 'd.php';
}
require_once dirname(__FILE__) . "/source/{$file}";
include($doc);
echo "<div>{$out}</div>";
$note = "sabit";
echo $note;
