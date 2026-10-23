<?php
$doc = $_GET['doc'];
if (!in_array($doc, array('a.php', 'b.php'))) {
    exit;
}
if (isset($_GET['who'])) {
    $who = htmlspecialchars($_GET['who']);
    $out .= "<pre>{$who}</pre>";
}
$note = $_GET['note'];
