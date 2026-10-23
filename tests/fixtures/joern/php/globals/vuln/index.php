<?php
// Dosyalar arası küresel değişken: seçilen seviye dosyası $page/$html yazar, bu dosya kullanır.
$level = $_COOKIE['level'] == 'a' ? 'a' : 'b';
require_once dirname(__FILE__) . "/source/{$level}.php";
include($page); // EXPECT: path
echo "<div>{$html}</div>"; // EXPECT: xss
function render() {
    global $html;
    print($html); // EXPECT: xss
}
function render2() {
    print($GLOBALS['html']); // EXPECT: xss
}
function render3() {
    $html = "yerel";
    print($html);
}
