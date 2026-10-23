<?php
// Oturum üzerinden ikinci derece akış: girdi oturuma yazılır, başka dosyada okunur.
session_start();
$_SESSION['uid'] = $_POST['uid'];
$_SESSION['role'] = 'user';
