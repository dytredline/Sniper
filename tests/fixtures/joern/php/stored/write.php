<?php
// Veritabanı üzerinden kalıcı XSS: girdi tabloya (SQL için kaçışlanarak) yazılır, başka dosyada okunup basılır.
$conn = mysqli_connect("localhost", "u", "p", "db");
$msg = $_POST['msg'];
mysqli_query($conn, "INSERT INTO guestbook (msg) VALUES ('" . mysqli_real_escape_string($conn, $msg) . "')");
$body = htmlspecialchars($_POST['body']);
mysqli_query($conn, "INSERT INTO notes (body) VALUES ('" . mysqli_real_escape_string($conn, $body) . "')");
