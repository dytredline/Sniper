<?php
// PDO hazırlanmış ifadeyle yazma: SQL enjeksiyonu değil, ama girdi tabloya HTML kaçışı olmadan yazılıyor.
$pdo = new PDO("mysql:host=localhost;dbname=app", "u", "p");
$stmt = $pdo->prepare("INSERT INTO comments (author, body) VALUES (?, ?)");
$stmt->execute([$_POST['author'], $_POST['body']]);
$bio = $pdo->prepare("INSERT INTO profiles (bio) VALUES (:bio)");
$bio->bindParam(':bio', $_POST['bio']);
$bio->execute();
$tag = $pdo->prepare("INSERT INTO tags (name) VALUES (:n)");
$tag->bindValue(':n', htmlspecialchars($_POST['tag']));
$tag->execute();
$find = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$find->execute([$_GET['id']]);
