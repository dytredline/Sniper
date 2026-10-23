<?php
$pdo = new PDO("mysql:host=localhost;dbname=app", "u", "p");
$rows = $pdo->query("SELECT author, body FROM comments");
foreach ($rows as $row) {
    echo "<p>" . $row['body'] . "</p>"; // EXPECT: xss
}
$profile = $pdo->prepare("SELECT bio FROM profiles WHERE id = ?");
$profile->execute([1]);
$p = $profile->fetch();
echo "<div>" . $p['bio'] . "</div>"; // EXPECT: xss
$tags = $pdo->query("SELECT name FROM tags");
while ($t = $tags->fetch()) {
    echo "<li>" . $t['name'] . "</li>";
}
$sessions = $pdo->query("SELECT token FROM sessions");
foreach ($sessions as $s) {
    echo "<i>" . $s['token'] . "</i>";
}
