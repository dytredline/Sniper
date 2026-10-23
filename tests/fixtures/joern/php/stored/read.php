<?php
$conn = mysqli_connect("localhost", "u", "p", "db");
$result = mysqli_query($conn, "SELECT msg FROM guestbook");
while ($row = mysqli_fetch_assoc($result)) {
    echo "<li>" . $row['msg'] . "</li>"; // EXPECT: xss
}
$notes = mysqli_query($conn, "SELECT body FROM notes");
while ($note = mysqli_fetch_assoc($notes)) {
    echo "<li>" . $note['body'] . "</li>";
}
