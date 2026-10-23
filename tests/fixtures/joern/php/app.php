<?php
// PHP kaynak/hedef modelleri: olumlu (EXPECT) ve olumsuz örnekler.
$id = $_GET['id'];
$conn = mysqli_connect("localhost", "u", "p", "db");
mysqli_query($conn, "SELECT * FROM users WHERE id = '$id'"); // EXPECT: sql
$num = intval($_GET['n']);
mysqli_query($conn, "SELECT * FROM users WHERE id = $num");
$pdo = new PDO("sqlite::memory:");
$pdo->query("SELECT * FROM t WHERE name = '" . $_POST['name'] . "'"); // EXPECT: sql
$stmt = $pdo->prepare("SELECT * FROM t WHERE name = ?");
$stmt->execute(array($_POST['name']));
system("ping -c 1 " . $_REQUEST['host']); // EXPECT: command
system("ping -c 1 " . escapeshellarg($_REQUEST['host']));
$out = shell_exec("ls " . $_COOKIE['dir']); // EXPECT: command
include($_GET['page'] . ".php"); // EXPECT: path
include("header.php");
eval("return " . $_GET['expr'] . ";"); // EXPECT: eval
echo "Merhaba " . $_GET['name']; // EXPECT: xss
echo "Merhaba " . htmlspecialchars($_GET['name']);
header("Location: " . $_GET['next']); // EXPECT: redirect
header("Content-Type: text/plain");
$handle = fopen($_GET['file'], "r"); // EXPECT: path
$data = unserialize($_COOKIE['state']); // EXPECT: deserialize
