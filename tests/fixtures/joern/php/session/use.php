<?php
session_start();
$conn = mysqli_connect("localhost", "u", "p", "db");
$uid = $_SESSION['uid'];
mysqli_query($conn, "SELECT * FROM users WHERE id = '$uid'"); // EXPECT: sql
$role = $_SESSION['role'];
mysqli_query($conn, "SELECT * FROM roles WHERE name = '$role'");
