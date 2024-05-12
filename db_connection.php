<?php
// Database connection parameters
$servername = "localhost";
$username = "root";
$password = ""; // Assuming you have no password set for your database
$database = "event_management";

// Create connection
$conn = new mysqli($servername, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
