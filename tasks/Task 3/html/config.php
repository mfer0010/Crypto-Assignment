<?php
session_start();
$host = "localhost"; /* Host name */
$user = "root"; /* User */
$password = "27E46222!"; /* Password */
$dbname = "crypto"; /* Database name */

$con = mysqli_connect($host, $user, $password,$dbname);
// Check connection
if (!$con) {
 die("Connection failed: " . mysqli_connect_error());
}