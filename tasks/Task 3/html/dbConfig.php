<?php

define ("DB_HOST", "localhost"); // set database host

define ("DB_USER", "root"); // set database user

define ("DB_PASS","27E46222!"); // set database password

define ("DB_NAME","members"); // set database name



$link = mysql_connect(DB_HOST, DB_USER, DB_PASS) or die("Couldn't make connection.");

$db = mysql_select_db(DB_NAME, $link) or die("Couldn't select database");

?>