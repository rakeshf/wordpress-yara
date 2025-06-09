<?php
// TEST: SQL injection pattern using GET (should trigger WP_SQL_Concat_From_Input)
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $id;
mysql_query($query);
