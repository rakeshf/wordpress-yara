<?php
// TEST: $wpdb usage without prepare (should trigger WP_WPDB_Unprepared)
global $wpdb;
$user = $_GET['user'];
$result = $wpdb->query("SELECT * FROM wp_users WHERE user_login = '$user'");
