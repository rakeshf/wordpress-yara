<?php

$wpdb->query("SELECT * FROM users WHERE id='$_GET[id]'");
