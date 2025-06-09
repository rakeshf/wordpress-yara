<?php
// TEST: Suspicious shell function usage (should trigger WP_Suspicious_Shell_Functions)
$cmd = $_GET['cmd'];
echo shell_exec($cmd);
