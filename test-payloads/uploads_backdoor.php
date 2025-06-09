<?php
// Path simulation only: save this in test-payloads/wp-content/uploads/backdoor.php
// TEST: PHP inside uploads folder (should trigger WP_Suspicious_Uploads_PHP)
echo "hello";
