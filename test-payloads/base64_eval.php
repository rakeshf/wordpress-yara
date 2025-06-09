<?php
// TEST: base64 + eval combo (should trigger WP_Suspicious_Eval_Base64)
$payload = base64_decode('ZWNobyAiSGVsbG8gd29ybGQiOw==');
eval($payload);
