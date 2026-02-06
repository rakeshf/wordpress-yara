rule wp_insecure_tls_disabled
{
    meta:
        description = "Insecure TLS verification disabled"
        category = "TLS"
    strings:
        $s1 = /['"]sslverify['"]\s*=>\s*false/i
        $s2 = /['"]verify['"]\s*=>\s*false/i
        $s3 = /CURLOPT_SSL_VERIFYPEER\s*,\s*false/i
        $s4 = /CURLOPT_SSL_VERIFYHOST\s*,\s*(0|false)/i
    condition:
        filesize < 10MB and any of ($s*)
}

rule wordpress_csrf_missing_nonce_verification
{
    meta:
        description = "State-changing action without nonce verification"
        category = "CSRF"
    strings:
        $input = /\$_(GET|POST|REQUEST)\[[^\]]+\]/i
        $state = /(update_option|delete_option|wp_update_post|file_put_contents|unlink|mkdir)/i
        $nonce = /(check_admin_referer|check_ajax_referer|wp_verify_nonce)/i
    condition:
        filesize < 10MB and $input and $state and not $nonce
}

rule wordpress_rce_unserialize
{
    meta:
        description = "Unserialize on user input"
        category = "RCE"
    strings:
        $u1 = /unserialize\s*\(\s*\$_(GET|POST|REQUEST)\[[^\]]+\]\s*\)/i
        $u2 = /unserialize\s*\(\s*base64_decode\s*\(\s*\$_(GET|POST|REQUEST)\[[^\]]+\]\s*\)\s*\)/i
    condition:
        filesize < 10MB and any of ($u*)
}

rule wordpress_file_upload_no_validation
{
    meta:
        description = "File upload without validation"
        category = "File Upload"
    strings:
        $upload = /move_uploaded_file\s*\(.*\$_FILES/i
        $fake   = /\.(php|js).*\.(jpg|png|gif)/i
    condition:
        filesize < 10MB and $upload and not $fake
}

rule wordpress_rfi_lfi_includes
{
    meta:
        description = "RFI/LFI via include or require"
        category = "RFI/LFI"
    strings:
        $inc = /(include|require)(_once)?\s*\(\s*\$_(GET|POST|REQUEST)\[[^\]]+\]\s*\)/i
    condition:
        filesize < 10MB and $inc
}

rule wordpress_missing_capability_check
{
    meta:
        description = "Privileged action without capability check"
        category = "Access Control"
    strings:
        $update = /update_(option|site_option|user_meta)\s*\(.*\$_(GET|POST|REQUEST|COOKIE)/i
        $cap    = "current_user_can"
    condition:
        filesize < 10MB and $update and not $cap
}

rule wp_obfuscated_malicious_patterns
{
    meta:
        description = "Obfuscated or malicious PHP"
        category = "Malware"
    strings:
        $eval = /\beval\s*\(/i
        $ass  = /\bassert\s*\(/i
        $b64  = /base64_decode\s*\(/i
        $gzi  = /gzinflate\s*\(|gzuncompress\s*\(/i
        $rot  = /str_rot13\s*\(/i
    condition:
        filesize < 10MB and ( $eval or $ass or 2 of ($b64,$gzi,$rot) )
}
