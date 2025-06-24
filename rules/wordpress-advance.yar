rule wordpress_csrf_missing_nonce_check
{
    meta:
        description = "Detect missing or weak CSRF protection"
        category = "CSRF"
    strings:
        $1 = /(?i)\$_(POST|GET|REQUEST)\[.*\].*\{.*(update|delete|create).*\}/
        $2 = /(?i)(?!check_admin_referer|check_ajax_referer|wp_verify_nonce).*\$_(POST|GET|REQUEST)/
    condition:
        any of ($1, $2)
}

rule wordpress_sql_injection_unsanitized_input
{
    meta:
        description = "Detect possible SQL injection via unsanitized user input"
        category = "SQL Injection"
    strings:
        $query = /SELECT.*\$_(GET|POST|REQUEST)/
        $unsafe = /"SELECT \* FROM.*\$.*\[.*\]"/
    condition:
        any of them
}

rule wordpress_xss_unescaped_output
{
    meta:
        description = "Detect reflected/stored XSS due to unescaped user input"
        category = "XSS"
    strings:
        $echo = /echo\s+\$_(GET|POST|REQUEST)\[.*\];/
        $shortcode = /\[.*=.*\$_(GET|POST|REQUEST)\[.*\]/
    condition:
        any of them
}

rule wordpress_auth_bypass_static_key
{
    meta:
        description = "Detect hardcoded static encryption keys (auth bypass)"
        category = "Authentication Bypass"
    strings:
        $key = /['"]?(enc|encrypt|key|secret)['"]?\s*=>\s*['"][a-f0-9]{16,}['"]/
    condition:
        $key
}

rule wordpress_arbitrary_file_delete
{
    meta:
        description = "Detect use of unlink() with user input"
        category = "Arbitrary File Deletion"
    strings:
        $unlink = /unlink\s*\(\s*\$_(GET|POST|REQUEST)\[.*\]/
    condition:
        $unlink
}

rule wordpress_file_upload_no_validation
{
    meta:
        description = "Detect vulnerable file upload (no MIME/type validation)"
        category = "File Upload"
    strings:
        $upload = /move_uploaded_file\s*\(.*\$_FILES/
        $no_check = /(?i)(\.php|\.js).*as\s*\.(jpg|png|gif)/
    condition:
        $upload and not $no_check
}

rule wordpress_rfi_lfi_includes
{
    meta:
        description = "Detect Remote or Local File Inclusion"
        category = "RFI/LFI"
    strings:
        $include = /include\s*\(\s*\$_(GET|POST|REQUEST)\[.*\]\s*\)/
    condition:
        $include
}

rule wordpress_missing_capability_check
{
    meta:
        description = "Detect missing current_user_can() in privileged actions"
        category = "Access Control"
    strings:
        $action = /(add|update|delete)_option\s*\(\s*.*\$_(GET|POST|REQUEST)\[.*\]/
        $no_capability = /(?i)current_user_can/
    condition:
        $action and not $no_capability
}

rule wordpress_direct_file_access
{
    meta:
        description = "Detect missing ABSPATH guard"
        category = "Direct File Access"
    strings:
        $no_abspath = /^<\?php(?!.*defined\s*\(\s*['"]ABSPATH['"]\s*\))/
    condition:
        $no_abspath
}

rule wordpress_rce_unserialize
{
    meta:
        description = "Detect unserialize() usage on user input"
        category = "RCE / Deserialization"
    strings:
        $rce = /unserialize\s*\(\s*\$_(GET|POST|REQUEST)\[.*\]\s*\)/
    condition:
        $rce
}

rule wordpress_idor_raw_access
{
    meta:
        description = "Detect insecure direct object reference (IDOR)"
        category = "IDOR"
    strings:
        $idor = /\$_(GET|POST|REQUEST)\['(user|post|order)_id'\]/
    condition:
        $idor
}
