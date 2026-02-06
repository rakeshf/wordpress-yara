/*******************************************************
 * wordpress-advanced-php-only-no-php_open.yar
 * Same security rules but WITHOUT $php_open helper string.
 * Scan only PHP files externally (recommended).
 *******************************************************/

rule wp_insecure_tls_disabled
{
    meta:
        description = "Insecure TLS verification disabled (sslverify/verify/curLOPT)"
        category = "TLS"
    strings:
        $s1 = /['"]sslverify['"]\s*=>\s*false/i
        $s2 = /['"]verify['"]\s*=>\s*false/i
        $s3 = /CURLOPT_SSL_VERIFYPEER\s*,\s*false/i
        $s4 = /CURLOPT_SSL_VERIFYHOST\s*,\s*(0|false)/i
    condition:
        filesize < 10240KB and any of ($s1,$s2,$s3,$s4)
}

rule wordpress_auth_bypass_static_key
{
    meta:
        description = "Detect hardcoded static encryption keys or secrets"
        category = "Authentication Bypass"
    strings:
        $s_key1 = /(['"]?(enc|encrypt|key|secret)['"]?)\s*(=>|:)\s*['"][a-f0-9]{16,}['"]/i
        $s_key2 = /(['"]?(CLIENT_SECRET|OAUTH_SECRET|CLIENT_KEY)['"]?)\s*(=>|:)\s*['"][^'"]{12,}['"]/i
    condition:
        filesize < 10MB and any of ($s_key1, $s_key2)
}

rule wp_state_missing_or_not_validated
{
    meta:
        description = "OAuth state parameter read, but no obvious server-side validation pattern"
        category = "OAuth/CSRF"
    strings:
        $s_state_read = /\$_(GET|REQUEST)\s*\[\s*['"]state['"]\s*\]/i
        $s_state_check_transient = /get_transient\s*\(\s*.*state.*\)/i
        $s_state_verify = /hash_equals\s*\(|===\s*\$state\s*\)/i
    condition:
        filesize < 10240KB and $s_state_read and not ( $s_state_check_transient or $s_state_verify )
}

rule wp_shell_exec_calls_or_obfuscation
{
    meta:
        description = "Potential command execution or obfuscation in PHP"
        category = "RCE/Malware"
    strings:
        $s_exec = /\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(/i
        $s_backtick = /`[^`]+`/s
        $s_obfus1 = /base64_decode\s*\(/i
        $s_obfus2 = /gzinflate\s*\(|gzuncompress\s*\(/i
        $s_obfus3 = /str_rot13\s*\(/i
    condition:
        filesize < 10240KB and ( $s_exec or $s_backtick or 2 of ($s_obfus1,$s_obfus2,$s_obfus3) )
}

rule wordpress_rce_unserialize
{
    meta:
        description = "Detect unserialize() usage on user input (possible deserialization RCE)"
        category = "RCE / Deserialization"
    strings:
        $s_rce1 = /unserialize\s*\(\s*\$_(GET|POST|REQUEST)\[.*\]\s*\)/i
        $s_rce2 = /unserialize\s*\(\s*base64_decode\s*\(\s*\$_(GET|POST|REQUEST)\[.*\]\s*\)\s*\)/i
    condition:
        filesize < 10MB and any of ($s_rce1, $s_rce2)
}


rule wordpress_file_upload_no_validation
{
    meta:
        description = "Detect potentially vulnerable file upload (no obvious MIME/type checks)"
        category = "File Upload"
    strings:
        $s_upload = /move_uploaded_file\s*\(.*\$_FILES/i
        $s_no_check = /(\.php|\.js).*(as|rename|move).*\.(jpg|png|gif)/i
    condition:
        filesize < 10MB and $s_upload and not $s_no_check
}

rule wordpress_rfi_lfi_includes
{
    meta:
        description = "Detect Remote or Local File Inclusion via unsanitized input in include/require"
        category = "RFI/LFI"
    strings:
        $s_include1 = /include(_once)?\s*\(\s*\$_(GET|POST|REQUEST)\[.*\]\s*\)/i
        $s_include2 = /require(_once)?\s*\(\s*\$_(GET|POST|REQUEST)\[.*\]\s*\)/i
    condition:
        filesize < 10MB and any of ($s_include1, $s_include2)
}


rule wp_open_redirect_param_usage
{
    meta:
        description = "wp_redirect with user-supplied target, no safe redirect"
        category = "Open Redirect"
    strings:
        $s_redirect = /wp_redirect\s*\(\s*\$_(GET|POST|REQUEST)\s*\[.*\]\s*\)/i
        $s_safe_redirect = /wp_safe_redirect\s*\(/i
    condition:
        filesize < 10240KB and $s_redirect and not $s_safe_redirect
}

rule wp_insecure_cookie_settings
{
    meta:
        description = "setcookie with tokens without Secure/HttpOnly/SameSite"
        category = "Privacy/Cookie"
    strings:
        $s_setcookie = /setcookie\s*\(\s*['"](access|id|oauth|jwt|token)[^'"]*['"]/i
        $s_secure = /secure\s*=>\s*true/i
        $s_httponly = /httponly\s*=>\s*true/i
        $s_samesite = /SameSite\s*=/i
    condition:
        filesize < 10240KB and $s_setcookie and not ($s_secure and $s_httponly and $s_samesite)
}

rule wordpress_missing_capability_check
{
    meta:
        description = "Detect privileged actions that reference user input without nearby capability checks"
        category = "Access Control"
    strings:
        $s_action = /(add|update|delete|insert|wp_insert|wp_update)\w*\s*\(.*\$_(GET|POST|REQUEST)\[.*\]\s*\)/i
        $u_direct = /update_(option|site_option|user_meta)\s*\(.*\$_(GET|POST|REQUEST|COOKIE)(\s*\[.*\])?\s*\)/i
        $u_indexed = /update_(option|site_option|user_meta)\s*\(.*\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\)/i
        $s_capability_check = /current_user_can\s*\(|current_user_can\s*\[/i
    condition:
        filesize < 10MB and ( any of ($u_direct, $u_indexed,$s_action) ) and not $s_capability_check
}

rule wp_debug_endpoints_exposed
{
    meta:
        description = "Debug/test endpoints or REST routes exposed"
        category = "Exposure"
    strings:
        $s_rest_init = /add_action\s*\(\s*['"]rest_api_init['"]/i
        $s_register = /register_rest_route\s*\(/i
        $s_debug_word = /['"]\b(debug|test|dev|probe|check|diag)\b['"]/i
    condition:
        filesize < 10240KB and $s_rest_init and $s_register and $s_debug_word
}


rule wp_obfuscated_malicious_patterns
{
    meta:
        description = "Heuristic for obfuscated/malicious code (multiple obfuscation functions or suspicious eval)"
        category = "Malicious/Obfuscated"
    strings:
        $s_eval = /\beval\s*\(/i
        $s_assert = /\bassert\s*\(/i
        $s_base64 = /base64_decode\s*\(/i
        $s_gzinflate = /gzinflate\s*\(|gzuncompress\s*\(/i
        $s_rot = /str_rot13\s*\(/i
    condition:
        filesize < 10240KB and ( $s_eval or $s_assert or 2 of ($s_base64,$s_gzinflate,$s_rot) )
}

rule OAuth_Email_Only_Acceptance
{
    meta:
        author = "Assistant"
        description = "Flags code that looks up or logs in users by email in an OAuth/token path — possible token acceptance based only on email."
        severity = "medium"
        
    strings:
        // typical patterns where code matches a user by email after receiving an id_token/access_token
        $tok_user_by_email1 = /get_user_by\s*\(\s*['"]email['"]\s*,/ ascii
        $tok_user_by_email2 = /wp_get_user_by\s*\(\s*['"]email['"]/ ascii
        // presence of access/id token variables
        $tok_var1 = /\$access_token\b/ ascii
        $tok_var2 = /\$id_token\b/ ascii
        // direct login calls by user ID or data
        $tok_login = /wp_set_auth_cookie\s*\(|wp_signon\s*\(|wp_set_current_user\s*\(/ ascii
    condition:
        ( any of ($tok_var*) and any of ($tok_user_by_email*) )
        or
        ( any of ($tok_var*) and $tok_login )
}

rule JWT_IDTOKEN_NO_SIG_VERIFICATION
{
    meta:
        author = "Assistant"
        description = "Flags functions that appear to parse id_tokens/JWTs by splitting/base64-decoding without obvious signature verification."
        severity = "high"
        
    strings:
        // function name used in your description
        $fn = /function\s+get_resource_owner_from_id_token\s*\(/ ascii
        // common unsafe parsing steps
        $explode_jwt = /explode\s*\(\s*['"]\.\s*['"]\s*,\s*\$id_token\s*\)/ ascii
        $explode_jwt_alt = /list\s*\(\s*\$header\s*,\s*\$payload\s*,\s*\$signature\s*\)\s*=\s*explode\s*\(/ ascii
        $base64_decode = /base64_decode\s*\(\s*\$payload|\$header/ ascii
        // known libraries but no verify call nearby: JSON decode used directly
        $json_decode = /json_decode\s*\(/ ascii
        // typical verify calls (we'll use absence in condition)
        $openssl_verify = /openssl_verify\s*\(/ ascii
        $jwt_decode_lib = /JWT::decode|FirebaseJWT::decode|\\\Firebase\\\JWT\\\JWT::decode|jwt_decode\s*\(/ ascii
    condition:
        // flagged if function exists and there are signs of manual JWT parsing OR library decode usage without openssl_verify presence
        $fn and ( $explode_jwt or $explode_jwt_alt or $base64_decode or $json_decode )
        or
        ( $jwt_decode_lib and not $openssl_verify )
}


rule wordpress_csrf_missing_nonce_check
{
    meta:
        description = "Detect potential missing or weak CSRF protection"
        category = "CSRF"
    strings:
        $s_input_pattern = /\$_(POST|GET|REQUEST)\[.*\].*\{.*(update|delete|create).*\}/i
        $s_nonce_pattern = /check_admin_referer|check_ajax_referer|wp_verify_nonce/i
    condition:
        filesize < 10MB and $s_input_pattern and not $s_nonce_pattern
}

rule wordpress_sql_injection_unsanitized_input
{
    meta:
        description = "Detect possible SQL injection via unsanitized user input"
        category = "SQL Injection"
    strings:
        $s_query = /SELECT\b.*\$_(GET|POST|REQUEST)/i
        $s_unsafe = /SELECT\s+\*\s+FROM.*\$_(GET|POST|REQUEST)/i
    condition:
        filesize < 10MB and any of ($s_query, $s_unsafe)
}

rule wp_ssrf_url_param
{
    meta:
        description = "Possible SSRF: remote fetch called with user-controlled URL parameter"
        category = "SSRF"
    strings:
        $s_remote = /wp_remote_(get|post|request)\s*\(.*\$_(GET|POST|REQUEST|COOKIE)/i
        $s_file_get = /file_get_contents\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i
        $s_curl_init = /curl_init\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i
    condition:
        filesize < 10240KB and ($s_remote or $s_file_get or $s_curl_init)
}

rule wordpress_idor_raw_access
{
    meta:
        description = "Detect insecure direct object reference (IDOR) style usage"
        category = "IDOR"
    strings:
        $s_idor1 = /\$_(GET|POST|REQUEST)\['?(user|post|order|item|product)_id'?\]/i
        $s_idor2 = /get_user_by\s*\(|get_post\s*\(|get_post_meta\s*\(/i
    condition:
        filesize < 10MB and any of ($s_idor1, $s_idor2)
}

rule wp_insecure_http_geoapi
{
    meta:
        description = "Uses http:// for geolocation/external IP APIs"
        category = "Insecure HTTP"
    strings:
        $s_http_call = /file_get_contents\s*\(\s*['"]http:\/\//i
        $s_wp_remote = /wp_remote_(get|post|request)\s*\(.*['"]http:\/\//i
    condition:
        filesize < 10240KB and ($s_http_call or $s_wp_remote)
}


rule wordpress_xss_unescaped_output
{
    meta:
        description = "Detect reflected/stored XSS due to unescaped user input"
        category = "XSS"
    strings:
        $s_echo = /echo\s+\$_(GET|POST|REQUEST)\[.*\]\s*;?/i
        $s_shortcode = /\[.*=.*\$_(GET|POST|REQUEST)\[.*\]\]/i
    condition:
        filesize < 10MB and any of ($s_echo, $s_shortcode)
}

rule WP_DB_Credentials_In_Config
{
    meta:
        description = "Detect hard-coded DB credentials in wp-config.php"
        severity = "high"
        author = "ChatGPT"

    strings:
        // MySQL constants in wp-config.php
        $name = /define\s*\(\s*['"]DB_NAME['"]\s*,\s*['"][^'"]+['"]\s*\)/
        $user = /define\s*\(\s*['"]DB_USER['"]\s*,\s*['"][^'"]+['"]\s*\)/
        $pass = /define\s*\(\s*['"]DB_PASSWORD['"]\s*,\s*['"][^'"]*['"]\s*\)/
        $host = /define\s*\(\s*['"]DB_HOST['"]\s*,\s*['"][^'"]+['"]\s*\)/
    condition:
        all of them
}

/* Weak password generator detection: uses rand()/mt_rand() or predictable tokens without salt */
rule wp_weak_password_generation
{
    meta:
        description = "Weak password generation: mt_rand()/rand() or unhashed default password"
        category = "Weak password"
    strings:
        $s_rand = /\b(mt_rand|rand|uniqid)\s*\(/i
        $s_wp_rand = /wp_generate_password\s*\(.*(false|8)/i
    condition:
        filesize < 10240KB and ($s_rand or $s_wp_rand)
}

/* Missing rate-limiting: checks for login actions without throttle/captcha or rate limit function */
rule wp_missing_rate_limiting
{
    meta:
        description = "Potential missing rate limiting on login-like actions"
        category = "Rate limit"
    strings:
        $s_login_action = /(wp_login|wp_authenticate|wp_signon|authenticate)\s*\(/i
        $s_rate_limit = /(limit|throttle|rate_limit|login_attempts|reCAPTCHA|captcha)/i
    condition:
        filesize < 10240KB and $s_login_action and not $s_rate_limit
}

rule wp_insecure_ip_and_http_usage
{
    meta:
        description = "Detects trust of spoofable IP headers and insecure HTTP usage"
        category = "IP Spoofing / Insecure HTTP"

    strings:
        /* Spoofable headers */
        $s_xff = /\$_SERVER\s*\[\s*['"]HTTP_X_FORWARDED_FOR['"]\s*\]/i
        $s_xreal = /\$_SERVER\s*\[\s*['"]HTTP_X_REAL_IP['"]\s*\]/i
        $s_client_ip = /\$_SERVER\s*\[\s*['"]HTTP_CLIENT_IP['"]\s*\]/i
        $s_forwarded = /\$_SERVER\s*\[\s*['"]HTTP_FORWARDED['"]\s*\]/i

        /* Missing IP validation */
        $s_validate = /filter_var\s*\(.*FILTER_VALIDATE_IP/i

        /* Insecure HTTP calls */
        $s_http_call1 = /file_get_contents\s*\(\s*['"]http:\/\//i
        $s_http_call2 = /wp_remote_(get|post|request)\s*\(.*['"]http:\/\//i
        $s_http_call3 = /curl_init\s*\(\s*['"]http:\/\//i

    condition:
        filesize < 10240KB and
        (
            /* IP spoofing: spoofable header used without validation */
            (
                ($s_xff or $s_xreal or $s_client_ip or $s_forwarded)
                and not $s_validate
            )
            or
            /* insecure HTTP usage */
            ($s_http_call1 or $s_http_call2 or $s_http_call3)
        )
}

/* Dependency vulnerabilities detection is outside YARA: detect composer.json/npm package files */
rule wp_dependency_files_present
{
    meta:
        description = "Detect presence of composer.json/package.json (review with SCA tools)"
        category = "Dependency"
    strings:
        $s_comp = /"require"\s*:/i
        $s_pkg = /"dependencies"\s*:/i
    condition:
        filesize < 10240KB and ( $s_comp or $s_pkg )
}


/* Path traversal hint: fopen/require with ../ and user input */
rule wp_path_traversal_hint
{
    meta:
        description = "Path traversal: fopen/include using ../ and user input"
        category = "Path traversal"
    strings:
        $s_trav = /(fopen|include|require)\s*\(.*\.\.\/.*\$_(GET|POST|REQUEST|COOKIE)/i
    condition:
        filesize < 10240KB and $s_trav
}

rule wordpress_arbitrary_file_delete
{
    meta:
        description = "Detect use of unlink() with potential user input"
        category = "Arbitrary File Deletion"
    strings:
        $s_unlink = /unlink\s*\(\s*\$_(GET|POST|REQUEST)\[.*\]\s*\)/i
        $s_unlink_concat = /unlink\s*\(.*\.\s*\$_(GET|POST|REQUEST)\[.*\]\s*\)/i
    condition:
        filesize < 10MB and any of ($s_unlink, $s_unlink_concat)
}


rule js_vulnerable_eval
{
    meta:
        description = "Detects use of eval() in JavaScript"
        severity = "high"
    strings:
        $eval = /eval\s*\(.*\);/i
    condition:
        $eval
}

/*******************************************************
 * Detect OAuth / OIDC flows missing state protection
 *******************************************************/

rule OAuth_Missing_State_Parameter
{
    meta:
        author      = "Assistant"
        description = "OAuth/OIDC authorization URL without state parameter (CSRF risk)"
        severity    = "high"
        date        = "2025-11-28"
        category    = "OAuth"

    strings:
        // Typical OAuth/OIDC authorize endpoints in code
        $s_auth_url_1 = /https?:\/\/[^\s'"]*(authorize|oauth\/auth|oauth2\/auth)[^\s'"]*/ nocase

        // Simpler regex: authorize? ... response_type=code ... client_id=
        $s_auth_url_2 = /authorize\?[^'"]*response_type=code[^'"]*client_id=[^'"]*/ nocase

        // Generic patterns for building authorize URLs (including WP style)
        $s_wp_add_query_arg = /add_query_arg\s*\(/ nocase
        $s_response_type    = "response_type=code"
        $s_client_id        = "client_id="

        // Any use of state= anywhere in file
        $s_state_param      = "state="

    condition:
        filesize < 2MB and
        (
            $s_auth_url_1 or
            $s_auth_url_2 or
            ($s_wp_add_query_arg and $s_response_type and $s_client_id)
        )
        and not $s_state_param
}


/*******************************************************
 * OAuth: missing state validation on callback
 *******************************************************/

rule OAuth_Missing_State_Validation
{
    meta:
        author      = "Assistant"
        description = "OAuth/OIDC callback or token handling without state validation"
        severity    = "high"
        date        = "2025-11-28"
        category    = "OAuth"

    strings:
        // Common OAuth callback / token-exchange indicators
        $s_callback_path_1  = /redirect_uri|callback_url|oauth_callback/ nocase
        $s_token_exchange_1 = /grant_type=authorization_code/ nocase
        $s_token_exchange_2 = /code_verifier|code=/ nocase
        $s_id_token         = "id_token"
        $s_access_token     = "access_token"

        // Typical PHP / WP superglobals for reading request input
        $s_superglobal      = /\$_(GET|POST|REQUEST)\s*\[/ nocase

        // Explicit use of state from request (what we EXPECT to see)
        $s_state_from_req   = /\$_(GET|POST|REQUEST)\s*\[\s*['"]state['"]\s*\]/ nocase

    condition:
        filesize < 2MB and
        (
            $s_token_exchange_1 or
            $s_token_exchange_2 or
            $s_id_token or
            $s_access_token or
            $s_callback_path_1
        )
        and $s_superglobal and
        not $s_state_from_req
}


/*******************************************************
 * Token leakage in URLs (redirects, headers, logs)
 *******************************************************/

rule OAuth_Token_Leakage_In_URL
{
    meta:
        author      = "Assistant"
        description = "Possible token leakage via URL (redirect or header/log)"
        category    = "OAuth"
        severity    = "high"
        date        = "2025-11-28"

    strings:
        // Token-like query parameters
        $qs_access_token  = "access_token="
        $qs_id_token      = "id_token="
        $qs_token_generic = "token="
        $qs_oauth_token   = "oauth_token="
        $qs_req_token     = "request_token="

        // Redirects / headers commonly used with URLs
        $redir_wp         = "wp_redirect("
        $redir_header     = "header("
        $redir_location   = "Location:"

        // Logging / debug output
        $log_error        = "error_log("
        $log_print        = "print_r("
        $log_var_dump     = "var_dump("
        $log_echo         = "echo "
        $log_console      = "console.log("

    condition:
        filesize < 2MB and
        any of ($qs_*) and
        (any of ($redir_*) or any of ($log_*))
}


/*******************************************************
 * Direct use of request token / user in auth logic
 *******************************************************/

rule OAuth_Direct_Request_Token_Use
{
    meta:
        author      = "Assistant"
        description = "Direct use of access/id/request token or user identity from request variables in auth/user APIs"
        category    = "OAuth"
        severity    = "high"
        date        = "2025-11-28"

    strings:
        // Reading token-like values from request
        $req_token_1 = /\$_(GET|POST|REQUEST)\s*\[\s*['"]access_token['"]\s*\]/ nocase
        $req_token_2 = /\$_(GET|POST|REQUEST)\s*\[\s*['"]id_token['"]\s*\]/ nocase
        $req_token_3 = /\$_(GET|POST|REQUEST)\s*\[\s*['"](oauth_token|request_token|token)['"]\s*\]/ nocase

        // Reading user identity directly from request
        $req_user_1  = /\$_(GET|POST|REQUEST)\s*\[\s*['"](user|username|login)['"]\s*\]/ nocase
        $req_user_2  = /\$_(GET|POST|REQUEST)\s*\[\s*['"](email|user_email)['"]\s*\]/ nocase

        // Sensitive user / auth APIs
        $user_api_1  = "wp_signon("
        $user_api_2  = "wp_set_auth_cookie("
        $user_api_3  = "get_user_by("
        $user_api_4  = "wp_create_user("
        $user_api_5  = "wp_insert_user("
        $user_api_6  = "wp_update_user("
        $user_api_7  = "update_user_meta("
        $user_api_8  = "wp_set_current_user("

    condition:
        filesize < 2MB and
        (any of ($req_token_*) or any of ($req_user_*)) and
        any of ($user_api_*)
}


/*******************************************************
 * Token logged / dumped (debug leakage)
 *******************************************************/

rule OAuth_Token_Logged_Or_Dumped
{
    meta:
        author      = "Assistant"
        description = "Tokens possibly logged or dumped (debug leakage)"
        category    = "OAuth"
        severity    = "medium"
        date        = "2025-11-28"

    strings:
        // Token names in logs
        $log_token_name_1 = "access_token"
        $log_token_name_2 = "id_token"
        $log_token_name_3 = "refresh_token"
        $log_token_name_4 = "oauth_token"

        // Logging and dumping functions
        $log_error        = "error_log("
        $log_print        = "print_r("
        $log_var_dump     = "var_dump("
        $log_var_export   = "var_export("
        $log_echo         = "echo "
        $log_console      = "console.log("

    condition:
        filesize < 2MB and
        any of ($log_token_name_*) and
        any of ($log_*)
}




/*******************************************************
 * Additional Open Redirect detection rules
 * (append to your existing YARA rules file)
 *******************************************************/

rule wp_open_redirect_header_location
{
    meta:
        author = "Assistant"
        description = "Detect header('Location: ...') with user-controlled input (possible open redirect)"
        category = "Open Redirect"
        severity = "high"
        date = "2025-12-03"

    strings:
        $s_header_loc = /header\s*\(\s*['"]Location\s*:\s*/ nocase
        $s_superglobal = /\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/ nocase
        // direct concatenation or interpolation
        $s_concat = /\.\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/ nocase
        $s_interpolate = /\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[[^\]]+\]\s*\)/ nocase

    condition:
        filesize < 2048KB and $s_header_loc and $s_superglobal and ( $s_concat or $s_interpolate )
}

rule wp_open_redirect_wp_redirect_more
{
    meta:
        author = "Assistant"
        description = "wp_redirect / wp_safe_redirect usage where user-supplied redirect param appears without validation"
        category = "Open Redirect"
        severity = "high"
        date = "2025-12-03"

    strings:
        // Redirect functions
        $s_wp_redirect = /wp_redirect\s*\(/ nocase
        $s_wp_safe = /wp_safe_redirect\s*\(/ nocase

        // Common redirect parameters
        $s_redirect_to = /redirect_to\s*=/ nocase
        $s_param_redirect_to = /['"]redirect_to['"]\s*,/ nocase
        $s_next_param = /['"]next['"]\s*,/ nocase

        // User-controlled redirect parameter usage
        $s_superglobal = /\$_(GET|POST|REQUEST)\s*\[\s*['"](redirect_to|next|target|url|return_to|r|redirect)['"]\s*\]/ nocase

    condition:
        filesize < 2048KB and
        $s_wp_redirect and
        (
            $s_superglobal or
            $s_redirect_to or
            $s_param_redirect_to or
            $s_next_param
        )
        and not $s_wp_safe
}

rule wp_open_redirect_location_header_concat
{
    meta:
        author = "Assistant"
        description = "Detects 'Location:' header built with user input or query string directly (header or echo Location:) — heuristic"
        category = "Open Redirect"
        severity = "high"
        date = "2025-12-03"

    strings:
        $s_header = /header\s*\(\s*['"]Location\s*:/ nocase
        $s_echo_location = /echo\s+['"]Location\s*:/ nocase
        $s_qs_token = /\?\w+=\s*\$_(GET|REQUEST|POST)\s*\[/ nocase
        $s_superglobal = /\$_(GET|POST|REQUEST)\s*\[/ nocase

    condition:
        filesize < 2048KB and
        ( $s_header or $s_echo_location ) and
        ( $s_superglobal or $s_qs_token )
}

rule meta_refresh_redirect
{
    meta:
        author = "Assistant"
        description = "Meta refresh redirect using user-supplied URL (possible open redirect)"
        category = "Open Redirect"
        severity = "medium"
        date = "2025-12-03"

    strings:
        $s_meta = /<meta\s+http-equiv\s*=\s*['"]refresh['"][^>]*content\s*=\s*['"][^'"]*url\s*=\s*/ nocase ascii
        $s_superglobal_in_html = /\$_(GET|POST|REQUEST)\s*\[/ nocase

    condition:
        filesize < 2048KB and $s_meta and $s_superglobal_in_html
}

rule wp_open_redirect_allowlist_missing
{
    meta:
        author = "Assistant"
        description = "Heuristic: presence of redirect parameter without usage of allowlist or validation helper (e.g., wp_validate_redirect, esc_url_raw, filter_var)"
        category = "Open Redirect"
        severity = "medium"
        date = "2025-12-03"

    strings:
        $s_param = /\$_(GET|POST|REQUEST)\s*\[\s*['"](redirect_to|target|url|next|return_to)['"]\s*\]/ nocase
        $s_validate = /wp_validate_redirect\s*\(|esc_url_raw\s*\(|filter_var\s*\(.*FILTER_VALIDATE_URL/i
    condition:
        filesize < 2048KB and $s_param and not $s_validate
}

rule wordpress_direct_file_access
{
    meta:
        description = "Detect possible missing ABSPATH guard (direct file access)"
        category = "Direct File Access"
    strings:
        $s_php_open = /<\?php/                            /* PHP opening tag */
        $s_defined_abspath = /defined\s*\(\s*['"]ABSPATH['"]\s*\)/i
    condition:
        filesize < 10MB and $s_php_open and not $s_defined_abspath
}

rule wp_auth_bypass_user_lookup_from_input
{
    meta:
        description = "Detects authentication bypass via user-controlled identifier (id/email/login)"
        severity = "critical"
        category = "authentication"
        cwe = "CWE-287"
        confidence = "very high"
        platform = "wordpress"

    strings:
        /* User input sources */
        $input_post = /\$_POST\s*\[\s*['"].*(id|user_id|userid|email|mail|login|username).*['"]\s*\]/i
        $input_get  = /\$_GET\s*\[\s*['"].*(id|user_id|userid|email|mail|login|username).*['"]\s*\]/i
        $input_req  = /\$_REQUEST\s*\[\s*['"].*(id|user_id|userid|email|mail|login|username).*['"]\s*\]/i

        /* User lookup */
        $get_user_id    = /get_user_by\s*\(\s*['"]id['"]\s*,/i
        $get_user_email = /get_user_by\s*\(\s*['"]email['"]\s*,/i
        $get_user_login = /get_user_by\s*\(\s*['"]login['"]\s*,/i

        /* Auth/session manipulation */
        $set_user = /wp_set_current_user\s*\(/i
        $set_auth = /wp_set_auth_cookie\s*\(/i

        /* Legitimate checks (negative signals) */
        $cap_check = "current_user_can"
        $nonce     = "wp_verify_nonce"
        $logged_in = "is_user_logged_in"

    condition:
        (
            any of ($input_post, $input_get, $input_req)
            and any of ($get_user_id, $get_user_email, $get_user_login)
            and any of ($set_user, $set_auth)
        )
        and not any of ($cap_check, $nonce, $logged_in)
}


rule php_plaintext_password_storage
{
    meta:
        description = "Detects plaintext password storage or comparison in PHP"
        severity = "high"
        category = "authentication"
        cwe = "CWE-256"
        confidence = "medium"

    strings:
        /* Password variables */
        $pwd_var1 = /\$password\s*=/ nocase
        $pwd_var2 = /\$pass\s*=/ nocase
        $pwd_var3 = /\$pwd\s*=/ nocase

        /* DB write patterns */
        $db_insert1 = /INSERT\s+INTO\s+.*password/i
        $db_insert2 = /UPDATE\s+.*SET\s+password/i
        $wpdb_write = /\$wpdb->(insert|update)\s*\(/i

        /* Direct comparison */
        $compare1 = /\$password\s*==/ nocase
        $compare2 = /\$password\s*===/ nocase

        /* Absence indicators (negative heuristics) */
        $hash_safe1 = "password_hash"
        $hash_safe2 = "wp_hash_password"
        $hash_safe3 = "password_verify"

    condition:
        (
            any of ($pwd_var*)
            and any of ($db_insert*, $wpdb_write, $compare*)
        )
        and not any of ($hash_safe*)
}

