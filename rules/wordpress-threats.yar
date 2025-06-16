rule WP_Malicious_Eval_Base64
{
    meta:
        description = "Detect eval(base64_decode(...)) pattern"
        category = "malware"
        severity = "high"
    strings:
        $a = "eval(base64_decode("
        $b = /eval\s*\(\s*base64_decode\s*\(\s*.{1,1000}\s*\)\s*\)/
    condition:
        any of them
}

rule WP_Shell_Patterns
{
    meta:
        description = "Common webshell PHP function patterns"
        severity = "high"
        category = "webshell"
    strings:
        $shell_exec = "shell_exec("
        $popen = "popen("
        $proc_open = "proc_open("
        $system = "system("
        $exec = "exec("
        $passthru = "passthru("
    condition:
        any of them
}

rule WP_Backdoor_Variables
{
    meta:
        description = "Suspicious use of $_POST or $_REQUEST with eval/exec"
        category = "backdoor"
        severity = "high"
    strings:
        $post = /eval\s*\(\s*\$_(POST|REQUEST)\[.{1,40}\]\s*\)/
        $get = /assert\s*\(\s*\$_(GET|POST)\[.{1,40}\]\s*\)/
    condition:
        any of them
}

rule WP_Obfuscated_Long_Strings
{
    meta:
        description = "Suspiciously long base64-like string"
        severity = "medium"
        category = "obfuscation"
    strings:
        $longstring = /[A-Za-z0-9+\/=]{300,600}/
    condition:
        $longstring
}

rule WP_Theme_Backdoor_Hidden_Admin
{
    meta:
        description = "Hidden admin user creation in themes"
        category = "backdoor"
        severity = "high"
    strings:
        $a = "wp_create_user"
        $b = "user_pass"
        $c = "add_user_to_blog"
        $d = "administrator"
    condition:
        all of them
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

rule WP_Unsanitized_SQL_Functions
{
    meta:
        description = "Detect direct use of mysql_query()/mysqli_query() without prepare"
        severity = "medium"
        author = "ChatGPT"

    strings:
        $mysql = /mysql_query\s*\(/
        $mysqli = /mysqli_query\s*\(.*\$.*\)/
    condition:
        any of ($mysql, $mysqli)
}

rule WP_SQL_Concat_From_Input
{
    meta:
        description = "Detect simple concatenation of $_GET/$_POST into SQL strings"
        severity = "high"
        author = "ChatGPT"

    strings:
        // look for quotes + dot + superglobal
        $in1 = /['"].*\.\s*\$_(GET|POST)\['[A-Za-z0-9_]+']\s*\.\s*['"]/
        $in2 = /\$_(GET|POST)\['[A-Za-z0-9_]+']\s*\.\s*["'].*["']/
    condition:
        any of ($in1, $in2)
}

rule WP_WPDB_Unprepared
{
    meta:
        description = "Detect use of $wpdb->query() or get_results() with concatenation"
        severity = "high"
        author = "ChatGPT"

    strings:
        $query = /\$wpdb->query\s*\(\s*['"].*\$.*['"]\s*\)/
        $results = /\$wpdb->get_results\s*\(\s*['"].*\$.*['"]\s*\)/
    condition:
        any of ($query, $results)
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

rule LFI_Pattern_PHP
{
    meta:
        description = "Detects possible LFI using user input in include/require"
        severity = "critical"
    strings:
        $include = /include\s*\(\s*\$_(GET|POST|REQUEST)/
        $require = /require\s*\(\s*\$_(GET|POST|REQUEST)/
        $inc_once = /include_once\s*\(\s*\$_(GET|POST|REQUEST)/
        $req_once = /require_once\s*\(\s*\$_(GET|POST|REQUEST)/
    condition:
        any of them
}