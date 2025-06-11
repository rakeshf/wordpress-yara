rule Laravel_Obfuscated_PHP
{
    meta:
        description = "Detects obfuscated PHP code common in Laravel web shells"
        severity = "high"
        author = "ChatGPT"

    strings:
        $eval = /eval\s*\(/
        $base64 = /base64_decode\s*\(/
        $gz = /gzinflate\s*\(/
        $rot13 = /str_rot13\s*\(/
        $strrev = /strrev\s*\(/
        $preg_replace_eval = /preg_replace\s*\(\s*['"][^'"]*\/e['"]/

    condition:
        uint16(0) == 0x3c3f and 1 of ($eval, $base64, $gz, $rot13, $strrev, $preg_replace_eval)
}
rule Laravel_WebShell_Common
{
    meta:
        description = "Detects common PHP web shell keywords"
        severity = "critical"
        author = "ChatGPT"

    strings:
        $s1 = "b374k"
        $s2 = "r57shell"
        $s3 = "php shell"
        $s4 = "Mini Shell"
        $s5 = "FilesMan"
        $s6 = /shell_exec\s*\(/
        $s7 = /system\s*\(/
        $s8 = /passthru\s*\(/
        $s9 = /popen\s*\(/
        $s10 = /proc_open\s*\(/

    condition:
        uint16(0) == 0x3c3f and 2 of ($s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10)
}
rule Laravel_Backdoor_Indicators
{
    meta:
        description = "Detects suspicious Laravel usage of system-level commands"
        author = "ChatGPT"
        severity = "high"

    strings:
        $danger1 = "Illuminate\\Support\\Facades\\Artisan::call("
        $danger2 = /Route::get\s*\(\s*['"][^'"]*['"]\s*,\s*function\s*\(\)\s*\{.*(eval|system|exec)/s
        $danger3 = /Artisan::call\s*\(\s*['"]migrate['"]/s
        $danger4 = /DB::select\s*\(.*(UNION|SELECT|FROM|WHERE)/is
        $danger5 = /file_put_contents\s*\(.*base64_decode/

    condition:
        any of ($danger*)
}
rule Laravel_Storage_Backdoor
{
    meta:
        description = "Detects PHP code placed in Laravel storage/public folders"
        author = "ChatGPT"
        severity = "critical"

    strings:
        $php_tag = "<?php"
        $eval = "eval("
        $shell = "cmd.php"

    condition:
        (filename matches /.*(storage|public).*\.php$/i) and $php_tag and any of ($eval, $shell)
}
