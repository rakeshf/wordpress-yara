rule OAuth_Missing_State_Parameter
{
    meta:
        description = "OAuth authorize URL without state parameter"
        category = "OAuth"
        severity = "high"
    strings:
        $auth = /authorize\?[^'"]*response_type=code[^'"]*client_id=/i
        $state = "state="
    condition:
        filesize < 2MB and $auth and not $state
}

rule OAuth_Missing_State_Validation
{
    meta:
        description = "OAuth callback without state validation"
        category = "OAuth"
        severity = "high"
    strings:
        $callback = /(callback|redirect_uri|oauth_callback)/i
        $state = /\$_(GET|POST|REQUEST)\[['"]state['"]\]/i
    condition:
        filesize < 2MB and $callback and not $state
}

rule OAuth_Email_Only_Acceptance
{
    meta:
        description = "OAuth login using email only"
        category = "OAuth"
    strings:
        $email = /get_user_by\s*\(\s*['"]email['"]\s*,/i
        $token = /(access_token|id_token)/i
    condition:
        filesize < 10MB and $email and $token
}

rule OAuth_Token_Leakage_In_URL
{
    meta:
        description = "OAuth token leaked in URL or logs"
        category = "OAuth"
    strings:
        $token = /(access_token=|id_token=|refresh_token=)/i
        $sink  = /(wp_redirect|header\(|error_log|print_r|var_dump|echo )/i
    condition:
        filesize < 2MB and $token and $sink
}
