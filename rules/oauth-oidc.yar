/* =========================================================
   OAuth / OIDC Vulnerability Detection Rules
   ========================================================= */


/* ---------------------------------------------------------
   OAuth State Parameter Issues
   --------------------------------------------------------- */

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



/* ---------------------------------------------------------
   OAuth Account Linking Issues
   --------------------------------------------------------- */

rule OAuth_Email_Only_Acceptance
{
    meta:
        description = "OAuth login using email only"
        category = "OAuth"
        severity = "high"

    strings:
        $email = /get_user_by\s*\(\s*['"]email['"]\s*,/i
        $token = /(access_token|id_token)/i

    condition:
        filesize < 10MB and $email and $token
}



/* ---------------------------------------------------------
   Token Leakage
   --------------------------------------------------------- */

rule OAuth_Token_Leakage_In_URL
{
    meta:
        description = "OAuth token leaked in URL or logs"
        category = "OAuth"
        severity = "high"

    strings:
        $token = /(access_token=|id_token=|refresh_token=)/i
        $sink  = /(wp_redirect|header\(|error_log|print_r|var_dump|echo )/i

    condition:
        filesize < 2MB and $token and $sink
}



/* ---------------------------------------------------------
   PKCE Issues
   --------------------------------------------------------- */

rule OAuth_Missing_PKCE
{
    meta:
        description = "OAuth authorization request without PKCE"
        category = "OAuth"
        severity = "high"

    strings:
        $auth = /authorize\?[^'"]*response_type=code/i
        $pkce1 = "code_challenge="
        $pkce2 = "code_verifier="

    condition:
        filesize < 2MB and $auth and not any of ($pkce*)
}



/* ---------------------------------------------------------
   Redirect URI Vulnerabilities
   --------------------------------------------------------- */

rule OAuth_Open_Redirect_URI
{
    meta:
        description = "Dynamic redirect_uri in OAuth flow"
        category = "OAuth"
        severity = "high"

    strings:
        $redirect1 = /redirect_uri=\$_(GET|POST|REQUEST)/i
        $redirect2 = /redirect_uri\s*=\s*\$_(GET|POST|REQUEST)/i

    condition:
        filesize < 2MB and any of ($redirect*)
}



/* ---------------------------------------------------------
   Token Storage Issues
   --------------------------------------------------------- */

rule OAuth_Token_Stored_Insecurely
{
    meta:
        description = "OAuth access token stored insecurely"
        category = "OAuth"
        severity = "medium"

    strings:
        $token = /(access_token|refresh_token)/i
        $store1 = /(update_option|set_transient|session\[|INSERT INTO)/i

    condition:
        filesize < 5MB and $token and $store1
}



/* ---------------------------------------------------------
   Client Secret Exposure
   --------------------------------------------------------- */

rule OAuth_Client_Secret_Exposure
{
    meta:
        description = "OAuth client secret hardcoded"
        category = "OAuth"
        severity = "high"

    strings:
        $secret1 = /client_secret\s*=\s*['"][A-Za-z0-9\-_]{20,}['"]/i
        $secret2 = /"client_secret"\s*:\s*"[^"]+"/i

    condition:
        filesize < 2MB and any of ($secret*)
}



/* ---------------------------------------------------------
   OAuth Flow Issues
   --------------------------------------------------------- */

rule OAuth_Implicit_Flow_Usage
{
    meta:
        description = "OAuth implicit flow usage"
        category = "OAuth"
        severity = "medium"

    strings:
        $implicit = /response_type=token/i

    condition:
        filesize < 2MB and $implicit
}



rule OAuth_Code_Leak_In_URL
{
    meta:
        description = "OAuth authorization code exposed in logs"
        category = "OAuth"
        severity = "medium"

    strings:
        $code = /(code=)/i
        $sink = /(echo|print_r|var_dump|error_log)/i

    condition:
        filesize < 2MB and $code and $sink
}



/* ---------------------------------------------------------
   OIDC Specific Vulnerabilities
   --------------------------------------------------------- */

rule OIDC_Missing_Nonce
{
    meta:
        description = "OIDC request missing nonce parameter"
        category = "OIDC"
        severity = "high"

    strings:
        $auth = /authorize\?[^'"]*openid/i
        $nonce = "nonce="

    condition:
        filesize < 2MB and $auth and not $nonce
}



rule OIDC_Missing_IDToken_Verification
{
    meta:
        description = "OIDC ID Token accepted without validation"
        category = "OIDC"
        severity = "critical"

    strings:
        $idtoken = "id_token"
        $decode = /(jwt_decode|decode\()/i
        $verify = /(verify|validate).*id_token/i

    condition:
        filesize < 2MB and $idtoken and $decode and not $verify
}



/* ---------------------------------------------------------
   Token Validation Issues
   --------------------------------------------------------- */

rule OAuth_Missing_Audience_Check
{
    meta:
        description = "OAuth token audience not validated"
        category = "OAuth"
        severity = "high"

    strings:
        $aud = /(audience|aud)/i
        $validate = /(validateAudience|verifyAudience)/i

    condition:
        filesize < 2MB and $aud and not $validate
}



/* ---------------------------------------------------------
   Transport Security
   --------------------------------------------------------- */

rule OAuth_Insecure_HTTP_Endpoint
{
    meta:
        description = "OAuth token endpoint using HTTP"
        category = "OAuth"
        severity = "critical"

    strings:
        $http = /http:\/\/[^'"]*\/token/i

    condition:
        filesize < 2MB and $http
}
