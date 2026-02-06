rule api_jwt_algorithm_none_or_weak_validation
{
    meta:
        description = "JWT alg:none or weak validation"
        category = "API_JWT"
    strings:
        $alg1 = "\"alg\":\"none\""
        $alg2 = "alg: 'none'"
        $jwt  = /(jwt\.decode|jwt\.verify|JWT::decode|jsonwebtoken)/i
    condition:
        filesize < 10MB and any of ($alg*) and $jwt
}

rule api_jwt_decoded_without_verification
{
    meta:
        description = "JWT decoded without verification"
        category = "API_JWT"
    strings:
        $decode = /(jwt\.decode|JWT::decode)/i
        $auth   = /(Authorization|Bearer )/i
        $bad    = /(verify:false|alg:none)/i
    condition:
        filesize < 10MB and $decode and $auth and not $bad
}

rule api_endpoint_missing_authentication
{
    meta:
        description = "API endpoint without auth checks"
        category = "API_AUTH"
    strings:
        $route = /(register_rest_route|router\.get|router\.post|app\.get)/i
        $auth  = /(Authorization|permission_callback|current_user_can|authMiddleware)/i
    condition:
        filesize < 10MB and $route and not $auth
}

rule microservice_trust_header_abuse
{
    meta:
        description = "Trusting spoofable internal headers"
        category = "Microservices"
    strings:
        $hdr = /(X-Forwarded-For|X-Real-IP|X-Internal)/i
        $cmp = /(==|if)/i
    condition:
        filesize < 10MB and $hdr and $cmp
}
