rule SAML_Missing_Signature_Validation
{
    meta:
        description = "Detects SAML implementations that parse assertions without validating signatures"
        author = "Security Research"
        severity = "high"
        vulnerability = "SAML Signature Validation Bypass"

    strings:
        $parse1 = "parseAssertion"
        $parse2 = "parseResponse"
        $parse3 = "getAssertion"
        $parse4 = "decodeSAMLResponse"

        $noverify1 = "skipSignatureValidation"
        $noverify2 = "disableSignatureValidation"
        $noverify3 = "validateSignature=false"
        $noverify4 = "verifySignature(false)"

    condition:
        any of ($parse*) and any of ($noverify*)
}



rule SAML_XML_Signature_Wrapping
{
    meta:
        description = "Detects potential XML Signature Wrapping vulnerabilities in SAML handling"
        author = "Security Research"
        severity = "critical"
        vulnerability = "XML Signature Wrapping (XSW)"

    strings:
        $xml1 = "<Assertion"
        $xml2 = "<Signature"
        $xml3 = "getElementsByTagName(\"Assertion\")"
        $xml4 = "getElementsByTagName(\"Signature\")"
        $xml5 = "document.getElementsByTagName"

        $bad1 = "assertions[0]"
        $bad2 = "signature[0]"
        $bad3 = "selectSingleNode(\"//Assertion\")"

    condition:
        any of ($xml*) and any of ($bad*)
}



rule SAML_Missing_Audience_Validation
{
    meta:
        description = "Detects SAML code that does not validate AudienceRestriction"
        author = "Security Research"
        severity = "high"
        vulnerability = "Improper Audience Validation"

    strings:
        $aud1 = "AudienceRestriction"
        $aud2 = "Audience"

        $missing1 = "skipAudienceValidation"
        $missing2 = "validateAudience=false"
        $missing3 = "disableAudienceCheck"

    condition:
        any of ($aud*) and any of ($missing*)
}



rule SAML_Missing_Issuer_Validation
{
    meta:
        description = "Detects SAML responses processed without validating the Issuer"
        author = "Security Research"
        severity = "high"
        vulnerability = "Improper Issuer Validation"

    strings:
        $issuer1 = "<Issuer>"
        $issuer2 = "getIssuer()"
        $issuer3 = "assertion.getIssuer"

        $skip1 = "skipIssuerValidation"
        $skip2 = "validateIssuer=false"
        $skip3 = "disableIssuerCheck"

    condition:
        any of ($issuer*) and any of ($skip*)
}



rule SAML_Unsigned_Assertion_Accepted
{
    meta:
        description = "Detects code that accepts unsigned SAML assertions"
        author = "Security Research"
        severity = "critical"
        vulnerability = "Unsigned Assertion Acceptance"

    strings:
        $unsigned1 = "allowUnsignedAssertions"
        $unsigned2 = "acceptUnsignedAssertion"
        $unsigned3 = "requireSignedAssertions=false"
        $unsigned4 = "validateAssertionSignature=false"

    condition:
        any of ($unsigned*)
}



rule SAML_Disabled_Certificate_Validation
{
    meta:
        description = "Detects disabled certificate verification in SAML implementations"
        author = "Security Research"
        severity = "high"
        vulnerability = "Certificate Validation Disabled"

    strings:
        $cert1 = "validateCertificate=false"
        $cert2 = "disableCertificateValidation"
        $cert3 = "trustAllCertificates"
        $cert4 = "setTrustAll(true)"

    condition:
        any of ($cert*)
}



rule SAML_RelayState_OpenRedirect
{
    meta:
        description = "Detects possible open redirect through RelayState parameter"
        author = "Security Research"
        severity = "medium"
        vulnerability = "RelayState Open Redirect"

    strings:
        $relay1 = "RelayState"
        $relay2 = "request.getParameter(\"RelayState\")"
        $relay3 = "redirect(request.getParameter(\"RelayState\"))"
        $relay4 = "response.sendRedirect(relayState)"

    condition:
        any of ($relay*)
}