# 🛡️ WordPress YARA Ruleset

A comprehensive YARA ruleset for detecting malware, security vulnerabilities, and suspicious patterns in WordPress installations, plugins, and themes.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Rule Files & Coverage](#rule-files--coverage)
- [Security Rules by Category](#security-rules-by-category)
- [Contents](#-contents)
- [Installation](#-installation)
- [Usage](#-usage)
- [Scanning Strategies](#-scanning-strategies)
- [Rule Statistics](#-rule-statistics)
- [Contributing](#-contributing)

---

## Overview

This repository contains **100+ YARA rules** designed to detect:

✅ **OWASP Top 10 Vulnerabilities**
✅ **Authentication & Authorization Bypasses**
✅ **Obfuscated Malware & Webshells**
✅ **Supply Chain Attacks**
✅ **OAuth/OIDC/SAML Security Issues**
✅ **SQL Injection & RCE**
✅ **File Upload & Path Traversal**
✅ **API Security Issues**
✅ **Credential Exposure**

---

## Rule Files & Coverage

| File | Rules | Coverage |
|------|-------|----------|
| [`rules/wordpress-threats.yar`](rules/wordpress-threats.yar) | 12 | Webshells, RCE, malware patterns |
| [`rules/wordpress-owasp.yar`](rules/wordpress-owasp.yar) | 10 | OWASP Top 10 vulnerabilities |
| [`rules/wordpress-advance.yar`](rules/wordpress-advance.yar) | 9 | Advanced WordPress security |
| [`rules/owasp.yar`](rules/owasp.yar) | 35+ | Comprehensive OWASP coverage |
| [`rules/api-jwt.yar`](rules/api-jwt.yar) | 5 | JWT & API authentication |
| [`rules/oauth-oidc.yar`](rules/oauth-oidc.yar) | 20+ | OAuth/OIDC vulnerabilities |
| [`rules/saml.yar`](rules/saml.yar) | 7 | SAML security issues |
| [`rules/laravel-threats.yar`](rules/laravel-threats.yar) | 5 | Laravel-specific threats |
| [`rules/supply-chain-wordpress.yar`](rules/supply-chain-wordpress.yar) | 8 | Supply chain attacks |
| [`rules/user-sync-ad.yar`](rules/user-sync-ad.yar) | 10 | LDAP/AD security |
| **Total** | **~100+** | **Production Ready** |

---

## Security Rules by Category

### 🔐 **OWASP Top 10 Coverage**

#### SQL Injection (4 Rules)
- `wordpress_sql_injection_unsanitized_input` - SELECT with unfiltered $_GET/$_POST
- `PHP_Possible_SQL_Injection_String_Interpolation` - Variable interpolation in SQL
- `WP_SQL_Concat_From_Input` - Direct string concatenation in queries
- `WP_WPDB_Unprepared` - $wpdb->query() without prepared statements

#### Remote Code Execution (6 Rules)
- `wordpress_rce_unserialize` - unserialize() on user input
- `wp_shell_exec_calls_or_obfuscation` - system(), exec(), shell_exec() functions
- `WP_Shell_Patterns` - Common webshell PHP patterns
- `WP_Malicious_Eval_Base64` - eval(base64_decode(...))
- `api_jwt_algorithm_none_or_weak_validation` - JWT with alg:none
- `Laravel_Obfuscated_PHP` - Obfuscated PHP code in Laravel

#### Cross-Site Scripting (XSS) (3 Rules)
- `wordpress_xss_unescaped_output` - Unescaped user input in output
- `wp_open_redirect_header_location` - header('Location: ...') with user input
- `meta_refresh_redirect` - Meta refresh redirects with user input

#### Cross-Site Request Forgery (CSRF) (3 Rules)
- `wordpress_csrf_missing_nonce_check` - State-changing actions without nonce
- `wordpress_csrf_missing_nonce_verification` - Missing wp_verify_nonce()
- `wp_state_missing_or_not_validated` - OAuth state not validated

#### Broken Authentication (5 Rules)
- `wordpress_auth_bypass_static_key` - Hardcoded encryption keys
- `wordpress_missing_capability_check` - Missing current_user_can() checks
- `wp_auth_bypass_user_lookup_from_input` - User lookup from unsanitized input
- `wp_missing_rate_limiting` - No rate limiting on login
- `php_plaintext_password_storage` - Plaintext password comparison

#### Broken Access Control (3 Rules)
- `wordpress_idor_raw_access` - Insecure Direct Object References
- `microservice_trust_header_abuse` - Trusting spoofable headers
- `AD_Admin_Role_Mapping` - Unchecked AD group to admin mapping

#### Sensitive Data Exposure (6 Rules)
- `WP_DB_Credentials_In_Config` - Hardcoded database credentials
- `wp_insecure_tls_disabled` - SSL/TLS verification disabled
- `wp_insecure_cookie_settings` - Missing Secure/HttpOnly/SameSite
- `OAuth_Client_Secret_Exposure` - Hardcoded OAuth secrets
- `OAuth_Token_Leakage_In_URL` - Tokens in URLs/logs
- `wp_insecure_ip_and_http_usage` - Insecure HTTP + spoofable IP headers

#### XML External Entities (XXE) & Injection (2 Rules)
- `SAML_XML_Signature_Wrapping` - XML Signature Wrapping attacks
- `LDAP_Injection_Filter` - LDAP injection in filters

#### Using Components with Known Vulnerabilities (1 Rule)
- `wp_dependency_files_present` - Detect composer.json/package.json (review with SCA)

#### Insufficient Logging & Monitoring (2 Rules)
- `OAuth_Token_Logged_Or_Dumped` - Tokens in debug output
- `wp_debug_endpoints_exposed` - Debug endpoints exposed

---

### 🔑 **Authentication & Authorization**

- `wordpress_auth_bypass_static_key` - Hardcoded secrets
- `wordpress_missing_capability_check` - Missing permission checks
- `wp_auth_bypass_user_lookup_from_input` - Auth bypass via user input
- `php_plaintext_password_storage` - Plaintext password storage
- `wp_missing_rate_limiting` - Missing login rate limiting
- `AD_Admin_Role_Mapping` - Unsafe AD group mapping
- `IdP_Attribute_Trust` - Trusting IdP attributes blindly
- `OIDC_Missing_IDToken_Verification` - OIDC token not validated

---

### 📁 **File & Directory Security**

- `wordpress_file_upload_no_validation` - File upload without MIME validation
- `wordpress_rfi_lfi_includes` - Remote/Local File Inclusion
- `wp_path_traversal_hint` - Path traversal with ../ patterns
- `wordpress_arbitrary_file_delete` - unlink() with user input
- `wordpress_direct_file_access` - Missing ABSPATH guard
- `WP_Insecure_NonAbsolute_Include_Path` - Non-absolute include paths
- `Laravel_Storage_Backdoor` - PHP in storage/public folders
- `wp_supply_chain_remote_include` - Remote includes in plugins

---

### 🌐 **API & OAuth/OIDC Security**

#### JWT Issues (3 Rules)
- `api_jwt_algorithm_none_or_weak_validation` - JWT alg:none bypass
- `api_jwt_decoded_without_verification` - JWT not verified
- `JWT_IDTOKEN_NO_SIG_VERIFICATION` - ID Token signature not checked

#### OAuth Issues (12 Rules)
- `OAuth_Missing_State_Parameter` - No CSRF protection via state
- `OAuth_Missing_State_Validation` - State parameter not validated
- `OAuth_Email_Only_Acceptance` - User lookup by email only
- `OAuth_Token_Leakage_In_URL` - Token in URL/logs
- `OAuth_Missing_PKCE` - Missing PKCE protection
- `OAuth_Open_Redirect_URI` - Dynamic redirect_uri from input
- `OAuth_Token_Stored_Insecurely` - Tokens stored without encryption
- `OAuth_Client_Secret_Exposure` - Hardcoded client secrets
- `OAuth_Implicit_Flow_Usage` - Insecure implicit flow
- `OAuth_Code_Leak_In_URL` - Authorization code exposed
- `OAuth_Missing_Audience_Check` - Token audience not validated
- `OAuth_Insecure_HTTP_Endpoint` - HTTP for token endpoint

#### OIDC Issues (2 Rules)
- `OIDC_Missing_Nonce` - OIDC request missing nonce
- `OIDC_Missing_IDToken_Verification` - ID Token not validated

#### API Endpoints (1 Rule)
- `api_endpoint_missing_authentication` - REST endpoints without auth

---

### 🔐 **SAML & Identity Security**

#### SAML (7 Rules)
- `SAML_Missing_Signature_Validation` - SAML assertions not verified
- `SAML_XML_Signature_Wrapping` - XML Signature Wrapping attacks
- `SAML_Missing_Audience_Validation` - Missing AudienceRestriction check
- `SAML_Missing_Issuer_Validation` - Issuer not validated
- `SAML_Unsigned_Assertion_Accepted` - Unsigned assertions accepted
- `SAML_Disabled_Certificate_Validation` - Certificate verification disabled
- `SAML_RelayState_OpenRedirect` - RelayState open redirect

#### LDAP & Active Directory (8 Rules)
- `LDAP_Injection_Filter` - LDAP injection in filters
- `LDAP_Filter_User_Input` - LDAP filter from request parameters
- `AD_Auto_User_Creation` - Automatic user creation from AD
- `AD_Admin_Role_Mapping` - AD groups mapped to admin
- `IdP_Attribute_Trust` - Blindly trusting IdP attributes
- `Missing_Email_Domain_Validation` - Email domain not validated
- `AD_Password_Sync` - Password synced from AD
- `LDAP_Insecure_Connection` - LDAP without TLS

---

### 🚀 **Supply Chain & Plugin Security**

- `wp_supply_chain_remote_code_execution` - Remote code execution in updates
- `wp_supply_chain_obfuscated_payload_dropper` - Obfuscated malware delivery
- `wp_supply_chain_external_update_server` - Malicious update servers
- `wp_supply_chain_external_zip_install` - External ZIP extraction
- `wp_supply_chain_hidden_admin_creation` - Silent admin user creation
- `wp_supply_chain_vendor_folder_backdoor` - Backdoors in vendor/
- `wp_supply_chain_typosquatted_library` - Typosquatted libraries
- `wp_supply_chain_activation_time_execution` - Code in plugin activation hook
- `wp_supply_chain_remote_include` - Remote file inclusion in plugins

---

### 🐛 **Obfuscation & Malware**

- `wp_obfuscated_malicious_patterns` - Multiple obfuscation indicators
- `WP_Malicious_Eval_Base64` - eval(base64_decode())
- `WP_Obfuscated_Long_Strings` - Long base64 strings
- `WP_Theme_Backdoor_Hidden_Admin` - Hidden admin in themes
- `Laravel_WebShell_Common` - Common webshell keywords
- `Laravel_Backdoor_Indicators` - Laravel backdoor patterns
- `PHP_Uninitialized_Array_Used_In_Return` - Suspicious array usage

---

### 🔗 **Networking & Transport**

- `wp_insecure_tls_disabled` - SSL verification disabled
- `wp_ssrf_url_param` - Server-Side Request Forgery
- `wp_insecure_http_geoapi` - HTTP for geo/IP APIs
- `wp_insecure_ip_and_http_usage` - Spoofable IP headers
- `LDAP_Insecure_Connection` - LDAP without TLS
- `OAuth_Insecure_HTTP_Endpoint` - Token endpoint over HTTP

---

### 🔍 **Miscellaneous Security**

- `wordpress_dependency_files_present` - Dependency files (review with SCA)
- `wp_debug_endpoints_exposed` - Debug routes exposed
- `js_vulnerable_eval` - JavaScript eval() usage
- `WP_Unsanitized_SQL_Functions` - mysql_query() without prepare

---

## 📁 Contents

- `rules/` – Directory containing all YARA rule files
  - `wordpress-threats.yar` – Webshells, RCE, obfuscated code
  - `wordpress-owasp.yar` – OWASP Top 10 vulnerabilities
  - `wordpress-advance.yar` – Advanced WordPress security checks
  - `owasp.yar` – Comprehensive OWASP coverage
  - `api-jwt.yar` – JWT and API security
  - `oauth-oidc.yar` – OAuth/OIDC vulnerabilities
  - `saml.yar` – SAML security issues
  - `laravel-threats.yar` – Laravel-specific threats
  - `supply-chain-wordpress.yar` – Supply chain attacks
  - `user-sync-ad.yar` – LDAP/AD security
- `test-payloads/` – Test cases and example malicious patterns
- `yara_line_matcher.py` – Python automation script
- `README.md` – This file

---

## 🚀 Installation

### Linux
```bash
sudo apt install yara

# Install Python YARA bindings
pip install yara-python
```

### macOS
```bash
brew install yara

# Install Python YARA bindings
pip install yara-python
```

### Windows (PowerShell as Admin)
```powershell
choco install yara

# Install Python YARA bindings
pip install yara-python
```

---

## 📖 Usage

### Basic YARA Scan
```bash
# Scan a single file
yara rules/wordpress-threats.yar /path/to/wordpress/plugin.php

# Scan a directory
yara -r rules/wordpress-threats.yar /var/www/html/wp-content/
```

### Python Scanner (Recommended)
```bash
# Scan WordPress plugins with context
python yara_line_matcher.py rules/wordpress-threats.yar /var/www/html/wp-content/plugins --skip-folders node_modules,vendor,.git

# Scan all rule files
python yara_line_matcher.py rules/ /var/www/html/wp-content --skip-folders node_modules,vendor

# Save results to file
python yara_line_matcher.py rules/ /var/www/html > scan_results.txt
```

### Multiple Rule Files
```bash
# Combine all rules
yara -r rules/ /var/www/html/wp-content/
```

### Generate Report
```bash
# JSON output
yara -j rules/ /var/www/html/wp-content/ > report.json

# Show matches with line numbers
yara -s rules/owasp.yar /var/www/html/wp-content/
```

---

## 🔄 Scanning Strategies

### Phase 1: Critical Vulnerability Scan (5 min)
```bash
yara rules/owasp.yar /var/www/html/wp-content/
```
Focus: SQL Injection, RCE, Authentication Bypass

### Phase 2: Malware & Webshell Scan (10 min)
```bash
yara rules/wordpress-threats.yar /var/www/html/wp-content/
```
Focus: Webshells, Obfuscated code, Known malware patterns

### Phase 3: API & OAuth Security (5 min)
```bash
yara rules/api-jwt.yar rules/oauth-oidc.yar /var/www/html/wp-content/
```
Focus: Token leakage, Missing validation, Secret exposure

### Phase 4: Complete Audit (20 min)
```bash
yara -r rules/ /var/www/html/
```
Focus: All vulnerabilities + supply chain + SAML/LDAP

---

## 🔧 CI/CD Integration

### GitHub Actions
```yaml
name: WordPress Security Scan

on: [push, pull_request]

jobs:
  yara-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install YARA
        run: sudo apt install yara
      - name: Run Security Scan
        run: yara -r rules/ .
```

### Pre-commit Hook
```bash
#!/bin/bash
# .git/hooks/pre-commit

yara -r rules/ . && exit 0 || exit 1
```

---

## 📊 Rule Statistics

| Category | Rules | Severity |
|----------|-------|----------|
| OWASP Top 10 | 35+ | Critical/High |
| Authentication | 8 | High |
| File Operations | 8 | High/Medium |
| API/OAuth | 15+ | High/Critical |
| SAML/LDAP | 15+ | High/Critical |
| Supply Chain | 9 | Critical/High |
| Obfuscation | 7 | High/Medium |
| Database | 6 | High |
| Transport | 6 | High |
| **Total** | **~100+** | **Production Ready** |

---

## ⚠️ Important Notes

1. **False Positives**: Some rules may trigger on legitimate code patterns. Review findings manually.
2. **False Negatives**: New/obfuscated malware may not be detected. Use as part of defense-in-depth.
3. **Regular Updates**: Keep rules updated as new threats emerge.
4. **Context Matters**: Always analyze results in context of your codebase.
5. **Professional Review**: Critical findings should be reviewed by security professionals.

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a new rule file or update existing ones
3. Test rules with both legitimate and malicious code
4. Submit a pull request with documentation

---

## 📝 License

This project is provided as-is for security research and WordPress vulnerability detection purposes.

---

## 🔗 Resources

- [YARA Documentation](https://virustotal.github.io/yara/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [WordPress Security](https://wordpress.org/support/article/hardening-wordpress/)
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)
- [SAML Security](https://owasp.org/www-community/attacks/SAML_Attacks)

---

## 📧 Support

For issues, questions, or rule suggestions, please open a GitHub issue.

---

**Last Updated**: 2026-05-19
**Status**: ✅ Production Ready | 100+ Rules | Comprehensive Coverage
