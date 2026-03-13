/* =========================================================
   Active Directory / User Sync Vulnerability Detection
   ========================================================= */


/* ---------------------------------------------------------
   LDAP Injection
   --------------------------------------------------------- */

rule LDAP_Injection_Filter
{
    meta:
        description = "Possible LDAP injection in filter construction"
        category = "AD/LDAP"
        severity = "high"

    strings:
        $ldap = /(ldap_search|ldap_bind|ldap_query)/i
        $filter = /\(\s*(uid|cn|mail|userPrincipalName)\s*=\s*\$\w+/i

    condition:
        filesize < 5MB and $ldap and $filter
}



/* ---------------------------------------------------------
   Dynamic LDAP Filter from User Input
   --------------------------------------------------------- */

rule LDAP_Filter_User_Input
{
    meta:
        description = "LDAP filter built using request parameters"
        category = "AD/LDAP"
        severity = "high"

    strings:
        $filter1 = /\(\s*(uid|mail|cn)\s*=\s*\$_(GET|POST|REQUEST)/i
        $filter2 = /ldap_search\s*\(.*\$_(GET|POST|REQUEST)/i

    condition:
        filesize < 5MB and any of ($filter*)
}



/* ---------------------------------------------------------
   Auto User Creation From AD
   --------------------------------------------------------- */

rule AD_Auto_User_Creation
{
    meta:
        description = "User automatically created from AD attributes"
        category = "User Sync"
        severity = "medium"

    strings:
        $create1 = /(create_user|wp_create_user|add_user)/i
        $attr = /(mail|userPrincipalName|displayName)/i

    condition:
        filesize < 10MB and $create1 and $attr
}



/* ---------------------------------------------------------
   Admin Role Mapping From AD Group
   --------------------------------------------------------- */

rule AD_Admin_Role_Mapping
{
    meta:
        description = "AD group mapped directly to admin role"
        category = "Privilege Escalation"
        severity = "critical"

    strings:
        $group = /(memberOf|group|roleMapping)/i
        $admin = /(administrator|admin_role|ROLE_ADMIN)/i

    condition:
        filesize < 5MB and $group and $admin
}



/* ---------------------------------------------------------
   Blind Trust in IdP Attributes
   --------------------------------------------------------- */

rule IdP_Attribute_Trust
{
    meta:
        description = "Blindly trusting IdP attributes for user creation"
        category = "User Sync"
        severity = "high"

    strings:
        $attr1 = /(email|mail|username)/i
        $sink = /(create_user|add_user|update_user)/i
        $source = /\$_(POST|GET|REQUEST)\[['"](email|mail|username)['"]\]/i

    condition:
        filesize < 5MB and $source and $sink
}



/* ---------------------------------------------------------
   Domain Validation Missing
   --------------------------------------------------------- */

rule Missing_Email_Domain_Validation
{
    meta:
        description = "User email accepted without domain validation"
        category = "User Sync"
        severity = "medium"

    strings:
        $email = /(email|mail)/i
        $create = /(create_user|add_user|wp_create_user)/i
        $domain = /(example\.com|company\.com)/i

    condition:
        filesize < 5MB and $email and $create and not $domain
}



/* ---------------------------------------------------------
   Password Sync Exposure
   --------------------------------------------------------- */

rule AD_Password_Sync
{
    meta:
        description = "Possible password sync or storage from AD"
        category = "User Sync"
        severity = "critical"

    strings:
        $pass1 = /(password|pwdLastSet)/i
        $ldap = /(ldap_search|ldap_bind)/i
        $store = /(update_user_meta|INSERT INTO)/i

    condition:
        filesize < 5MB and $pass1 and $ldap and $store
}



/* ---------------------------------------------------------
   LDAP Connection Without TLS
   --------------------------------------------------------- */

rule LDAP_Insecure_Connection
{
    meta:
        description = "LDAP connection without TLS"
        category = "Transport"
        severity = "high"

    strings:
        $ldap = /ldap:\/\//i
        $ldaps = /ldaps:\/\//i

    condition:
        filesize < 2MB and $ldap and not $ldaps
}



/* ---------------------------------------------------------
   SCIM User Provisioning Without Validation
   --------------------------------------------------------- */

rule SCIM_User_Provisioning_Trust
{
    meta:
        description = "SCIM provisioning endpoint trusting input"
        category = "SCIM"
        severity = "high"

    strings:
        $scim = /(scim|Users|Groups)/i
        $create = /(create_user|add_user|insert_user)/i
        $input = /\$_(POST|REQUEST)/i

    condition:
        filesize < 5MB and $scim and $create and $input
}



/* ---------------------------------------------------------
   Group Sync Without Verification
   --------------------------------------------------------- */

rule AD_Group_Sync_No_Validation
{
    meta:
        description = "Group membership used without verification"
        category = "Privilege Escalation"
        severity = "high"

    strings:
        $group = /(memberOf|groups)/i
        $role = /(role|permission|admin)/i
        $assign = /(set_role|assign_role)/i

    condition:
        filesize < 5MB and $group and $role and $assign
}