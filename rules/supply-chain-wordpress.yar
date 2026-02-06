/************************************************************
 * supply-chain-wordpress.yar
 * WordPress plugin & theme supply-chain attack detection
 * Scope: wp-content/plugins, wp-content/themes
 ************************************************************/

rule wp_supply_chain_remote_code_execution
{
    meta:
        description = "Plugin/theme downloads remote content and executes it"
        category = "SUPPLY_CHAIN"
        severity = "critical"
        confidence = "high"

    strings:
        /* Remote fetch */
        $fetch1 = "wp_remote_get("
        $fetch2 = "wp_remote_post("
        $fetch3 = "file_get_contents("
        $fetch4 = "curl_init("
        $fetch5 = "curl "
        $fetch6 = "wget "

        /* Execution */
        $exec1 = "eval("
        $exec2 = "assert("
        $exec3 = "shell_exec("
        $exec4 = "exec("
        $exec5 = "system("

    condition:
        filesize < 10MB
        and any of ($fetch*)
        and any of ($exec*)
}

/* ------------------------------------------------------ */

rule wp_supply_chain_obfuscated_payload_dropper
{
    meta:
        description = "Obfuscated payload used to drop or modify plugin files"
        category = "SUPPLY_CHAIN"
        severity = "high"
        confidence = "high"

    strings:
        $obf1 = "base64_decode("
        $obf2 = "gzinflate("
        $obf3 = "gzuncompress("
        $obf4 = "str_rot13("
        $write1 = "file_put_contents("
        $write2 = "fopen("

    condition:
        filesize < 10MB
        and 2 of ($obf*)
        and any of ($write*)
}

/* ------------------------------------------------------ */

rule wp_supply_chain_external_update_server
{
    meta:
        description = "Plugin implements update logic using external server"
        category = "SUPPLY_CHAIN"
        severity = "high"
        confidence = "medium"

    strings:
        $update1 = "pre_set_site_transient_update_plugins"
        $update2 = "set_site_transient('update_plugins'"
        $update3 = "plugins_api"
        $remote  = /(http:\/\/|https:\/\/)/i

    condition:
        filesize < 10MB
        and any of ($update*)
        and $remote
}

/* ------------------------------------------------------ */

rule wp_supply_chain_external_zip_install
{
    meta:
        description = "Plugin downloads and extracts ZIP from external URL"
        category = "SUPPLY_CHAIN"
        severity = "critical"
        confidence = "high"

    strings:
        $download = "download_url("
        $unzip1   = "unzip_file("
        $unzip2   = "ZipArchive"
        $remote   = /(http:\/\/|https:\/\/)/i

    condition:
        filesize < 10MB
        and $download
        and any of ($unzip*)
        and $remote
}

/* ------------------------------------------------------ */

rule wp_supply_chain_hidden_admin_creation
{
    meta:
        description = "Plugin silently creates or elevates administrator user"
        category = "SUPPLY_CHAIN"
        severity = "critical"
        confidence = "high"

    strings:
        $user1 = "wp_create_user("
        $user2 = "wp_insert_user("
        $meta  = "update_user_meta("
        $role1 = "'administrator'"
        $role2 = "\"administrator\""
        $caps  = "wp_capabilities"

    condition:
        filesize < 10MB
        and ( any of ($user*) or $meta )
        and ( any of ($role*) or $caps )
}

/* ------------------------------------------------------ */

rule wp_supply_chain_vendor_folder_backdoor
{
    meta:
        description = "Executable backdoor logic inside vendor directory"
        category = "SUPPLY_CHAIN"
        severity = "high"
        confidence = "medium"

    strings:
        $vendor = "/vendor/"
        $exec1  = "eval("
        $exec2  = "shell_exec("
        $exec3  = "system("
        $exec4  = "exec("

    condition:
        filesize < 10MB
        and $vendor
        and any of ($exec*)
}

/* ------------------------------------------------------ */

rule wp_supply_chain_typosquatted_library
{
    meta:
        description = "Possible typosquatted bundled PHP library"
        category = "SUPPLY_CHAIN"
        severity = "medium"
        confidence = "heuristic"

    strings:
        $lib1 = "phmialer"
        $lib2 = "monologg"
        $lib3 = "sympfony"
        $lib4 = "guzzel"
        $lib5 = "reqeust"

    condition:
        filesize < 5MB
        and any of ($lib*)
}

/* ------------------------------------------------------ */

rule wp_supply_chain_activation_time_execution
{
    meta:
        description = "Dangerous code executed during plugin activation"
        category = "SUPPLY_CHAIN"
        severity = "medium"
        confidence = "medium"

    strings:
        $activate = "register_activation_hook("
        $exec1 = "exec("
        $exec2 = "shell_exec("
        $exec3 = "system("
        $write = "file_put_contents("

    condition:
        filesize < 10MB
        and $activate
        and ( any of ($exec*) or $write )
}

/* ------------------------------------------------------ */

rule wp_supply_chain_remote_include
{
    meta:
        description = "Remote file inclusion in plugin/theme code"
        category = "SUPPLY_CHAIN"
        severity = "critical"
        confidence = "high"

    strings:
        $include = /(include|require)(_once)?\s*\(/i
        $remote  = /(http:\/\/|https:\/\/)/i

    condition:
        filesize < 10MB
        and $include
        and $remote
}
