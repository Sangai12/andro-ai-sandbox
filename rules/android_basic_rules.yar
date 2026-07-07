/*
AndroAI Sandbox - Basic Android YARA Rules

Phase 20.2 scope:
- Demonstration rules
- Safe starter signatures
- Evidence generation only
*/

rule Android_HTTP_URL
{
    strings:
        $http = "http://"

    condition:
        $http
}

rule Android_Frida
{
    strings:
        $frida = "frida" nocase
        $gum = "gum-js-loop" nocase

    condition:
        any of them
}

rule Android_Magisk
{
    strings:
        $magisk = "magisk" nocase
        $zygisk = "zygisk" nocase

    condition:
        any of them
}

rule Android_Xposed
{
    strings:
        $xposed = "xposed" nocase
        $lsposed = "lsposed" nocase

    condition:
        any of them
}

rule Android_Root_SU
{
    strings:
        $su1 = "/system/bin/su"
        $su2 = "/system/xbin/su"

    condition:
        any of them
}