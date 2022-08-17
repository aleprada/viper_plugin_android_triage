rule privacy_abusing_android_permissions{
    meta:
        author = "Alejandro Prada"
        date = "08-10-2021"
        description = "Rule for detecting abusive permissions in AndroidManifest.xml and .DEX files"
    strings:
        //security
        $a1 = "SYSTEM_ALERT_WINDOW"  fullword ascii wide
        $a2 = "INSTALL_PACKAGES" fullword ascii wide
        $a3 = "AUTHENTICATE ACCOUNTS" fullword ascii wide
        $a4 = "READ SENSITIVE LOG DATA" fullword ascii wide
        $a5 = "RECEIVE_SMS" fullword ascii wide
        $a6 = "READ_SMS" fullword ascii wide
        $a7 = "SEND_SMS" fullword ascii wide
        $a8 = "CALL_PHONE" fullword ascii wide
        $a9 = "CALL_PRIVILEGED" fullword ascii wide
        $a10 = "WRITE_EXTERNAL_STORAGE" fullword ascii wide  
        $a11 = "READ_PHONE_STATE" fullword ascii wide
        $a12 = "WAKE_LOCK" fullword ascii wide
        $a13 = "INTERNET" fullword ascii wide
        $a14 = "ACCESS_NETWORK_STATE" fullword ascii wide
        $a15 = "ACCESS_WIFI_STATE" fullword ascii wide

	condition:
        4 of ($a*)
}



















