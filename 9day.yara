rule Stealer_Clipper_Simple :
{
    meta:
        author = "Shoninf"
        description = "Обнаруживает стилер и клиппер с доставкой через Telegram"
        date = "2026-09-10"
        reference = "https://gti.bi.zone/search/darkweb#darkweb%3A6c5d658f-0091-48d0-a64c-2b2169495c1e"

    strings:
        $t1 = "api.telegram.org" wide ascii 
        $t2 = "GetClipboardData" wide ascii
        $t3 = "SetClipboardData" wide ascii
        $b1 = "Chrome" wide ascii
        $b2 = "Firefox" wide ascii
        $w1 = "mnemonic" wide ascii 
        $a1 = "App-Bound" wide ascii 

    condition:
        (
            uint16(0) == 0x5A4D or          // PE (exe/dll)
            uint32(0) == 0x464C457F or      // ELF (Linux)
            uint32(0) == 0xFEEDFACF         // Mach-O (macOS)
        ) and
        (
            $t1 or                          // Telegram C2
            ($t2 and $t3) or                // Клиппер (буфер обмена)
            ($a1 and $b1)                   // Обход Chrome
        )
}