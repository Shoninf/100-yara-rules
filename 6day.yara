rule droper_anydesk_bat2exe : rare_werewolf anydesk
{
    meta:
        author = "Shoninf"
        description = "Обнаруживает загрузчик AnyDesk/4t Tray Minimizer (Bat2Exe, PowerShell, bitsadmin)"
        date = "2026-09-06"
        reference = "https://gti.bi.zone/search/attack#attack%3Ab7f69ac3-a1bc-4d75-b823-89543767e7ca"

    strings:
        $s1 = "aero-bas.store" wide ascii
        $s2 = "ZHVtYmFzcw==" wide ascii
        $s3 = "Auto apdate" wide ascii
        $s4 = "whatisit.rar" wide ascii
        $s5 = "mail-identification.site" wide ascii
        $s6 = "wordpress" wide ascii
        $s7 = "Trays.exe" wide ascii

    condition:
        #s1 + #s2 + #s3 + #s4 + #s5 + #s6 + #s7 >= 2
}