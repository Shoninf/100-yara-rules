rule droper_purerat_purelogs :
{
    meta:
        author = "Shoninf"
        description = "Обнаруживает загрузчик PureRAT и PureLogs Stealer (.com, .exe)"
        date = "2026-09-04"
        reference = "https://gti.bi.zone/entity/attack:c5ca6728-a11f-4252-8097-40fbd6799fde/graph"

    strings:
        $s1 = "klgjgjgkhhkbn.exe"          // имя файла в автозапуске
        $s2 = "klgjgjgkhhk.exe"            // первая стадия
        $s3 = "STL_1.exe"                  // вторая стадия
        $s4 = "PureRAT"                    // название RAT
        $s5 = "PureLogs"                   // название стилера
        $s6 = "Gyyicd"                     // мьютекс PureRAT
        $s7 = "30b40b5ffada"               // мьютекс PureLogs
        $s8 = "PluginWindowNotify"         // плагин мониторинга окон
        $s9 = "/ping"                      // endpoint (часть URL)
        $s10 = "/plugin"                   // endpoint
        $s11 = "/userinfo"                 // endpoint

    condition:
        ($s1 or $s2 or $s3) and ($s4 or $s5 or $s6 or $s7 or $s8 or $s9 or $s10 or $s11)
}