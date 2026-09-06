rule droper_asyncrat_python :
{
    meta:
        author = "Shoninf"
        description = "Обнаруживает загрузчик AsyncRAT (SFX-архив, Python, COM-hijacking)"
        date = "2026-09-05"
        reference = "https://gti.bi.zone/search/attack#attack%3A9a86081d-f842-4f08-9707-da7b7aa2151b"

    strings:
        $s1 = "appi\\appi"                         // уникальный путь к папке
        $s2 = "svchost.pyc"                        // полезная нагрузка Python
        $s3 = "shell_ext.sct"                      // файл для COM-hijacking
        $s4 = "F56F6FDD-AA9D-4618-A949-C1B91AF43B1A" // CLSID для COM-hijacking
        $s5 = "sdawx.shop"                         // C2-домен AsyncRAT
        $s6 = "g3ordWowQp19NPK6NdngX6vcn0Vn/BxfImRiaHonxYvZ+/QaYp1oF75XFsU6jVooBvmiId8lxz0+9UNgH3x84H+7RkVj8QQEgFx6Umv80ZALOK2ULPARnKRBQ4A4wFmSFeD3H1nDHnEKdQaJNWdPBRAE7eJoPvYbrr+9JmVHQZ0=" // серверная подпись
        $s7 = "EtwEventWrite"                      // патчинг для обхода ETW
        $s8 = "AmsiScanBuffer"                     // патчинг для обхода AMSI
        $s9 = "MicrosoftEdgeUpdateTaskUser_watch"  // имя запланированной задачи

    condition:
        $s1 and ($s2 or $s3 or $s4 or $s5 or $s6 or $s7 or $s8 or $s9)
}