rule vanta_core_asgard_wolf :
{
    meta:
        author = "Shoninf"
        description = "Обнаруживает артефакты, связанные с утечкой данных VantaCore/Asgard Wolf (ООО Севернефтегазпром)"
        date = "2026-09-07"
        reference = "https://gti.bi.zone/search/darkweb#darkweb%3A38774205-471e-435a-8126-aeec5f05f502"

    strings:
        // Уникальные строки из описания утечки
        $s1 = "STORAGE01-GP" wide ascii
        $s2 = "storage01-gp" wide ascii
        $s3 = "storage04-nux" wide ascii
        $s4 = "Severneftegazprom" wide ascii
        $s5 = "severneftegazprom" wide ascii
        $s6 = "sngp" wide ascii
        $s7 = "SNGP" wide ascii
        $s8 = "VantaCore" wide ascii
        $s9 = "Asgard Wolf" wide ascii
        $s10 = "treeinfo.wc" wide ascii
        $s11 = "Thumbs.db" wide ascii
        $s12 = "Root/sngp/files/STORAGE01-GP/share" wide ascii

    condition:
        // Должен быть PE-файл или документ, содержащий индикаторы. (убираем ложные срабатывания)
        (
            uint16(0) == 0x5A4D or  // PE (exe/dll)
            uint16(0) == 0x4D5A or  // PE (альтернативный)
            uint32(0) == 0x504B0304 or // ZIP (включая DOCX, XLSX)
            uint32(0) == 0x25504446 or // PDF
            uint32(0) == 0xD0CF11E0    // OLE (DOC, XLS, PPT)
        ) and
        (
            // Группа 1: специфичные имена серверов
            $s1 or $s2 or $s3 or $s12
        ) and
        (
            // Группа 2: минимум два дополнительных индикатора
            ( $s4 or $s5 or $s6 or $s7 ) +
            ( $s8 or $s9 ) +
            ( $s10 or $s11 )
        ) >= 2
}
