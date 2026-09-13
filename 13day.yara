rule RMRF_MetaScan_Leak :
{
    meta:
        author = "Shoninf"
        description = "Обнаруживает артефакты, связанные с утечкой RMRF у MetaScan"
        date = "2026-09-13"
        reference = "https://gti.bi.zone/search/darkweb#darkweb%3A38d31f84-ecfe-4618-b488-9b58967b46a3"

    strings:
        // Название компании и группировки
        $s1 = "MetaScan" wide ascii nocase
        $s2 = "metascan.ru" wide ascii nocase
        $s3 = "RMRF" wide nocase

        // Имена клиентов из утечки (отчёты по уязвимостям)
        $c1 = "Лента" wide ascii
        $c2 = "Сбербанк" wide ascii
        $c3 = "Ростелеком" wide ascii
        $c4 = "Итэлма" wide ascii
        $c5 = "Росхим" wide ascii
        $c6 = "Selectel" wide ascii
        $c7 = "Токеон" wide ascii

        // Признаки инфраструктуры (Django, Ansible, Nuclei)
        $d1 = "django" wide ascii nocase
        $d2 = "ansible" wide ascii nocase
        $d3 = "nuclei" wide ascii nocase
        $d4 = "nmap" wide ascii nocase
        $d5 = "masscan" wide ascii nocase
        $d6 = "hydra" wide ascii nocase
        $d7 = "OWASP ZAP" wide ascii nocase

    condition:
        // Файл должен быть документом, архивом или текстом
        (
            uint32(0) == 0x504B0304 or      // ZIP (DOCX, XLSX, архивы)
            uint32(0) == 0x25504446 or      // PDF
            uint32(0) == 0xD0CF11E0 or      // OLE (DOC, XLS, PPT)
            uint32(0) == 0x377ABCAF         // 7z
        ) and
        // Обязательно: название компании или группировки
        (
            $s1 or $s2 or $s3
        ) and
        // Дополнительно: минимум 2 индикатора (клиенты или инструменты)
        (
            ($c1 or $c2 or $c3 or $c4 or $c5 or $c6 or $c7) +
            ($d1 or $d2 or $d3 or $d4 or $d5 or $d6 or $d7)
        ) >= 2
}