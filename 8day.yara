rule audit_team_mansurovogroup :
{
    meta:
        author = "Shoninf"
        description = "Обнаруживает артефакты, связанные с утечкой данных AUDIT TEAM (Агрокомплекс Мансурово)"
        date = "2026-09-09"
        reference = "https://gti.bi.zone/search/darkweb#darkweb%3Aedd2646d-ce1e-437f-8da8-394eef3ff598"
        victim = "mansurovogroup.ru"

    strings:
        // Уникальные строки из описания утечки
        $s1 = "AUDIT TEAM" wide ascii nocase
        $s2 = "Audit Team" wide ascii nocase
        $s3 = "audit team" wide ascii nocase
        $s4 = "Мансурово" wide ascii nocase
        $s5 = "mansurovo" wide ascii nocase
        $s6 = "mansurovogroup" wide ascii nocase
        $s7 = "ma***up" wide ascii nocase
        $s8 = "192.168.26.14" wide ascii
        $s9 = "192.168.26.14_E.7z" wide ascii
        $s10 = "192.168.26.14_F.7z" wide ascii
        $s11 = "backup.7z" wide ascii nocase 
        $s12 = "backup2.7z" wide ascii nocase

    condition:
        (
            // Группа 1: Название группировки (обязательно)
            $s1 or $s2 or $s3
        ) and
        (
            // Группа 2: минимум 2 дополнительных индикатора из списка
            ($s4 or $s5 or $s6) +
            ($s7) +
            ($s8 or $s9 or $s10) +
            ($s11 or $s12)
        ) >= 2
}