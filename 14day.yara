rule WordPress_wp_db_backup :
{
    meta:
        author = "Shoninf"
        description = "Обнаруживает эксплуатацию уязвимости обхода каталогов в плагине wp-db-backup"
        date = "2026-09-15"
        reference = "BIZ-2025-47927(CVE-2006-5705)"

    strings:
        // Уязвимый файл плагина
        $p1 = "wp-db-backup.php" wide ascii nocase
        $p2 = "wp-db-backup" wide ascii nocase

        // Параметры, через которые идёт эксплуатация
        $q1 = "backup=" wide ascii
        $q2 = "fragment=" wide ascii

        // Признаки обхода каталогов
        $t1 = "../" ascii
        $t2 = "..%2f" wide ascii nocase
        $t3 = "%2e%2e%2f" wide ascii nocase
        $t4 = "....//" ascii

        // Признаки чтения/записи файлов
        $f1 = "wp-config.php" wide ascii nocase
        $f2 = "/etc/passwd" wide ascii
        $f3 = "file_get_contents" wide ascii
        $f4 = "file_put_contents" wide ascii

    condition:
        // Документ/скрипт/лог/архив — любой текстовый или сжатый файл
        (
            uint32(0) == 0x504B0304 or      // ZIP
            uint32(0) == 0x25504446 or      // PDF
            uint32(0) == 0xD0CF11E0 or      // OLE (DOC, XLS)
            uint16(0) == 0x2321 or          // #! (скрипт)
            uint16(0) == 0x3C3F or          // <? (PHP)
            uint16(0) == 0x7B0A            // {\n (JSON)
        ) and
        // Обязательно: имя плагина
        (
            $p1 or $p2
        ) and
        // Дополнительно: параметры + обход каталогов
        (
            ($q1 or $q2) and
            ($t1 or $t2 or $t3 or $t4)
        )
}