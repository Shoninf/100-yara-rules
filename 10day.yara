rule GrimGazer_WatchWolf :
{
    meta:
        author = "Shoninf"
        description = "Обнаруживает троян GrimGazer (Watch Wolf)"
        date = "2026-09-11"
        reference = "https://gti.bi.zone/search/attack#attack%3A91db63e1-80dc-4704-a42b-2a4d2338719f"
    strings:
        $f1 = "Акт сверки АВГУСТ.exe" wide ascii
        $f2 = "Счет на оплату" wide ascii
        $d1 = "shell_overlay_data.db" wide ascii
        $d2 = "fmvt_dropper.log" wide ascii
        $r1 = "InprocServer32" wide ascii
        $r2 = "ContextMenuHandlers" wide ascii
        $c1 = "--remote-debugging-port=" wide ascii
        $a1 = "KasperskyLab" wide ascii
        $s1 = "342ab8a5.click" wide ascii

    condition:
        (
        uint16(0) == 0x5A4D or          // PE (Windows EXE/DLL)
        uint32(0) == 0x504B0304 or      // ZIP (DOCX, XLSX, JAR, APK)
        uint32(0) == 0x377ABCAF or      // 7z
        uint32(0) == 0xD0CF11E0 or      // OLE (DOC, XLS, PPT старых версий)
        uint32(0) == 0x25504446         // PDF
        )
        (
            $f1 or $f2 or $d1 or $d2 or
            ($r1 and $r2) or $c1 or $a1 or $s1
        )
}