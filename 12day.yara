rule Umbral_Stealer : stealer discord
{
    meta:
        author = "Shoninf"
        description = "Обнаруживает стилер Umbral Stealer (сборка Blank-c)"
        date = "2026-09-12"
        reference = "https://gti.bi.zone/search/darkweb#darkweb%3Ab287501b-b9f0-4f1c-908c-5a0d05206679"

    strings:
        // Название стилера и билдера
        $n1 = "Umbral" wide ascii
        $n2 = "Umbral.builder.exe" wide ascii
        $n3 = "Umbral-" wide ascii             // префикс ZIP-архива Umbral-{MachineName}.zip

        // Discord C2 (доставка логов)
        $d1 = "discord.com/api/webhooks" wide ascii
        $d2 = "discordapp.com/api/webhooks" wide ascii

        // Обход Chrome App-Bound Encryption v20
        $a1 = "App-Bound" wide ascii
        $a2 = "lsass.exe" wide ascii
        $a3 = "DPAPI" wide ascii
        $a4 = "ChaCha20-Poly1305" wide ascii

        // Отключение Defender через MpCmdRun
        $m1 = "MpCmdRun.exe" wide ascii
        $m2 = "-DisableIOAVProtection" wide ascii
        $m3 = "Add-MpPreference" wide ascii

        // Самоудаление и закрепление
        $s1 = "melt" wide ascii
        $s2 = "startup" wide ascii

        // Скрытые бэкдоры из оригинального проекта
        $b1 = "BunifuSet.dll" wide ascii
        $b2 = "BunifuService.dll" wide ascii
        $b3 = "BunifuShape.dll" wide ascii

    condition:
        uint16(0) == 0x5A4D and            // PE (Windows .exe)
        (
            $n1 or $n2 or $n3 or           // Название стилера
            $d1 or $d2 or                  // Discord вебхук
            ($a1 and $a2) or               // Обход Chrome через lsass
            ($m1 and $m2) or               // Отключение Defender
            $b1 or $b2 or $b3              // Скрытые библиотеки
        )
}