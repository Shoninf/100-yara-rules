rule xloader_formbook :
{
    meta:
        author = "Виктор"
        description = "Обнаруживает загрузчик XLoader/Formbook (PE, .bat, инжект)"
        date = "2026-09-02"
        reference = "https://gti.bi.zone/search/attack#attack%3Af618c56e-4c2f-4496-b454-befc38c5ede5"

    strings:
        $s1 = "KP0186RFB2TF3AA0"           // мьютекс 1
        $s2 = "6799877-440AG-4_"           // мьютекс 2
        $s3 = "99268O914-CG9xG1"           // мьютекс 3
        $s4 = "orve.top"                   // домен (можно взять любой)

    condition:
        // Срабатывает, если найдены как минимум два из трёх мьютексов
        // либо один мьютекс и домен
        ($s1 and $s2) or ($s1 and $s3) or ($s2 and $s3) or ($s1 and $s4) or ($s2 and $s4) or ($s3 and $s4)
}