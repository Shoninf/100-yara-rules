rule droper_busysnake : tag1 tag2
{
    meta:
        author = "Виктор"
        description = "день 1"
        date = "2026-01-09"
        reference = "https://gti.bi.zone/entity/attack:13f72279-f6c9-4732-b8c9-b20debaf8008/graph"

    strings:
        $s1 = "7748717"
        $s2 = "Wus"
        $s3 = "Microsystem Internet"

    condition:
        ($s1 and $s2) or ($s1 and $s3) or ($s2 and $s3)
}