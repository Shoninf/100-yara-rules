rule VM_malvare :
{
    meta:
        author = "shoninf"
        description = "OracleVMMaintenance"
        date = "2026-09-03"
        reference = "https://gti.bi.zone/entity/attack:2e88dcd3-76dc-4de1-9681-d1a92d19db96/graph"

    strings:
        $s1 = "Local\\MinuaSoftware" // мьютекс #1
        $s2 = "OracleVMMaintenance.exe" // исполняемый файл
        $s3 = "JRAUpdateTool.bat" // сценарий
        $s4 = "/api" //отправка
    condition:
        $s1 and ($s2 or $s3 or $s4)
}