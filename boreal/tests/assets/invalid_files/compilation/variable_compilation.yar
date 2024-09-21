// [error: variable $a cannot be compiled: Compiled regex exceeds size limit of 10485760 bytes.]
rule a {
    strings:
        $a = /.{1,999999}/
    condition:
        $a
}
