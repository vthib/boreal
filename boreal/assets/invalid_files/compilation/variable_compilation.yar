rule a {
    strings:
        $a = /.{1,999999}/
    condition:
        $a
}
