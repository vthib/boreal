// [error: string modifier private appears multiple times]
rule a {
    strings:
        $a = "a" private wide private
}
