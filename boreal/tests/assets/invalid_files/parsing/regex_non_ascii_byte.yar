// [error: regex should only contain ascii bytes]
rule a {
    strings:
        $a = /[é]/
    condition:
        $a
}
