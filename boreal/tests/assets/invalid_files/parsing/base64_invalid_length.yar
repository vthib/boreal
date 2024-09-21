// [error: base64 modifier alphabet must contain exactly 64 characters]
rule a {
    strings:
        $a = "a" base64("abc")
    condition:
        $a
}
