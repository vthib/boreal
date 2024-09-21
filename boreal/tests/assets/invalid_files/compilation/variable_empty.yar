// [error: variable $foo cannot be compiled: variable is empty]
rule a {
    strings:
        $foo = "" wide base64
    condition:
        $foo
}
