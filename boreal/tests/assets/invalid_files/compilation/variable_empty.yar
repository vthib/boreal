rule a {
    strings:
        $foo = "" wide base64
    condition:
        $foo
}
