rule a {
    strings:
        $a = "a" fullword wide base64wide private
    condition:
        $a
}
