// [error: alphabets used for base64 and base64wide must be identical]
rule a {
    strings:
        $a = "a" base64("/=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") base64wide
    condition:
        $a
}
