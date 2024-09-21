// [error: alphabets used for base64 and base64wide must be identical]
rule a {
    strings:
        $a = "a" base64 base64wide("/=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    condition:
        $a
}
