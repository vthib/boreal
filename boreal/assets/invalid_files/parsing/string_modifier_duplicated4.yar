rule a {
    strings:
        $a = "a" base64wide xor base64wide("/=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
}
