import "pe"

rule a {
    condition:
        for any k, v, t in (0, 1, 2): (true)
}
