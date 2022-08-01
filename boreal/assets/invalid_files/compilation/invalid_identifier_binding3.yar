import "pe"

rule a {
    condition:
        for any k, v in (0..2): (true)
}

