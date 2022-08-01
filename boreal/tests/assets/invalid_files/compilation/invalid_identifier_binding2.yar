import "pe"

rule a {
    condition:
        for any k, v in pe.sections: (true)
}
