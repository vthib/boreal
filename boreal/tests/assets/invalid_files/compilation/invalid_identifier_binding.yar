import "pe"

rule a {
    condition:
        for any a in pe.version_info: (true)
}
