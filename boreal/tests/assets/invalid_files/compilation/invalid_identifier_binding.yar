// [error: expected 2 identifiers to bind, got 1]
import "pe"

rule a {
    condition:
        for any a in pe.version_info: (true)
}
