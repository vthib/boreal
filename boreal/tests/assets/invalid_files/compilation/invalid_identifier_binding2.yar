// [error: expected 1 identifiers to bind, got 2]
import "pe"

rule a {
    condition:
        for any k, v in pe.sections: (true)
}
