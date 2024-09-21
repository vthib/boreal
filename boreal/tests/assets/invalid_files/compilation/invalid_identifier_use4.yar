// [error: wrong use of identifier]
import "pe"

rule c {
    condition:
        for any a in pe.import_details: (
            a.functions == 2
        )
}
