// [error: cannot include]
import "pe"

rule a {
    condition: true
}

include "./do-not-exist.yar"
