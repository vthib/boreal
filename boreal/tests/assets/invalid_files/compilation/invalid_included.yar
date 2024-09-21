// [error: variable $a is unused]
import "pe"

rule a {
    condition: true
}

include "./unused_variable.yar"
