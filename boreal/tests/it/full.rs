//! Tests on using boreal more "fully".
//!
//! Almost all other tests are in isolation, one rule with one variable, only checking if the rule
//! passes, etc. This can miss bugs that depends on a more real usage of the library: AC scan
//! indexes or reported matches that are wrong when many variables are used, etc.
//!
//! This module is for tests that try to cover those cases.
use crate::utils::Compiler;

#[test]
fn test_many_vars() {
    let mut compiler = Compiler::new();
    compiler.add_rules(
        r#"
// One rule with a bit of everything
rule a {
    strings:
        $r1 = /\bword\b/ ascii wide
        $s1 = "append"
        $h1 = { 61 70 70 } // "app"
        $s2 = "appendage" nocase
        $h2 = { C1 ?3 FF }
    condition:
        any of them
}

// A rule with a few anonymous strings
rule b {
    strings:
        $ = "app"
        $ = "a\nb"
        $ = "full" fullword nocase
    condition:
        any of them
}
"#,
    );

    compiler.add_rules_in_namespace(
        r#"
rule c {
    strings:
        $rgx = /\s_\w+\d{,2}/
        $version = /\d+\.\d+\.\d+/
        $hex = { d2 cc [5-] cc 2d }
        $hex2 = { d2 (?f | 00 | 1?) [2] ( AB | BA ) }
    condition:
        any of them
}
        "#,
        "2nd namespace",
    );

    compiler.add_rules_in_namespace(
        r#"
rule d {
    strings:
        $s1 = "append" nocase
        $s2 = "append"
    condition:
        any of them
}
        "#,
        "2nd namespace",
    );

    let checker = compiler.into_checker();

    checker.check_full_matches(
        b"word, got many words, some full fullwords, some non-fullword \
          \0w\0o\0r\0d\0 \0and words FULL of word, WORD.",
        vec![
            // on rule a, should match for `\bword\b`
            (
                "default:a".to_owned(),
                vec![(
                    "r1",
                    vec![(b"word", 0, 4), (b"w\0o\0r\0d\0", 62, 8), (b"word", 90, 4)],
                )],
            ),
            // on rule a, should match for `"full" fullword.
            (
                "default:b".to_owned(),
                vec![("", vec![(b"full", 27, 4), (b"FULL", 82, 4)])],
            ),
        ],
    );

    // This comes from the documentation of the aho-corasick crate, making sure
    // overlapping matches are properly reported.
    checker.check_full_matches(
        b"append the app to the appendage, Append the ApP to the ApPENDAGE.",
        vec![
            // on rule a, should match for `append`, `app`, and `appendage` nocase.
            (
                "default:a".to_owned(),
                vec![
                    ("s1", vec![(b"append", 0, 6), (b"append", 22, 6)]),
                    ("h1", vec![(b"app", 0, 3), (b"app", 11, 3), (b"app", 22, 3)]),
                    ("s2", vec![(b"appendage", 22, 9), (b"ApPENDAGE", 55, 9)]),
                ],
            ),
            // on rule b, should match for "app"
            (
                "default:b".to_owned(),
                vec![("", vec![(b"app", 0, 3), (b"app", 11, 3), (b"app", 22, 3)])],
            ),
            // on rule d, should match for "append" nocase and append
            (
                "2nd namespace:d".to_owned(),
                vec![
                    (
                        "s1",
                        vec![
                            (b"append", 0, 6),
                            (b"append", 22, 6),
                            (b"Append", 33, 6),
                            (b"ApPEND", 55, 6),
                        ],
                    ),
                    ("s2", vec![(b"append", 0, 6), (b"append", 22, 6)]),
                ],
            ),
        ],
    );

    // Check some overlapping hex strings, and bit of other stuff
    checker.check_full_matches(
        b"\xC1\xB4\xFF \xD2\xCC\xC1\xB3\xFF\xD2\x00\t\n\xBA\xCC\x2D \
          a23a\nb3.5.7.9.11\n13 _ab5 a234 _c_d _de \xC1\x33\xFF _",
        vec![
            // on rule a, should match for `{ C1 ?3 FF }`
            (
                "default:a".to_owned(),
                vec![(
                    "h2",
                    vec![(b"\xC1\xB3\xFF", 6, 3), (b"\xC1\x33\xFF", 56, 3)],
                )],
            ),
            // on rule b, should match for "a\nb"
            ("default:b".to_owned(), vec![("", vec![(b"a\nb", 20, 3)])]),
            // on rule c, should match for all the strings
            (
                "2nd namespace:c".to_owned(),
                vec![
                    (
                        "rgx",
                        vec![(b" _ab5", 36, 5), (b" _c_d", 46, 5), (b" _de", 51, 4)],
                    ),
                    (
                        "version",
                        vec![(b"3.5.7", 23, 5), (b"5.7.9", 25, 5), (b"7.9.11", 27, 6)],
                    ),
                    (
                        "hex",
                        vec![(b"\xD2\xCC\xC1\xB3\xFF\xD2\x00\t\n\xBA\xCC\x2D", 4, 12)],
                    ),
                    ("hex2", vec![(b"\xD2\x00\t\n\xBA", 9, 5)]),
                ],
            ),
        ],
    );
}
