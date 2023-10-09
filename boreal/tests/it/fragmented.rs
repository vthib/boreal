use crate::utils::Checker;

#[test]
fn test_fragmented_string_scan() {
    let checker = Checker::new(
        r"
rule a {
    strings:
        $a = /a\w+/
        $b = /^cde/
    condition:
        #a == 4 and #b == 2
}",
    );

    let regions = &[
        (0, b"cde abc ab".as_slice()),
        (0x1000, b"abcde cde"),
        (0x2000, b"cde"),
        (0x3000, b" abcd "),
    ];
    checker.check_fragmented(regions, true);
    checker.check_fragmented_full_matches(
        regions,
        vec![(
            "default:a".to_owned(),
            vec![
                (
                    "a",
                    vec![
                        (b"abc", 4, 3),
                        (b"ab", 8, 2),
                        (b"abcde", 0x1000, 5),
                        (b"abcd", 0x3001, 4),
                    ],
                ),
                ("b", vec![(b"cde", 0, 3), (b"cde", 0x2000, 3)]),
            ],
        )],
    );
}

// Check strings matches do not handle spans across regions
#[test]
fn test_fragmented_cut() {
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = "abcd"
    condition:
        $a
}"#,
    );

    // Disjoint region, should not match
    checker.check_fragmented(&[(0, b"ab"), (1000, b"cd")], false);
    // Adjacent region. It does not work, but we could imagine a match mode
    // where it does.
    checker.check_fragmented(&[(0, b"ab"), (2, b"cd")], false);
}

#[test]
fn test_fragmented_filesize() {
    let checker = Checker::new(
        r#"
rule a {
    condition:
        filesize == 10
}"#,
    );
    checker.check(b"0123456789", true);
    checker.check_fragmented(&[(0, b"0123456789")], false);
    checker.check_fragmented(&[(0, b"01234"), (5, b"56789")], false);

    let checker = Checker::new(
        r#"
rule a {
    condition:
        not defined filesize
}"#,
    );
    checker.check(b"0", false);
    checker.check_fragmented(&[(0, b"0")], true);
}

#[test]
fn test_fragmented_read_integer() {
    let checker = Checker::new(
        r#"
rule a {
    condition:
        uint32(1000) == 0x12345678
}"#,
    );

    let data = std::iter::repeat(0).take(2000).collect::<Vec<_>>();
    checker.check_fragmented(&[(0, &data)], false);

    let data = std::iter::repeat(0)
        .take(1000)
        .chain([0x78, 0x56, 0x34, 0x12])
        .collect::<Vec<_>>();
    checker.check_fragmented(&[(0, &data)], true);
    checker.check_fragmented(&[(0, &data[1..])], false);
    checker.check_fragmented(&[(200, &data[200..])], true);
    checker.check_fragmented(&[(200, &data[201..])], false);
    checker.check_fragmented(&[(200, &data[199..])], false);
    checker.check_fragmented(&[(500, b"aaa"), (800, &data[800..])], true);

    // Check when at the limit
    checker.check_fragmented(&[(1000, &[0x78, 0x56, 0x34, 0x12])], true);
    checker.check_fragmented(&[(1000, &[0x78, 0x56, 0x34, 0x12, 0])], true);
    checker.check_fragmented(&[(999, &[0, 0x78, 0x56, 0x34, 0x12])], true);
    checker.check_fragmented(&[(1000, &[0x78, 0x56]), (1002, &[0x34, 0x12])], false);
    checker.check_fragmented(&[(1050, b"")], false);
}
