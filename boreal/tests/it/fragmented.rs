use boreal::{
    memory::{FragmentedMemory, MemoryParams, Region, RegionDescription},
    scanner::{FragmentedScanMode, ScanParams},
};

use crate::utils::{get_boreal_full_matches, Checker};

#[test]
fn test_fragmented_string_scan() {
    let mut checker = Checker::new(
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
        (0, Some(b"cde abc ab".as_slice())),
        (0x1000, Some(b"abcde cde")),
        (0x2000, Some(b"cde")),
        (0x2A00, None),
        (0x3000, Some(b" abcd ")),
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

#[test]
fn test_fragmented_reverse_validation() {
    // Check that the optimization to prevent reverse validation to be quadratic does not
    // break detection with fragmented memory.
    // To avoid spending too long on reverse validation, the validation is bounded by the starting
    // offset of the previous match. In the case of fragmented memory however, this starting
    // offset should not be taken if it comes from another region.
    let mut checker = Checker::new(
        r"
rule a {
    strings:
        $a = /a[^a]*?bcde/
    condition:
        $a
}",
    );

    let regions = &[
        // Start offset is 5
        (0x1000, Some(b"01234abbbbcde".as_slice())),
        // Start offset is 0, but reverse validation starts after 5: the previous start offset
        // should not be taken into account or the reverse valid will fail.
        (0x2000, Some(b"a123456789bcde".as_slice())),
        // Start offset is 10
        (0x3000, Some(b"0123456789abcde".as_slice())),
        // Start offset is 1
        (0x4000, Some(b" abcde".as_slice())),
    ];
    checker.check_fragmented(regions, true);
    checker.check_fragmented_full_matches(
        regions,
        vec![(
            "default:a".to_owned(),
            vec![(
                "a",
                vec![
                    (b"abbbbcde", 0x1005, 8),
                    (b"a123456789bcde", 0x2000, 14),
                    (b"abcde", 0x300A, 5),
                    (b"abcde", 0x4001, 5),
                ],
            )],
        )],
    );
}

#[test]
fn test_fragmented_match_offset() {
    // check all the expressions that uses the match offset, to ensure the base of
    // the region is taken properly into account.
    let mut checker = Checker::new(
        r"
rule a {
    strings:
        $a = /a[^a]*?bcde/
    condition:
        #a == 4 and
        // Check offset of match
        (@a[1] == 0x1005 and !a[1] == 8) and
        (@a[2] == 0x2000 and !a[2] == 14) and
        (@a[3] == 0x300A and !a[3] == 5) and
        (@a[4] == 0x4001 and !a[4] == 5) and
        // Check count in
        (#a in (0x2000..0x4000) == 2) and
        // find at
        for any of them: ($ at 0x4001) and
        // find in
        for any of them: ($ in (0x1000..0x2000))
}",
    );

    let regions = &[
        // Start offset is 5
        (0x1000, Some(b"01234abbbbcde".as_slice())),
        // Start offset is 0, but reverse validation starts after 5: the previous start offset
        // should not be taken into account or the reverse valid will fail.
        (0x2000, Some(b"a123456789bcde".as_slice())),
        // Start offset is 10
        (0x3000, Some(b"0123456789abcde".as_slice())),
        // Start offset is 1
        (0x4000, Some(b" abcde".as_slice())),
    ];
    checker.check_fragmented(regions, true);
}

// Check strings matches do not handle spans across regions
#[test]
fn test_fragmented_cut() {
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = "abcd"
    condition:
        $a
}"#,
    );

    // Disjoint region, should not match
    checker.check_fragmented(&[(0, Some(b"ab")), (1000, Some(b"cd"))], false);
    // Adjacent region. It does not work, but we could imagine a match mode
    // where it does.
    checker.check_fragmented(&[(0, Some(b"ab")), (2, Some(b"cd"))], false);
}

#[test]
fn test_fragmented_empty() {
    let mut checker = Checker::new(
        r#"
rule a {
    condition:
        true
}"#,
    );

    checker.check_fragmented(&[(0, None), (10, None)], true);
}

#[test]
fn test_fragmented_filesize() {
    let mut checker = Checker::new(
        r#"
rule a {
    condition:
        filesize == 10
}"#,
    );
    checker.check(b"0123456789", true);
    checker.check_fragmented(&[(0, Some(b"0123456789"))], false);
    checker.check_fragmented(&[(0, Some(b"01234")), (5, Some(b"56789"))], false);

    let mut checker = Checker::new(
        r#"
rule a {
    condition:
        not defined filesize
}"#,
    );
    checker.check(b"0", false);
    checker.check_fragmented(&[(0, Some(b"0"))], true);
}

#[test]
fn test_fragmented_read_integer() {
    let mut checker = Checker::new(
        r#"
rule a {
    condition:
        uint32(1000) == 0x12345678
}"#,
    );

    let data = std::iter::repeat(0).take(2000).collect::<Vec<_>>();
    checker.check_fragmented(&[(0, Some(&data))], false);

    let data = std::iter::repeat(0)
        .take(1000)
        .chain([0x78, 0x56, 0x34, 0x12])
        .collect::<Vec<_>>();
    checker.check_fragmented(&[(0, Some(&data))], true);
    checker.check_fragmented(&[(0, Some(&data[1..]))], false);
    checker.check_fragmented(&[(200, Some(&data[200..]))], true);
    checker.check_fragmented(&[(200, Some(&data[201..]))], false);
    checker.check_fragmented(&[(200, Some(&data[199..]))], false);
    checker.check_fragmented(&[(500, Some(b"aaa")), (800, Some(&data[800..]))], true);

    // Check when at the limit
    checker.check_fragmented(&[(1000, Some(&[0x78, 0x56, 0x34, 0x12]))], true);
    checker.check_fragmented(&[(1000, Some(&[0x78, 0x56, 0x34, 0x12, 0]))], true);
    checker.check_fragmented(&[(999, Some(&[0, 0x78, 0x56, 0x34, 0x12]))], true);
    checker.check_fragmented(
        &[(1000, Some(&[0x78, 0x56])), (1002, Some(&[0x34, 0x12]))],
        false,
    );
    checker.check_fragmented(&[(1050, Some(b""))], false);
}

#[test]
#[cfg(feature = "object")]
fn test_fragmented_entrypoint() {
    use crate::libyara_compat::util::{ELF32_FILE, ELF32_SHAREDOBJ, ELF64_FILE};

    fn checker(value: u64) -> Checker {
        let mut checker = Checker::new(&format!("rule a {{ condition: entrypoint == {value} }}"));
        checker.set_process_memory_flag();
        checker
    }

    let mut undefined_checker = Checker::new("rule a { condition: not defined entrypoint }");
    undefined_checker.set_process_memory_flag();

    undefined_checker.check_fragmented(&[(0, Some(b""))], true);

    checker(0x8048060).check_fragmented(&[(0, Some(ELF32_FILE))], true);
    checker(0x8048060 + 1000).check_fragmented(
        &[(0, Some(b"a")), (500, Some(b"b")), (1000, Some(ELF32_FILE))],
        true,
    );

    checker(0x400080 + 500).check_fragmented(&[(500, Some(ELF64_FILE))], true);

    // First one found wins
    checker(0x8048060 + 500).check_fragmented(
        &[
            (0, Some(b"a")),
            (500, Some(ELF32_FILE)),
            (1000, Some(ELF64_FILE)),
        ],
        true,
    );
    checker(0x400080 + 500).check_fragmented(
        &[
            (0, Some(b"a")),
            (500, Some(ELF64_FILE)),
            (1000, Some(ELF32_FILE)),
        ],
        true,
    );

    // an elf that is not ET_EXEC is ignored
    undefined_checker.check_fragmented(&[(0, Some(b"a")), (500, Some(ELF32_SHAREDOBJ))], true);
    checker(0x8048060 + 1000).check_fragmented(
        &[
            (0, Some(b"a")),
            (500, Some(ELF32_SHAREDOBJ)),
            (1000, Some(ELF32_FILE)),
        ],
        true,
    );

    // Do the same for PE files
    let pe32 = std::fs::read("tests/assets/libyara/data/tiny").unwrap();
    let pe64 = std::fs::read("tests/assets/libyara/data/pe_mingw").unwrap();
    let dll = std::fs::read("tests/assets/libyara/data/mtxex.dll").unwrap();

    checker(0x14E0).check_fragmented(&[(0, Some(&pe32))], true);
    checker(0x14E0 + 1000).check_fragmented(&[(0, Some(b"a")), (1000, Some(&pe32))], true);

    checker(0x14F0).check_fragmented(&[(0, Some(&pe64))], true);
    checker(0x14F0 + 1000).check_fragmented(&[(0, Some(b"a")), (1000, Some(&pe64))], true);

    // DLL is ignored
    undefined_checker.check_fragmented(&[(0, Some(&dll))], true);
    checker(0x14F0 + 1000).check_fragmented(&[(0, Some(&dll)), (1000, Some(&pe64))], true);

    // first one picked
    checker(0x8048060 + 1000).check_fragmented(
        &[
            (0, Some(b"a")),
            (500, Some(&dll)),
            (1000, Some(ELF32_FILE)),
            (2000, Some(&pe32)),
        ],
        true,
    );
    checker(0x14E0 + 1000).check_fragmented(
        &[
            (0, Some(b"a")),
            (500, Some(&dll)),
            (1000, Some(&pe32)),
            (2000, Some(ELF32_FILE)),
        ],
        true,
    );
}

#[test]
#[cfg(feature = "object")]
fn test_fragmented_pe() {
    let rule = r#"
import "pe"

rule pe32 {
    condition: pe.is_pe and pe.is_32bit()
}
rule pe64 {
    condition: pe.is_pe and not pe.is_32bit()
}
rule dll {
    condition: pe.is_pe and pe.is_dll()
}
"#;
    let mut checker = Checker::new(rule);
    checker.set_process_memory_flag();

    let pe32 = std::fs::read("tests/assets/libyara/data/tiny").unwrap();
    let pe64 = std::fs::read("tests/assets/libyara/data/pe_mingw").unwrap();
    let dll = std::fs::read("tests/assets/libyara/data/mtxex.dll").unwrap();

    checker.check_fragmented_full_matches(
        &[(0, Some(&pe32))],
        vec![("default:pe32".to_owned(), vec![])],
    );
    checker.check_fragmented_full_matches(
        &[(0, Some(b"a")), (1000, Some(&pe64)), (2000, Some(&pe32))],
        vec![("default:pe64".to_owned(), vec![])],
    );
    checker.check_fragmented_full_matches(&[(0, Some(&dll)), (1000, Some(b"b"))], vec![]);
    checker.check_fragmented_full_matches(
        &[(0, Some(&dll)), (1000, Some(b"b")), (2000, Some(&pe32))],
        vec![("default:pe32".to_owned(), vec![])],
    );
}

#[test]
#[cfg(feature = "object")]
fn test_fragmented_elf() {
    use crate::libyara_compat::util::{ELF32_FILE, ELF32_SHAREDOBJ, ELF64_FILE};

    let rule = r#"
import "elf"

rule elf32 {
    condition: elf.machine == elf.EM_386
}
rule elf64 {
    condition: elf.machine == elf.EM_X86_64
}
rule so {
    condition: elf.type == elf.ET_DYN
}
"#;
    let mut checker = Checker::new(rule);
    checker.set_process_memory_flag();

    checker.check_fragmented_full_matches(
        &[(0, Some(ELF32_FILE))],
        vec![("default:elf32".to_owned(), vec![])],
    );

    // Should stop when finding the first one, and ignore the second one
    checker.check_fragmented_full_matches(
        &[
            (0, Some(b"a")),
            (1000, Some(ELF64_FILE)),
            (2000, Some(ELF32_FILE)),
        ],
        vec![("default:elf64".to_owned(), vec![])],
    );

    // Should ignore a SO file
    checker
        .check_fragmented_full_matches(&[(0, Some(ELF32_SHAREDOBJ)), (1000, Some(b"b"))], vec![]);

    checker.check_fragmented_full_matches(
        &[
            (0, Some(ELF32_SHAREDOBJ)),
            (1000, Some(b"b")),
            (2000, Some(ELF32_FILE)),
        ],
        vec![("default:elf32".to_owned(), vec![])],
    );
}

#[test]
#[cfg(feature = "object")]
fn test_fragmented_macho() {
    use crate::libyara_compat::util::{
        MACHO_X86_64_DYLIB_FILE as macho64, MACHO_X86_FILE as macho32,
    };

    let rule = r#"
import "macho"

rule macho32 {
    condition: macho.cputype == macho.CPU_TYPE_X86
}
rule macho64 {
    condition: macho.cputype == macho.CPU_TYPE_X86_64
}
"#;
    let mut checker = Checker::new(rule);
    checker.set_process_memory_flag();

    checker.check_fragmented_full_matches(
        &[(0, Some(macho32))],
        vec![("default:macho32".to_owned(), vec![])],
    );

    // Should stop when finding the first one, and ignore the second one
    checker.check_fragmented_full_matches(
        &[
            (0, Some(b"a")),
            (1000, Some(macho64)),
            (2000, Some(macho32)),
        ],
        vec![("default:macho64".to_owned(), vec![])],
    );
}

#[test]
fn test_fragmented_param_max_fetched_region_size() {
    let mut checker = Checker::new_without_yara(
        r#"
rule a {
    strings:
        $a = "abcdefgh"
    condition:
        $a
}"#,
    );

    // By default, works fine
    checker.check_fragmented(&[(0, Some(b"abcdefgh"))], true);

    // This will fail as the limit is very low and cuts the string
    checker.set_scan_params(ScanParams::default().max_fetched_region_size(4));
    checker.check_fragmented(&[(0, Some(b"abcdefgh"))], false);

    checker.set_scan_params(ScanParams::default().max_fetched_region_size(20));
    checker.check_fragmented(&[(0, Some(b"123456789 abcdefgh"))], true);
    // Cuts the string in two
    checker.check_fragmented(&[(0, Some(b"123456789 12345 abcdefgh"))], false);
    // Does not match if the whole string is past the limit, contrary to the
    // memory_chunk_size parameter.
    checker.check_fragmented(&[(0, Some(b"123456789 123456789 12345 abcdefgh"))], false);
}

#[test]
fn test_fragmented_param_memory_chunk_size() {
    let mut checker = Checker::new_without_yara(
        r#"
rule a {
    strings:
        $a = "abcdefgh"
    condition:
        $a
}"#,
    );

    // By default, works fine
    checker.check_fragmented(&[(0, Some(b"abcdefgh"))], true);

    // This will fail as the limit is very low and cuts the string
    checker.set_scan_params(ScanParams::default().memory_chunk_size(Some(4)));
    checker.check_fragmented(&[(0, Some(b"abcdefgh"))], false);

    checker.set_scan_params(ScanParams::default().memory_chunk_size(Some(20)));
    checker.check_fragmented(&[(0, Some(b"123456789 abcdefgh"))], true);
    // Cuts the string in two
    checker.check_fragmented(&[(0, Some(b"123456789 12345 abcdefgh"))], false);
    // Match since the string is in the second chunk.
    checker.check_fragmented(&[(0, Some(b"123456789 123456789 12345 abcdefgh"))], true);

    let mut checker = Checker::new_without_yara(
        r#"
rule a {
    strings:
        $a = "abcde"
        $b = "defgh"
        $c = "ijk"
    condition:
        all of them
}"#,
    );
    checker.set_scan_params(ScanParams::default().memory_chunk_size(Some(10)));
    checker.check_fragmented(
        &[
            (1000, Some(b"  abcde 123456")),
            (2000, Some(b"123456789 12 defgh 3")),
            (3000, Some(b"123456789 123456789 123456789 1234567ijk")),
        ],
        true,
    );
}

#[test]
#[cfg(feature = "object")]
fn test_fragmented_scan_mode_modules_dynamic_values() {
    use boreal::scanner::FragmentedScanMode;

    let rule = r#"
import "pe"

rule scanned_pe {
    condition: defined pe.is_pe
}
"#;
    let mut checker = Checker::new_without_yara(rule);

    let pe = std::fs::read("tests/assets/libyara/data/tiny").unwrap();

    // Legacy mode: evaluate modules
    checker.check_fragmented(&[(0, Some(&pe))], true);

    // Fast mode: do not evaluate modules
    checker.set_scan_params(ScanParams::default().fragmented_scan_mode(FragmentedScanMode::fast()));
    checker.check_fragmented(&[(0, Some(&pe))], false);

    // Single-pass mode: evaluate modules
    checker.set_scan_params(
        ScanParams::default().fragmented_scan_mode(FragmentedScanMode::single_pass()),
    );
    checker.check_fragmented(&[(0, Some(&pe))], true);
}

#[test]
fn test_fragmented_scan_mode_can_refetch_regions() {
    let rule = r#"
rule refetched_region {
    condition: uint8(1000) == 0x12
}
"#;
    let mut checker = Checker::new_without_yara(rule);

    // Legacy mode: refetch regions
    checker.check_fragmented(&[(1000, Some(b"\x12"))], true);

    // Fast mode: do not refetch regions
    checker.set_scan_params(ScanParams::default().fragmented_scan_mode(FragmentedScanMode::fast()));
    checker.check_fragmented(&[(1000, Some(b"\x12"))], false);

    // Single-pass mode: do not refetch regions
    checker.set_scan_params(
        ScanParams::default().fragmented_scan_mode(FragmentedScanMode::single_pass()),
    );
    checker.check_fragmented(&[(1000, Some(b"\x12"))], false);
}

#[test]
fn test_fragmented_no_scan_optimization() {
    let rule = r#"
rule refetched_region {
    strings:
        $a = "fetched"
    condition:
        true or $a
}
"#;
    let checker = Checker::new_without_yara(rule);
    let mut scanner = checker.scanner().scanner;

    let expected_no_opti = vec![(
        "default:refetched_region".to_owned(),
        vec![("a", vec![(b"fetched".as_slice(), 100, 7)])],
    )];
    let expected_opti = vec![("default:refetched_region".to_owned(), vec![])];

    // Legacy mode: no optimization
    let mut observer = Observer::new();
    let res = scanner.scan_fragmented(&mut observer).unwrap();
    assert!(observer.fetched);
    let res = get_boreal_full_matches(&res);
    assert_eq!(&res, &expected_no_opti);

    // Fast mode: optimization
    let mut observer = Observer::new();
    scanner.set_scan_params(ScanParams::default().fragmented_scan_mode(FragmentedScanMode::fast()));
    let res = scanner.scan_fragmented(&mut observer).unwrap();
    assert!(!observer.fetched);
    let res = get_boreal_full_matches(&res);
    assert_eq!(&res, &expected_opti);

    // Single-pass mode: no optimization
    let mut observer = Observer::new();
    scanner.set_scan_params(
        ScanParams::default().fragmented_scan_mode(FragmentedScanMode::single_pass()),
    );
    let res = scanner.scan_fragmented(&mut observer).unwrap();
    assert!(observer.fetched);
    let res = get_boreal_full_matches(&res);
    assert_eq!(&res, &expected_no_opti);
}

#[derive(Debug)]
struct Observer {
    idx: usize,
    fetched: bool,
}

impl Observer {
    fn new() -> Self {
        Self {
            idx: 0,
            fetched: false,
        }
    }
}

impl FragmentedMemory for &mut Observer {
    fn next(&mut self, _params: &MemoryParams) -> Option<RegionDescription> {
        if self.idx == 0 {
            self.idx = 1;
            Some(RegionDescription {
                start: 100,
                length: 7,
            })
        } else {
            None
        }
    }

    fn fetch(&mut self, _params: &MemoryParams) -> Option<Region> {
        self.fetched = true;
        Some(Region {
            start: 100,
            mem: b"fetched",
        })
    }

    fn reset(&mut self) {
        self.idx = 0;
    }
}
