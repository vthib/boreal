use std::io::Write;

const STATIC_PAYLOAD: &str = "PAYLOAD_ON_STACK";

fn main() {
    let arg = std::env::args().nth(1).unwrap();

    // This binary is used for tests. The protocol is very simple:
    // - the caller must provide the name of the test to execute
    // - this program will then print details to stdout, and print "ready\n"
    //   when the test can be executed.
    // - this program will then sleep for a long time, until the test ends
    //   and the process is killed.
    match &*arg {
        "stack" => stack(),
        "max_fetched_region_size" => max_fetched_region_size(),
        _ => panic!("unknown arg {}", arg),
    }
}

struct Region {
    _file: tempfile::NamedTempFile,
    map: memmap2::Mmap,
}

impl Region {
    fn addr(&self) -> usize {
        self.map.as_ptr() as usize
    }
}

fn stack() {
    // This is "test0123456789helper" when xor'ed
    let payload = xor_bytes(b"{j|{?>=<;:9876gjc\x7fj}", 15);

    println!("ready");
    std::thread::sleep(std::time::Duration::from_secs(500));

    // Black box to avoid the payload from being optimized away before
    // the process scan.
    std::hint::black_box(payload);
    std::hint::black_box(STATIC_PAYLOAD);
}

fn max_fetched_region_size() {
    // The searched string is "Dwb6r5gd", and the fetch limit is 20 bytes

    // One page will contain the whole string.
    // This is "Dwb6r5gd"
    let region1 = allocate_region(b"Kxm9}:hk");

    // This one will still match, since it is exactly 20 bytes
    // This is "123456789 Dwb6r5gd"
    let region2 = allocate_region(b">=<;:9876/Kxm9}:hk");

    // This one will not match as it gets cut
    // This is "123456789 12345 Dwb6r5gd"
    let region3 = allocate_region(b">=<;:9876/>=<;:/Kxm9}:hk");

    // Past the limit so will not get matched
    // This is "123456789 123456789 12345 Dwb6r5gd"
    let region4 = allocate_region(b">=<;:9876/>=<;:9876/>=<;:/Kxm9}:hk");

    // Send the base addresses of the region back to the test
    println!("{:x}", region1.addr());
    println!("{:x}", region2.addr());
    println!("{:x}", region3.addr());
    println!("{:x}", region4.addr());

    println!("ready");
    std::thread::sleep(std::time::Duration::from_secs(500));
}

fn allocate_region(contents: &[u8]) -> Region {
    // Create a file, write the xored content into it, and mmap it.
    // Why a file instead of an anonymous mapping? It ensures each region is separate
    // in the proc maps file, instead of part of the same region.
    let mut file = tempfile::NamedTempFile::new().unwrap();
    xor_bytes_into(contents, 15, file.as_file_mut());
    let map = unsafe { memmap2::Mmap::map(file.as_file()).unwrap() };

    Region { _file: file, map }
}

fn xor_bytes(v: &[u8], xor_byte: u8) -> Vec<u8> {
    v.iter().map(|b| *b ^ xor_byte).collect()
}

fn xor_bytes_into(v: &[u8], xor_byte: u8, f: &mut std::fs::File) {
    for b in v {
        f.write_all(&[*b ^ xor_byte]).unwrap();
    }
    f.flush().unwrap();
}
