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
        "memory_chunk_size" => memory_chunk_size(),
        "file_copy_on_write" => file_copy_on_write(),
        _ => panic!("unknown arg {}", arg),
    }
}

struct Region {
    _file: tempfile::NamedTempFile,
    map: memmap2::MmapMut,
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

// Use this value as the "page_size" we use to construct our regions. This should
// always be a multiple of the page size.
const PAGE_SIZE: usize = 4 * 1024 * 1024;

fn max_fetched_region_size() {
    // The searched string is "Dwb6r5gd", and the fetch limit is 12MB
    let pattern = b"Kxm9}:hk";

    // One page will contain the whole string.
    // This is "Dwb6r5gd"
    let region1 = Region::new(pattern);

    // This one will still match, since it is exactly 12MB
    let mut region2 = Region::zeroed(PAGE_SIZE);
    region2.write_at(PAGE_SIZE - 8, pattern);

    // This one will not match as it gets cut in the middle
    let mut region3 = Region::zeroed(PAGE_SIZE + 10);
    region3.write_at(PAGE_SIZE - 4, pattern);

    // Past the limit so will not get matched
    let mut region4 = Region::zeroed(PAGE_SIZE + 500);
    region4.write_at(PAGE_SIZE + 200, pattern);

    // Send the base addresses of the region back to the test
    println!("{:x}", region1.addr());
    println!("{:x}", region2.addr());
    println!("{:x}", region3.addr());
    println!("{:x}", region4.addr());

    println!("ready");
    std::thread::sleep(std::time::Duration::from_secs(500));
}

fn memory_chunk_size() {
    // The searched string is "T5aI0uhg7S", and the chunk size is 4MB
    let pattern = b"[:nF?zgh8\\";

    // One page will contain the string, right at the end.
    let mut region1 = Region::zeroed(PAGE_SIZE);
    region1.write_at(PAGE_SIZE - 10, pattern);

    // One page will split the string in two
    let mut region2 = Region::zeroed(2 * PAGE_SIZE + 20);
    region2.write_at(2 * PAGE_SIZE - 5, pattern);

    // One page will contain the string, twice, in two separate chunks
    let mut region3 = Region::zeroed(PAGE_SIZE * 5);
    // First one is right at the 3 * PAGE_SIZE limit
    region3.write_at(3 * PAGE_SIZE - 5, pattern);
    // Second one is after 4 pages
    region3.write_at(4 * PAGE_SIZE + 4096, pattern);

    // Send the base addresses of the region back to the test
    println!("{:x}", region1.addr());
    println!("{:x}", region2.addr());
    println!("{:x}", region3.addr());

    println!("ready");
    std::thread::sleep(std::time::Duration::from_secs(500));
}

fn file_copy_on_write() {
    // Bad pattern, must not be matched
    let bad = b"]NbJ{m^iYJ";
    // Good pattern, must be matched
    let good = b"|{j<Lk6[j7";

    // Create a file, and write "RAmEtbQfVE" in it
    let mut contents = vec![0; 4 * 4096];
    xor_bytes_into(bad, 15, &mut contents[2048..2058]);
    // Map at offset 500
    let mut region1 = Region::copy_on_write(contents, 500);
    // overwrite what is written in it to write "ste3Cd9Te8"
    region1.write_at(2048 - 500, good);

    // New file, with:
    // - the good pattern at 1000
    // - the bad pattern at 4096 - 5 (between two pages)
    // Send the base addresses of the region back to the test
    let mut contents = vec![0; 2 * 4096];
    xor_bytes_into(good, 15, &mut contents[1000..1010]);
    xor_bytes_into(bad, 15, &mut contents[4091..5001]);
    let mut region2 = Region::copy_on_write(contents, 0);
    region2.write_at(4091, good);

    println!("{:x}", region1.addr());
    println!("{:x}", region2.addr());

    println!("ready");
    std::thread::sleep(std::time::Duration::from_secs(500));
}

impl Region {
    fn new(contents: &[u8]) -> Self {
        let mut this = Self::zeroed(contents.len());
        this.write_at(0, contents);
        this
    }

    fn zeroed(size: usize) -> Self {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let contents = vec![0; size];
        file.write_all(&contents).unwrap();
        let map = unsafe { memmap2::MmapMut::map_mut(file.as_file()).unwrap() };

        Self { _file: file, map }
    }

    fn copy_on_write(mut contents: Vec<u8>, offset: u64) -> Self {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&contents).unwrap();

        // Erase contents to not let it live in our RAM.
        for b in &mut contents {
            *b = 0;
        }
        drop(contents);

        let map = unsafe {
            memmap2::MmapOptions::new()
                .offset(offset)
                .map_copy(file.as_file())
                .unwrap()
        };

        Self { _file: file, map }
    }

    fn write_at(&mut self, offset: usize, payload: &[u8]) {
        xor_bytes_into(payload, 15, &mut self.map[offset..(offset + payload.len())]);
    }
}

fn xor_bytes(v: &[u8], xor_byte: u8) -> Vec<u8> {
    v.iter().map(|b| *b ^ xor_byte).collect()
}

fn xor_bytes_into(v: &[u8], xor_byte: u8, dest: &mut [u8]) {
    for (v, d) in v.iter().zip(dest.iter_mut()) {
        *d = *v ^ xor_byte;
    }
}
