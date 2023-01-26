use std::fmt::Write;

use foreign_types_shared::{ForeignType, ForeignTypeRef};
use object::{pe, read::pe::DataDirectories, Bytes, LittleEndian as LE, U16, U32};
use openssl::asn1::{Asn1IntegerRef, Asn1StringRef, Asn1Type};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::{X509NameRef, X509};
use openssl_sys::{
    d2i_PKCS7, OBJ_nid2obj, OBJ_obj2txt, OBJ_txt2obj, OPENSSL_sk_value, X509_get_signature_nid,
    ASN1_TIME,
};

use super::Value;

const MAX_PE_CERTS: usize = 16;

pub fn get_signatures(data_dirs: &DataDirectories, mem: &[u8]) -> Option<Vec<Value>> {
    let dir = data_dirs.get(pe::IMAGE_DIRECTORY_ENTRY_SECURITY)?;
    let (va, size) = dir.address_range();
    let va = va as usize;
    let size = size as usize;
    let end = va.checked_add(size)?;

    if va == 0 {
        return None;
    }

    let mut data = Bytes(mem.get(va..end)?);
    let mut signatures = Vec::new();

    // Data contains a list of WIN_CERTIFICATE objects:
    // <https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-win_certificate>
    // Each subsequent one is aligned on a 8-bytes boundary.
    while !data.is_empty() {
        let mut length: u32 = data.read::<U32<LE>>().ok()?.get(LE);
        // length contains the length + rev + type, so remove it
        if length <= 8 {
            break;
        }
        length -= 8;

        let rev: u16 = data.read::<U16<LE>>().ok()?.get(LE);
        let cert_type: u16 = data.read::<U16<LE>>().ok()?.get(LE);
        let mut cert = data.read_slice::<u8>(length as usize).ok()?;

        // revision is 2.0 and cert type is PKCS_SIGNED_DATA
        if rev == 0x0200 && cert_type == 0x0002 {
            while !cert.is_empty() && signatures.len() < MAX_PE_CERTS {
                if !add_signatures_from_pkcs7_der(&mut cert, &mut signatures) {
                    break;
                }
            }
        }

        let offset = data.0.as_ptr() as usize - mem.as_ptr() as usize;
        let new_offset = align64(offset);
        data.skip(new_offset - offset).ok()?;
    }

    Some(signatures)
}

fn add_signatures_from_pkcs7_der(data: &mut &[u8], signatures: &mut Vec<Value>) -> bool {
    let pkcs = match MyPkcs7::from_der(data) {
        Some(v) => v,
        None => return false,
    };

    let stack = match Stack::new() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let certs = match pkcs.0.signers(&stack, Pkcs7Flags::empty()) {
        Ok(v) => v,
        Err(_) => return false,
    };

    for cert in certs {
        if signatures.len() >= MAX_PE_CERTS {
            break;
        }
        signatures.push(x509_to_value(&cert));
    }

    // Detect nested signatures
    add_nested_signatures(&pkcs, signatures);

    true
}

fn add_nested_signatures(pkcs: &MyPkcs7, signatures: &mut Vec<Value>) {
    const SPC_NESTED_SIGNATURE_OBJID: &str = "1.3.6.1.4.1.311.2.4.1\0";

    let signer_info = unsafe { sys::PKCS7_get_signer_info(pkcs.0.as_ptr()) };
    if signer_info.is_null() {
        return;
    }
    let signer_info = unsafe { OPENSSL_sk_value(signer_info.cast(), 0) };
    if signer_info.is_null() {
        return;
    }
    let signer_info: &sys::PKCS7SignerInfo = unsafe { &*(signer_info.cast()) };
    let attrs = signer_info.unauth_attr;
    let idx = unsafe {
        sys::X509at_get_attr_by_OBJ(
            attrs,
            OBJ_txt2obj(SPC_NESTED_SIGNATURE_OBJID.as_ptr().cast(), 1),
            -1,
        )
    };
    let xa = unsafe { sys::X509at_get_attr(attrs, idx) };
    if xa.is_null() {
        return;
    }
    for i in 0..MAX_PE_CERTS {
        let nested = unsafe { sys::X509_ATTRIBUTE_get0_type(xa, i as i32) };
        if nested.is_null() {
            break;
        }
        let nested: &sys::MyAsn1Type = unsafe { &*nested.cast() };
        if nested.typ != Asn1Type::SEQUENCE.as_raw() {
            break;
        }

        let seq = unsafe { Asn1StringRef::from_ptr(nested.sequence) };
        let mut data = seq.as_slice();
        let _ = add_signatures_from_pkcs7_der(&mut data, signatures);
        if signatures.len() >= MAX_PE_CERTS {
            break;
        }
    }
}

struct MyPkcs7(Pkcs7);

impl MyPkcs7 {
    // Same as Pkcs7::from_der, but update the slice to point to after the pkcs7. This allows
    // parsing all certificates from the slice which is supposed to be an array.
    fn from_der(data: &mut &[u8]) -> Option<Self> {
        let mut ptr = data.as_ptr();

        let pkcs7 = unsafe { d2i_PKCS7(std::ptr::null_mut(), &mut ptr, data.len() as _) };
        *data = &data[(ptr as usize - data.as_ptr() as usize)..];

        if pkcs7.is_null() {
            None
        } else {
            Some(Self(unsafe { Pkcs7::from_ptr(pkcs7) }))
        }
    }
}

fn x509_to_value(cert: &X509) -> Value {
    // 0 means version 1, etc
    let version = cert.version() + 1;
    let serial_number = serial_number_to_string(cert.serial_number());
    let digest = cert.digest(MessageDigest::sha1()).ok();

    let not_before = asn1_time_to_ts(cert.not_before().as_ptr());
    let not_before = not_before.and_then(|v| i64::try_from(v).ok());
    let not_after = asn1_time_to_ts(cert.not_after().as_ptr());
    let not_after = not_after.and_then(|v| i64::try_from(v).ok());

    let sig_nid = Nid::from_raw(unsafe { X509_get_signature_nid(cert.as_ptr()) });

    Value::Object(
        [
            ("subject", Some(get_x509_name(cert.subject_name()).into())),
            ("issuer", Some(get_x509_name(cert.issuer_name()).into())),
            (
                "algorithm",
                sig_nid
                    .long_name()
                    .ok()
                    .map(|v| v.to_owned().into_bytes().into()),
            ),
            ("algorithm_oid", get_nid_oid(&sig_nid).map(Into::into)),
            (
                "thumbprint",
                digest.map(|v| hex::encode(v).into_bytes().into()),
            ),
            ("version", Some(version.into())),
            ("serial", serial_number.map(|v| v.into_bytes().into())),
            ("not_before", not_before.map(Into::into)),
            ("not_after", not_after.map(Into::into)),
            (
                "valid_on",
                Some(Value::function(move |_, args| {
                    valid_on(args, not_before, not_after)
                })),
            ),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .collect(),
    )
}

fn get_x509_name(name: &X509NameRef) -> Vec<u8> {
    let mut buf = vec![0; 256];
    let _ = unsafe { sys::X509_NAME_oneline(name.as_ptr(), buf.as_mut_ptr(), buf.len() as _) };

    let len = buf.iter().position(|v| *v == 0).unwrap_or(buf.len());
    buf.truncate(len);
    buf
}

fn get_nid_oid(nid: &Nid) -> Option<Vec<u8>> {
    let obj = unsafe { OBJ_nid2obj(nid.as_raw()) };
    if obj.is_null() {
        return None;
    }

    let mut buf = [0; 256];
    let len = unsafe { OBJ_obj2txt(buf.as_mut_ptr(), buf.len() as _, obj, 1) };
    if len <= 0 {
        None
    } else {
        let bytes = &buf[..std::cmp::min(len as usize, buf.len())];
        Some(bytes.iter().map(|v| *v as u8).collect())
    }
}

fn serial_number_to_string(serial: &Asn1IntegerRef) -> Option<String> {
    let len = unsafe { sys::i2d_ASN1_INTEGER(serial.as_ptr(), std::ptr::null_mut()) };
    if len <= 2 || len > 22 {
        return None;
    }

    let mut buf = vec![0; len as usize];
    let mut buf_ptr = buf.as_mut_ptr();
    let len = unsafe { sys::i2d_ASN1_INTEGER(serial.as_ptr(), &mut buf_ptr) };
    if len <= 0 {
        return None;
    }

    let len = len as usize;
    let mut out = String::with_capacity(len * 3);
    // Skip DER type and length information
    for (i, c) in buf[2..].iter().enumerate().take(len - 2) {
        if i != 0 {
            out.push(':');
        }
        let _ = write!(out, "{c:02x}");
    }

    Some(out)
}

// Copied from libyara pe_utils.c
fn asn1_time_to_ts(time: *mut ASN1_TIME) -> Option<u64> {
    const NDAYS_NON_LEAP: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    const NDAYS_LEAP: [u64; 12] = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    if time.is_null() {
        return None;
    }

    let time: &sys::Asn1Time = unsafe { &*time.cast() };
    let mut res: u64 = 0;
    let data: &[u8] = unsafe { std::slice::from_raw_parts(time.data, time.length as usize) };
    let mut iter = data.iter().map(|v| u64::from(*v - b'0'));

    let mut year = 0;
    if time.typ == Asn1Type::UTCTIME.as_raw() {
        // Format is YYmmddHHMMSS
        year += iter.next()? * 10;
        year += iter.next()?;
        if year < 70 {
            year += 100;
        }
    } else if time.typ == Asn1Type::GENERALIZEDTIME.as_raw() {
        // Format is YYYYmmddHHMMSS
        year += iter.next()? * 1000;
        year += iter.next()? * 100;
        year += iter.next()? * 10;
        year += iter.next()?;
        year -= 1900;
    }
    for i in 70..year {
        res += if is_leap(i) { 366 } else { 365 };
    }

    let month = iter.next()? * 10 + iter.next()? - 1;
    for i in 0..month {
        res += if is_leap(year) {
            NDAYS_LEAP[i as usize]
        } else {
            NDAYS_NON_LEAP[i as usize]
        };
    }

    // Add the ddHHMMSS
    res += (iter.next()? * 10 + iter.next()?) - 1;
    res *= 24;
    res += iter.next()? * 10 + iter.next()?;
    res *= 60;
    res += iter.next()? * 10 + iter.next()?;
    res *= 60;
    res += iter.next()? * 10 + iter.next()?;

    Some(res)
}

fn is_leap(mut year: u64) -> bool {
    year += 1900;
    (year % 4) == 0 && ((year % 100) != 0 || (year % 400) == 0)
}

// Align offset on 64-bit boundary
const fn align64(offset: usize) -> usize {
    (offset + 7) & !7
}

fn valid_on(args: Vec<Value>, not_before: Option<i64>, not_after: Option<i64>) -> Option<Value> {
    let mut args = args.into_iter();
    let timestamp: i64 = args.next()?.try_into().ok()?;

    match (not_before, not_after) {
        (Some(not_before), Some(not_after)) => Some(Value::Boolean(
            timestamp >= not_before && timestamp <= not_after,
        )),
        _ => None,
    }
}

// sys bindings for openssl that are missing from openssl-sys
mod sys {
    use openssl_sys::{
        stack_st_X509_ATTRIBUTE, ASN1_INTEGER, ASN1_OBJECT, ASN1_STRING, ASN1_TYPE, PKCS7,
        X509_NAME,
    };
    use std::os::raw::{c_int, c_void};

    extern "C" {
        pub fn i2d_ASN1_INTEGER(a: *mut ASN1_INTEGER, out: *mut *mut u8) -> c_int;

        pub fn X509_NAME_oneline(a: *mut X509_NAME, buf: *mut u8, size: c_int) -> *mut u8;

        pub fn PKCS7_get_signer_info(p7: *mut PKCS7) -> *mut c_void;

        pub fn X509at_get_attr_by_OBJ(
            sk: *const stack_st_X509_ATTRIBUTE,
            obj: *const ASN1_OBJECT,
            lastpos: c_int,
        ) -> c_int;

        pub fn X509at_get_attr(x: *const stack_st_X509_ATTRIBUTE, loc: c_int)
            -> *mut X509Attribute;

        pub fn X509_ATTRIBUTE_get0_type(attr: *mut X509Attribute, idx: c_int) -> *mut ASN1_TYPE;
    }

    pub enum X509Attribute {}

    #[repr(C)]
    pub struct PKCS7SignerInfo {
        // We only care about the unauth_attr field. The previous ones are all pointers, so just
        // group them, alignment and offset is the same.
        pub _ignore: [*const c_void; 6],
        pub unauth_attr: *mut stack_st_X509_ATTRIBUTE,
    }

    #[repr(C)]
    pub struct MyAsn1Type {
        pub typ: c_int,
        // This is a union, of which we only care about the sequence. typ should be 16
        // (V_ASN1_SEQUENCE) to access this.
        pub sequence: *mut ASN1_STRING,
    }

    #[repr(C)]
    pub struct Asn1Time {
        pub length: c_int,
        pub typ: c_int,
        pub data: *const u8,
    }
}
