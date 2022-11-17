use std::fmt::Write;

use foreign_types_shared::{ForeignType, ForeignTypeRef};
use object::{pe, read::pe::DataDirectories, Bytes, LittleEndian as LE, U16, U32};
use openssl::asn1::{Asn1IntegerRef, Asn1Type};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::{X509NameRef, X509};
use openssl_sys::{
    d2i_PKCS7, OBJ_nid2obj, OBJ_obj2txt, X509_get_signature_nid, ASN1_INTEGER, ASN1_TIME, X509_NAME,
};

use super::Value;

// TODO: add this to openssl-sys and Asn1Integer::to_der to rust-openssl ?
extern "C" {
    pub fn i2d_ASN1_INTEGER(a: *mut ASN1_INTEGER, out: *mut *mut u8) -> std::ffi::c_int;

    pub fn X509_NAME_oneline(a: *mut X509_NAME, buf: *mut u8, size: std::ffi::c_int) -> *mut u8;
}

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
            // TODO: limit on number of certs
            while !cert.is_empty() {
                let pkcs = match MyPkcs7::from_der(&mut cert) {
                    Some(v) => v,
                    None => break,
                };

                let stack = match Stack::new() {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let certs = match pkcs.0.signers(&stack, Pkcs7Flags::empty()) {
                    Ok(v) => v,
                    Err(_) => break,
                };

                // TODO: limit on number of certs
                for cert in certs {
                    signatures.push(x509_to_value(&cert));
                }
            }
        }

        let offset = data.0.as_ptr() as usize - mem.as_ptr() as usize;
        let new_offset = align64(offset);
        data.skip(new_offset - offset).ok()?;
    }

    Some(signatures)
}

struct MyPkcs7(Pkcs7);

impl MyPkcs7 {
    fn from_der(data: &mut &[u8]) -> Option<Self> {
        let mut ptr = data.as_ptr();

        let pkcs7 = unsafe { d2i_PKCS7(std::ptr::null_mut(), &mut ptr, data.len() as i64) };
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
    let not_after = asn1_time_to_ts(cert.not_after().as_ptr());

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
            ("not_before", not_before.and_then(|v| v.try_into().ok())),
            ("not_after", not_after.and_then(|v| v.try_into().ok())),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .collect(),
    )
}

fn get_x509_name(name: &X509NameRef) -> Vec<u8> {
    let mut buf = vec![0; 256];
    let _ = unsafe { X509_NAME_oneline(name.as_ptr(), buf.as_mut_ptr(), buf.len() as _) };

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
    let len = unsafe { i2d_ASN1_INTEGER(serial.as_ptr(), std::ptr::null_mut()) };
    if len <= 2 || len > 22 {
        return None;
    }

    let mut buf = vec![0; len as usize];
    let mut buf_ptr = buf.as_mut_ptr();
    let len = unsafe { i2d_ASN1_INTEGER(serial.as_ptr(), &mut buf_ptr) };
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
        let _ = write!(out, "{:02x}", c);
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

    let time: &Asn1Time = unsafe { &*time.cast() };
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

// This is the object as declared in openssl, but the rust bindings do not expose it
#[repr(C)]
struct Asn1Time {
    length: std::ffi::c_int,
    typ: std::ffi::c_int,
    data: *const u8,
}

// Align offset on 64-bit boundary
const fn align64(offset: usize) -> usize {
    (offset + 7) & !7
}
