//! ASN.1 types definition related to authenticode objects.
//!
//! Those objects come from multiple places:
//!
//! - Most of them are adapted from the `x509-cert`, `spki` and `cms` crates, and modified to:
//!   - replace most owning types with `Ref` variants, to avoid copying data if possible
//!   - replace fields that are unused with `AnyRef`: there is no need to parse those.
//!   - make some parsing less strict. Instead of rejecting some parsing because it is not
//!     supported in the specifications, we would rather allow it as our goal is to parse
//!     files that are in the wild.
//!
//! - Several are created to match microsoft specific objects: the `Spc*` types notably.

// Disable this lint: looks like the `Sequence` derive macro generates an impl that
// triggers this lint. It would be nice to find a fix for this in the `der` crate.
#![allow(single_use_lifetimes)]

use der::{asn1, Choice, Decode, Encode, Reader, Sequence, ValueOrd};
use sha1::Digest;

pub use const_oid::db::rfc5911::{
    ID_COUNTERSIGNATURE, ID_MESSAGE_DIGEST, ID_SIGNED_DATA, ID_SIGNING_TIME,
};
pub use der::asn1::{
    AnyRef, BitStringRef, GeneralizedTime, IntRef, ObjectIdentifier, OctetStringRef, SetOfVec,
    UtcTime,
};

use crate::module::hex_encode;

// Microsoft specific object identifier.
pub const ID_SPC_INDIRECT_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.4");
pub const ID_SPC_SP_OPUS_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.12");
pub const ID_SPC_NESTED_SIGNATURE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.4.1");
pub const ID_COUNTERSIGN: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");
pub const ID_CT_TSTINFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

// Obsolete oid used in some files in place of rfc5912::SHA_1_WITH_RSA_ENCRYPTION
pub const SHA1_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.29");

// Does not exist in const_oid
pub const ECDSA_WITH_SHA_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.1");

// Some object identifiers often used in certificates issuer/subject fields.
pub const JURISDICTION_L: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.60.2.1.1");
pub const JURISDICTION_ST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.60.2.1.2");
pub const JURISDICTION_C: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.60.2.1.3");

/// The `ContentInfo` type is defined in [RFC 5652 Section 3].
///
/// ```text
///   ContentInfo ::= SEQUENCE {
///       contentType        CONTENT-TYPE.
///                       &id({ContentSet}),
///       content            [0] EXPLICIT CONTENT-TYPE.
///                       &Type({ContentSet}{@contentType})}
/// ```
///
/// [RFC 5652 Section 3]: https://www.rfc-editor.org/rfc/rfc5652#section-3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ContentInfo<'a> {
    pub content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub content: AnyRef<'a>,
}

/// The `SignerInfo` type is defined in [RFC 5652 Section 5.3].
///
/// ```text
///   SignerInfo ::= SEQUENCE {
///       version CMSVersion,
///       sid SignerIdentifier,
///       digestAlgorithm DigestAlgorithmIdentifier,
///       signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
///       signatureAlgorithm SignatureAlgorithmIdentifier,
///       signature SignatureValue,
///       unsignedAttrs [1] IMPLICIT Attributes
///           {{UnsignedAttributes}} OPTIONAL }
/// ```
///
/// [RFC 5652 Section 5.3]: https://www.rfc-editor.org/rfc/rfc5652#section-5.3
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct SignerInfo<'a> {
    pub version: u8,
    pub sid: SignerIdentifier<'a>,
    pub digest_alg: AlgorithmIdentifierRef<'a>,
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub signed_attrs: Option<SignedAttrs<'a>>,
    pub signature_algorithm: AlgorithmIdentifierRef<'a>,
    pub signature: OctetStringRef<'a>,
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub unsigned_attrs: Option<AttributesRef<'a>>,
}

impl<'a> SignerInfo<'a> {
    pub fn get_signed_attr(&self, oid: &ObjectIdentifier) -> Option<AnyRef<'a>> {
        let attrs = self.signed_attrs.as_ref()?;
        let attr = attrs.attrs.iter().find(|attr| &attr.oid == oid)?;

        attr.values.iter().next().copied()
    }

    pub fn get_message_digest(&self) -> Option<&'a [u8]> {
        self.get_signed_attr(&ID_MESSAGE_DIGEST).map(AnyRef::value)
    }

    pub fn get_signing_time(&self) -> Option<Time> {
        let value = self.get_signed_attr(&ID_SIGNING_TIME)?;

        if let Ok(v) = value.decode_as::<UtcTime>() {
            Some(Time::UtcTime(v))
        } else if let Ok(v) = value.decode_as::<GeneralizedTime>() {
            Some(Time::GeneralTime(v))
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAttrs<'a> {
    pub attrs: Vec<AttributeRef<'a>>,
    pub value: &'a [u8],
}

impl<'a> der::DecodeValue<'a> for SignedAttrs<'a> {
    fn decode_value<R: Reader<'a>>(decoder: &mut R, header: der::Header) -> der::Result<Self> {
        let mut attrs = Vec::new();
        decoder.read_nested(header.length, |decoder| {
            let value = decoder.read_slice(decoder.remaining_len())?;
            let mut decoder = der::SliceReader::new(value)?;

            while !decoder.is_finished() {
                attrs.push(decoder.decode()?);
            }

            Ok(Self { attrs, value })
        })
    }
}

impl der::EncodeValue for SignedAttrs<'_> {
    fn value_len(&self) -> der::Result<der::Length> {
        self.attrs
            .iter()
            .try_fold(der::Length::ZERO, |len, elem| len + elem.encoded_len()?)
    }

    fn encode_value(&self, writer: &mut impl der::Writer) -> der::Result<()> {
        for elem in &self.attrs {
            elem.encode(writer)?;
        }

        Ok(())
    }
}

impl ValueOrd for SignedAttrs<'_> {
    fn value_cmp(&self, other: &Self) -> der::Result<std::cmp::Ordering> {
        use der::DerOrd;

        let length_ord = self.attrs.len().cmp(&other.attrs.len());

        for (value1, value2) in self.attrs.iter().zip(other.attrs.iter()) {
            match value1.der_cmp(value2)? {
                std::cmp::Ordering::Equal => (),
                other => return Ok(other),
            }
        }

        Ok(length_ord)
    }
}

impl der::FixedTag for SignedAttrs<'_> {
    const TAG: der::Tag = der::Tag::Set;
}

/// The `SignerIdentifier` type is defined in [RFC 5652 Section 5.3].
///
/// ```text
/// SignerIdentifier ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   subjectKeyIdentifier \[0\] SubjectKeyIdentifier }
/// ```
///
/// [RFC 5652 Section 5.3]: https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum SignerIdentifier<'a> {
    IssuerAndSerialNumber(IssuerAndSerialNumber<'a>),

    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    SubjectKeyIdentifier(OctetStringRef<'a>),
}

impl ValueOrd for SignerIdentifier<'_> {
    fn value_cmp(&self, other: &Self) -> der::Result<std::cmp::Ordering> {
        use der::DerOrd;

        self.to_der()?.der_cmp(&other.to_der()?)
    }
}

/// `IssuerAndSerialNumber` structure as defined in [RFC 5652 Section 10.2.4].
///
/// ```text
/// IssuerAndSerialNumber ::= SEQUENCE {
///   issuer Name,
///   serialNumber CertificateSerialNumber }
/// ```
///
/// [RFC 5652 Section 10.2.4]: https://datatracker.ietf.org/doc/html/rfc5652#section-10.2.4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct IssuerAndSerialNumber<'a> {
    pub issuer: NameRef<'a>,
    pub serial_number: IntRef<'a>,
}

/// `SpcSpOpusInfo` object.
///
/// ```text
///  SpcSpOpusInfo ::= SEQUENCE {
///     programName        [0] EXPLICIT SpcString OPTIONAL,
///     moreInfo           [1] EXPLICIT SpcLink OPTIONAL
/// }
/// ```
///
/// <https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/91755632-4b0d-44ca-89a9-9699afbbd268>
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcSpOpusInfo<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub program_name: Option<SpcString<'a>>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub more_info: Option<SpcLink<'a>>,
}

/// `SpcString` object.
///
/// ```text
/// SpcString ::= CHOICE {
///     unicode        [0] IMPLICIT BMPSTRING
/// }
/// ```
///
/// <https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/d5bcc38d-051f-4775-8c44-74d52e301702>
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum SpcString<'a> {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Unicode(asn1::BmpString),
    // This is undocumented, but is used in some binaries
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT")]
    Ascii(asn1::Ia5StringRef<'a>),
}

/// `SpcLink` object.
///
/// ```text
/// SpcLink ::= CHOICE {
///     url        [0] IMPLICIT IA5STRING
/// }
/// ```
///
/// <https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/7cb90c30-902f-48d7-a5ee-686ce1ff0d36>
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum SpcLink<'a> {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Url(asn1::Ia5StringRef<'a>),
}

/// `SpcIndirectDataContent` object.
///
/// ```text
/// SpcIndirectDataContent ::= SEQUENCE {
///     data               SpcAttributeTypeAndOptionalValue,
///     messageDigest      DigestInfo
/// }
/// ```
///
/// <https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/1537695a-28f0-4828-8b7b-d6dab62b8030>
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcIndirectDataContent<'a> {
    pub data: SpcAttributeTypeAndOptionalValue<'a>,
    pub message_digest: DigestInfo<'a>,
}

/// `SpcAttributeTypeAndOptionalValue` object.
///
/// ```text
/// SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
///     type                OBJECT IDENTIFIER,
///     value               [0] EXPLICIT ANY OPTIONAL
/// }
/// ```
///
/// <https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/1537695a-28f0-4828-8b7b-d6dab62b8030>
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpcAttributeTypeAndOptionalValue<'a> {
    pub r#type: ObjectIdentifier,
    pub value: Option<AnyRef<'a>>,
}

/// `DigestInfo` object.
///
/// ```text
/// DigestInfo ::= SEQUENCE {
///     digestAlgorithm    AlgorithmIdentifier,
///     digest             OCTETSTRING
/// }
/// ```
///
/// <https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/1537695a-28f0-4828-8b7b-d6dab62b8030>
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct DigestInfo<'a> {
    pub digest_algorithm: AlgorithmIdentifierRef<'a>,
    pub digest: OctetStringRef<'a>,
}

/// `TstInfo` object.
///
/// ```text
/// TSTInfo ::= SEQUENCE  {
///     version                      INTEGER  { v1(1) },
///     policy                       TSAPolicyId,
///     messageImprint               MessageImprint,
///       -- MUST have the same value as the similar field in
///       -- TimeStampReq
///     serialNumber                 INTEGER,
///       -- Time-Stamping users MUST be ready to accommodate integers
///       -- up to 160 bits.
///     genTime                      GeneralizedTime,
///     accuracy                     Accuracy                 OPTIONAL,
///     ordering                     BOOLEAN             DEFAULT FALSE,
///     nonce                        INTEGER                  OPTIONAL,
///       -- MUST be present if the similar field was present
///       -- in TimeStampReq.  In that case it MUST have the same value.
///     tsa                          [0] GeneralName          OPTIONAL,
///     extensions                   [1] IMPLICIT Extensions   OPTIONAL  }
/// ```
///
/// <https://datatracker.ietf.org/doc/html/rfc3161>
///
/// We only parse up to the genTime because we do not care about the rest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TstInfo<'a> {
    pub version: &'a [u8],
    pub policy: &'a [u8],
    pub message_imprint: MessageImprint<'a>,
    pub serial_number: IntRef<'a>,
    pub gen_time: GeneralizedTimeWithFrac,
    pub remaining: &'a [u8],
}

impl<'a> der::DecodeValue<'a> for TstInfo<'a> {
    fn decode_value<R: Reader<'a>>(decoder: &mut R, header: der::Header) -> der::Result<Self> {
        decoder.read_nested(header.length, |decoder| {
            let version = decoder.tlv_bytes()?;
            let policy = decoder.tlv_bytes()?;
            let message_imprint = decoder.decode()?;
            let serial_number = decoder.decode()?;
            let gen_time = decoder.decode()?;
            // Ignore the rest of the data
            let remaining = decoder.read_slice(decoder.remaining_len())?;

            Ok(Self {
                version,
                policy,
                message_imprint,
                serial_number,
                gen_time,
                remaining,
            })
        })
    }
}

impl der::FixedTag for TstInfo<'_> {
    const TAG: der::Tag = der::Tag::Sequence;
}

/// `GeneralizedTime` but with fractional subsecond precision.
///
/// We do not use this subsecond part, so it is not stored. This exist
/// only to be able to parse properly such values, since `GeneralizedTime`
/// reject them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneralizedTimeWithFrac(pub GeneralizedTime);

impl<'a> der::DecodeValue<'a> for GeneralizedTimeWithFrac {
    fn decode_value<R: Reader<'a>>(decoder: &mut R, header: der::Header) -> der::Result<Self> {
        use der::FixedTag;

        let s = decoder.read_slice(header.length)?;
        if s.len() < 15 || s[s.len() - 1] != b'Z' {
            return Err(Self::TAG.value_error());
        }

        // The slice should look like
        //
        // YYYYMMDDHHMMSS[optional part]Z
        //
        // we ignore the optional part, move the Z right after the seconds and feed this to the
        // GeneralizedTime parser.
        let bytes = [
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12], s[13],
            b'Z',
        ];
        let mut subreader = der::SliceReader::new(&bytes)?;
        GeneralizedTime::decode_value(
            &mut subreader,
            der::Header::new(header.tag, der::Length::new(15))?,
        )
        .map(Self)
    }
}

impl der::FixedTag for GeneralizedTimeWithFrac {
    const TAG: der::Tag = der::Tag::GeneralizedTime;
}

/// `MessageImprint` object.
///
/// ```text
/// MessageImprint ::= SEQUENCE  {
///    hashAlgorithm                AlgorithmIdentifier,
///    hashedMessage                OCTET STRING  }
/// ```
///
/// <https://datatracker.ietf.org/doc/html/rfc3161>
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct MessageImprint<'a> {
    pub hash_algorithm: AlgorithmIdentifierRef<'a>,
    pub hashed_message: OctetStringRef<'a>,
}

/// The `SignedData` type is defined in [RFC 5652 Section 5.1].
///
/// ```text
///   SignedData ::= SEQUENCE {
///       version CMSVersion,
///       digestAlgorithms SET OF DigestAlgorithmIdentifier,
///       encapContentInfo EncapsulatedContentInfo,
///       certificates [0] IMPLICIT CertificateSet OPTIONAL,
///       crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///       signerInfos SignerInfos }
/// ```
///
/// [RFC 5652 Section 5.1]: https://www.rfc-editor.org/rfc/rfc5652#section-5.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SignedData<'a> {
    pub version: u8,
    pub digest_algorithms: SetOfVec<AlgorithmIdentifierRef<'a>>,
    pub encap_content_info: EncapsulatedContentInfo<'a>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub certificates: Option<Certificates<'a>>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub crls: Option<AnyRef<'a>>,
    pub signer_infos: SetOfVec<SignerInfo<'a>>,
}

impl<'a> SignedData<'a> {
    pub fn get_spc_indirect_data(&self) -> Option<SpcIndirectDataContent<'a>> {
        if self.encap_content_info.econtent_type == ID_SPC_INDIRECT_DATA {
            self.encap_content_info.econtent?.decode_as().ok()
        } else {
            None
        }
    }
}

/// The `EncapsulatedContentInfo` type is defined in [RFC 5652 Section 5.2].
///
/// ```text
///   EncapsulatedContentInfo ::= SEQUENCE {
///       eContentType       CONTENT-TYPE.&id({ContentSet}),
///       eContent           [0] EXPLICIT OCTET STRING
///               ( CONTAINING CONTENT-TYPE.
///                   &Type({ContentSet}{@eContentType})) OPTIONAL }
/// ```
///
/// [RFC 5652 Section 5.2]: https://www.rfc-editor.org/rfc/rfc5652#section-5.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EncapsulatedContentInfo<'a> {
    pub econtent_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub econtent: Option<AnyRef<'a>>,
}

/// Set of certificates.
///
/// Wrapper types to replace `SetOfVec<Certificate>`.
///
/// This allows capturing the der encoding of each certificate, and computing
/// the thumbprint of those certificates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificates<'a>(pub Vec<CertificateWithThumbprint<'a>>);

impl<'a> der::DecodeValue<'a> for Certificates<'a> {
    fn decode_value<R: Reader<'a>>(decoder: &mut R, header: der::Header) -> der::Result<Self> {
        decoder.read_nested(header.length, |decoder| {
            let mut res = Vec::new();

            while !decoder.is_finished() {
                let der = decoder.tlv_bytes()?;
                let thumbprint = hex_encode(sha1::Sha1::digest(der));

                // Be lax about errors here: our Certificate decoding info is not complete and
                // obsolete certificates might not parse correctly: we want to ignore them in this
                // case, and not make the decoding of the whole set fail.
                match Certificate::from_der(der) {
                    Ok(cert) => res.push(CertificateWithThumbprint { cert, thumbprint }),
                    Err(_) => break,
                }
            }

            Ok(Self(res))
        })
    }
}

impl der::EncodeValue for Certificates<'_> {
    fn value_len(&self) -> der::Result<der::Length> {
        self.0.iter().try_fold(der::Length::ZERO, |len, elem| {
            len + elem.cert.encoded_len()?
        })
    }

    fn encode_value(&self, writer: &mut impl der::Writer) -> der::Result<()> {
        for elem in &self.0 {
            elem.cert.encode(writer)?;
        }

        Ok(())
    }
}

impl der::FixedTag for Certificates<'_> {
    const TAG: der::Tag = der::Tag::Set;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateWithThumbprint<'a> {
    pub cert: Certificate<'a>,
    pub thumbprint: Vec<u8>,
}

/// X.509 `AlgorithmIdentifier` as defined in [RFC 5280 Section 4.1.1.2].
///
/// ```text
/// AlgorithmIdentifier  ::=  SEQUENCE  {
///      algorithm               OBJECT IDENTIFIER,
///      parameters              ANY DEFINED BY algorithm OPTIONAL  }
/// ```
///
/// [RFC 5280 Section 4.1.1.2]: https://tools.ietf.org/html/rfc5280#section-4.1.1.2
#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct AlgorithmIdentifierRef<'a> {
    /// Algorithm OID, i.e. the `algorithm` field in the `AlgorithmIdentifier`
    /// ASN.1 schema.
    pub oid: ObjectIdentifier,

    /// Algorithm `parameters`.
    pub parameters: Option<AnyRef<'a>>,
}

/// X.501 `AttributeType` as defined in [RFC 5280 Appendix A.1].
///
/// ```text
/// AttributeType           ::= OBJECT IDENTIFIER
/// ```
///
/// [RFC 5280 Appendix A.1]: https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1
pub type AttributeType = ObjectIdentifier;

/// X.501 `AttributeValue` as defined in [RFC 5280 Appendix A.1].
///
/// ```text
/// AttributeValue          ::= ANY
/// ```
///
/// [RFC 5280 Appendix A.1]: https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1
pub type AttributeValueRef<'a> = AnyRef<'a>;

/// X.501 `Attribute` as defined in [RFC 5280 Appendix A.1].
///
/// ```text
/// Attribute               ::= SEQUENCE {
///     type             AttributeType,
///     values    SET OF AttributeValue -- at least one value is required
/// }
/// ```
///
/// Note that [RFC 2986 Section 4] defines a constrained version of this type:
///
/// ```text
/// Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
///     type   ATTRIBUTE.&id({IOSet}),
///     values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
/// }
/// ```
///
/// The unconstrained version should be preferred.
///
/// [RFC 2986 Section 4]: https://datatracker.ietf.org/doc/html/rfc2986#section-4
/// [RFC 5280 Appendix A.1]: https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1
#[derive(Clone, Debug, PartialEq, Eq, Sequence, ValueOrd)]
pub struct AttributeRef<'a> {
    pub oid: AttributeType,
    pub values: SetOfVec<AttributeValueRef<'a>>,
}

/// X.501 `Attributes` as defined in [RFC 2986 Section 4].
///
/// ```text
/// Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
/// ```
///
/// [RFC 2986 Section 4]: https://datatracker.ietf.org/doc/html/rfc2986#section-4
pub type AttributesRef<'a> = SetOfVec<AttributeRef<'a>>;

/// X.501 `AttributeTypeAndValue` as defined in [RFC 5280 Appendix A.1].
///
/// ```text
/// AttributeTypeAndValue ::= SEQUENCE {
///   type     AttributeType,
///   value    AttributeValue
/// }
/// ```
///
/// [RFC 5280 Appendix A.1]: https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct AttributeTypeAndValueRef<'a> {
    pub oid: AttributeType,
    pub value: AttributeValueRef<'a>,
}

/// X.509 `TbsCertificate` as defined in [RFC 5280 Section 4.1]
///
/// ASN.1 structure containing the names of the subject and issuer, a public
/// key associated with the subject, a validity period, and other associated
/// information.
///
/// ```text
/// TBSCertificate  ::=  SEQUENCE  {
///     version         [0]  EXPLICIT Version DEFAULT v1,
///     serialNumber         CertificateSerialNumber,
///     signature            AlgorithmIdentifier,
///     issuer               Name,
///     validity             Validity,
///     subject              Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,
///     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///                          -- If present, version MUST be v2 or v3
///     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///                          -- If present, version MUST be v2 or v3
///     extensions      [3]  Extensions OPTIONAL
///                          -- If present, version MUST be v3 --
/// }
/// ```
///
/// [RFC 5280 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct TbsCertificate<'a> {
    #[asn1(context_specific = "0", default = "u8::default")]
    pub version: u8,

    pub serial_number: IntRef<'a>,
    pub signature: AlgorithmIdentifierRef<'a>,
    pub issuer: NameRef<'a>,
    pub validity: Validity,
    pub subject: NameRef<'a>,
    pub subject_public_key_info: AnyRef<'a>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub issuer_unique_id: Option<BitStringRef<'a>>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub subject_unique_id: Option<BitStringRef<'a>>,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub extensions: Option<AnyRef<'a>>,
}

/// X.509 certificates are defined in [RFC 5280 Section 4.1].
///
/// ```text
/// Certificate  ::=  SEQUENCE  {
///     tbsCertificate       TBSCertificate,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signature            BIT STRING
/// }
/// ```
///
/// [RFC 5280 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate<'a> {
    pub tbs_certificate: TbsCertificate<'a>,
    pub cert_raw: &'a [u8],
    pub signature_algorithm: AlgorithmIdentifierRef<'a>,
    pub signature: BitStringRef<'a>,
}

impl<'a> der::DecodeValue<'a> for Certificate<'a> {
    fn decode_value<R: Reader<'a>>(decoder: &mut R, header: der::Header) -> der::Result<Self> {
        decoder.read_nested(header.length, |decoder| {
            let cert_raw = decoder.tlv_bytes()?;
            let tbs_certificate = TbsCertificate::from_der(cert_raw)?;
            let signature_algorithm = decoder.decode()?;
            let signature = decoder.decode()?;

            Ok(Self {
                tbs_certificate,
                cert_raw,
                signature_algorithm,
                signature,
            })
        })
    }
}

impl der::EncodeValue for Certificate<'_> {
    fn value_len(&self) -> der::Result<der::Length> {
        self.tbs_certificate.encoded_len()?
            + self.signature_algorithm.encoded_len()?
            + self.signature.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl der::Writer) -> der::Result<()> {
        self.tbs_certificate.encode(writer)?;
        self.signature_algorithm.encode(writer)?;
        self.signature.encode(writer)?;

        Ok(())
    }
}

impl der::FixedTag for Certificate<'_> {
    const TAG: der::Tag = der::Tag::Sequence;
}

/// X.501 `Validity` as defined in [RFC 5280 Section 4.1.2.5]
///
/// ```text
/// Validity ::= SEQUENCE {
///     notBefore      Time,
///     notAfter       Time
/// }
/// ```
/// [RFC 5280 Section 4.1.2.5]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5
#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct Validity {
    /// notBefore value
    pub not_before: Time,

    /// notAfter value
    pub not_after: Time,
}

/// X.501 `Time` as defined in [RFC 5280 Section 4.1.2.5].
///
/// Schema definition from [RFC 5280 Appendix A]:
///
/// ```text
/// Time ::= CHOICE {
///      utcTime        UTCTime,
///      generalTime    GeneralizedTime
/// }
/// ```
///
/// [RFC 5280 Section 4.1.2.5]: https://tools.ietf.org/html/rfc5280#section-4.1.2.5
/// [RFC 5280 Appendix A]: https://tools.ietf.org/html/rfc5280#page-117
#[derive(Choice, Copy, Clone, Debug, Eq, PartialEq, ValueOrd)]
pub enum Time {
    /// Legacy UTC time (has 2-digit year, valid from 1970 to 2049).
    ///
    /// Note: RFC 5280 specifies 1950-2049, however due to common operations working on
    /// `UNIX_EPOCH` this implementation's lower bound is 1970.
    #[asn1(type = "UTCTime")]
    UtcTime(UtcTime),

    /// Modern [`GeneralizedTime`] encoding with 4-digit year.
    #[asn1(type = "GeneralizedTime")]
    GeneralTime(GeneralizedTime),
}

/// X.501 Name as defined in [RFC 5280 Section 4.1.2.4]. X.501 Name is used to represent distinguished names.
///
/// ```text
/// Name ::= CHOICE { rdnSequence  RDNSequence }
/// ```
///
/// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
pub type NameRef<'a> = RdnSequenceRef<'a>;

/// X.501 `RDNSequence` as defined in [RFC 5280 Section 4.1.2.4].
///
/// ```text
/// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
/// ```
///
/// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
pub type RdnSequenceRef<'a> = Vec<RelativeDistinguishedNameRef<'a>>;

/// `RelativeDistinguishedName` as defined in [RFC 5280 Section 4.1.2.4].
///
/// ```text
/// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
/// ```
///
/// Note that we follow the more common definition above. This technically
/// differs from the definition in X.501, which is:
///
/// ```text
/// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndDistinguishedValue
///
/// AttributeTypeAndDistinguishedValue ::= SEQUENCE {
///     type ATTRIBUTE.&id ({SupportedAttributes}),
///     value ATTRIBUTE.&Type({SupportedAttributes}{@type}),
///     primaryDistinguished BOOLEAN DEFAULT TRUE,
///     valuesWithContext SET SIZE (1..MAX) OF SEQUENCE {
///         distingAttrValue [0] ATTRIBUTE.&Type ({SupportedAttributes}{@type}) OPTIONAL,
///         contextList SET SIZE (1..MAX) OF Context
///     } OPTIONAL
/// }
/// ```
///
/// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
pub type RelativeDistinguishedNameRef<'a> = SetOfVec<AttributeTypeAndValueRef<'a>>;
