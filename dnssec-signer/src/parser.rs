use std::collections::BTreeMap;
use std::str::FromStr;
use base64::Engine;
use trust_dns_proto::error::*;
use trust_dns_client::error::*;
use trust_dns_proto::rr::dnssec::rdata::{DNSSECRData, DNSKEY, NSEC3PARAM, NSEC3, SIG};
use trust_dns_client::rr::{DNSClass, LowerName, Name, RData, Record, RecordSet, RrKey};
use trust_dns_client::rr::rdata::{NULL};
use trust_dns_client::rr::RecordType as TrustRecordType;
use trust_dns_client::serialize::txt::RDataParser;
use trust_dns_client::serialize::txt::Token;
use trust_dns_proto::rr::domain::Label;
use crate::lexer::Lexer;
use trust_dns_proto::serialize::binary::{BinEncodable, BinEncoder};

#[derive(Clone, Copy, Default)]
pub struct Parser;

#[allow(unused)]
enum State {
    StartLine,    // start of line, @, $<WORD>, Name, Blank
    TtlClassType, // [<TTL>] [<class>] <type>,
    Ttl,          // $TTL <time>
    Record(Vec<String>),
    Include, // $INCLUDE <filename>
    Origin,
}

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
#[allow(dead_code)]
#[non_exhaustive]
pub enum RecordType {
    A,
    AAAA,
    ANAME,
    //  AFSDB,      //	18	RFC 1183	AFS database record
    ANY,
    //  APL,        //	42	RFC 3123	Address Prefix List
    AXFR,
    CAA,
    CDS,
    CDNSKEY,
    //  CERT,       // 37 RFC 4398 Certificate record
    CNAME,
    DHCID,
    //  DLV,        //	32769	RFC 4431	DNSSEC Lookaside Validation record
    //  DNAME,      // 39 RFC 2672 Delegation Name
    DNAME,
    CSYNC,
    DNSKEY,
    DS,
    HINFO,
    //  HIP,        // 55 RFC 5205 Host Identity Protocol
    HTTPS,
    //  IPSECKEY,   // 45 RFC 4025 IPsec Key
    IXFR,
    //  KX,         // 36 RFC 2230 Key eXchanger record
    KEY,
    //  LOC,        // 29 RFC 1876 Location record
    LOC,
    MX,
    NAPTR,
    NS,
    NSEC,
    NSEC3,
    NSEC3PARAM,
    NULL,
    OPENPGPKEY,
    OPT,
    PTR,
    RP,
    RRSIG,
    SIG,
    SOA,
    SRV,
    SSHFP,
    SVCB,
    //  TA,         // 32768 N/A DNSSEC Trust Authorities
    //  TKEY,       // 249 RFC 2930 Secret key record
    TLSA,
    TSIG,
    TXT,
    Unknown(u16),
    ZERO,
}

impl RecordType {
    fn to_trust(&self) -> TrustRecordType {
        match self {
            Self::A => TrustRecordType::A,
            Self::AAAA => TrustRecordType::AAAA,
            Self::ANAME => TrustRecordType::ANAME,
            Self::ANY => TrustRecordType::ANY,
            Self::AXFR => TrustRecordType::AXFR,
            Self::CAA => TrustRecordType::CAA,
            Self::CDS => TrustRecordType::CDS,
            Self::CDNSKEY => TrustRecordType::CDNSKEY,
            Self::CNAME => TrustRecordType::CNAME,
            Self::DHCID => TrustRecordType::Unknown(49),
            Self::DNAME => TrustRecordType::Unknown(39),
            Self::CSYNC => TrustRecordType::CSYNC,
            Self::DNSKEY => TrustRecordType::DNSKEY,
            Self::DS => TrustRecordType::DS,
            Self::HINFO => TrustRecordType::HINFO,
            Self::HTTPS => TrustRecordType::HTTPS,
            Self::IXFR => TrustRecordType::IXFR,
            Self::KEY => TrustRecordType::KEY,
            Self::LOC => TrustRecordType::Unknown(29),
            Self::MX => TrustRecordType::MX,
            Self::NAPTR => TrustRecordType::NAPTR,
            Self::NS => TrustRecordType::NS,
            Self::NSEC => TrustRecordType::NSEC,
            Self::NSEC3 => TrustRecordType::NSEC3,
            Self::NSEC3PARAM => TrustRecordType::NSEC3PARAM,
            Self::NULL => TrustRecordType::NULL,
            Self::OPENPGPKEY => TrustRecordType::OPENPGPKEY,
            Self::OPT => TrustRecordType::OPT,
            Self::PTR => TrustRecordType::PTR,
            Self::RP => TrustRecordType::Unknown(17),
            Self::RRSIG => TrustRecordType::RRSIG,
            Self::SIG => TrustRecordType::SIG,
            Self::SOA => TrustRecordType::SOA,
            Self::SRV => TrustRecordType::SRV,
            Self::SSHFP => TrustRecordType::SSHFP,
            Self::SVCB => TrustRecordType::SVCB,
            Self::TLSA => TrustRecordType::TLSA,
            Self::TSIG => TrustRecordType::TSIG,
            Self::TXT => TrustRecordType::TXT,
            Self::Unknown(u) => TrustRecordType::Unknown(*u),
            Self::ZERO => TrustRecordType::ZERO,
        }
    }
}

impl FromStr for RecordType {
    type Err = ProtoError;

    fn from_str(str: &str) -> ProtoResult<Self> {
        debug_assert!(str.chars().all(|x| char::is_digit(x, 36)));
        match str {
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::AAAA),
            "ANAME" => Ok(Self::ANAME),
            "AXFR" => Ok(Self::AXFR),
            "CAA" => Ok(Self::CAA),
            "CDNSKEY" => Ok(Self::CDNSKEY),
            "CDS" => Ok(Self::CDS),
            "CNAME" => Ok(Self::CNAME),
            "CSYNC" => Ok(Self::CSYNC),
            "DHCID" => Ok(Self::DHCID),
            "DNSKEY" => Ok(Self::DNSKEY),
            "DS" => Ok(Self::DS),
            "HINFO" => Ok(Self::HINFO),
            "HTTPS" => Ok(Self::HTTPS),
            "KEY" => Ok(Self::KEY),
            "LOC" => Ok(Self::LOC),
            "MX" => Ok(Self::MX),
            "NAPTR" => Ok(Self::NAPTR),
            "NSEC" => Ok(Self::NSEC),
            "NSEC3" => Ok(Self::NSEC3),
            "NSEC3PARAM" => Ok(Self::NSEC3PARAM),
            "NS" => Ok(Self::NS),
            "NULL" => Ok(Self::NULL),
            "OPENPGPKEY" => Ok(Self::OPENPGPKEY),
            "PTR" => Ok(Self::PTR),
            "RP" => Ok(Self::RP),
            "RRSIG" => Ok(Self::RRSIG),
            "SIG" => Ok(Self::SIG),
            "SOA" => Ok(Self::SOA),
            "SRV" => Ok(Self::SRV),
            "SSHFP" => Ok(Self::SSHFP),
            "SVCB" => Ok(Self::SVCB),
            "TLSA" => Ok(Self::TLSA),
            "TXT" => Ok(Self::TXT),
            "TSIG" => Ok(Self::TSIG),
            "ANY" | "*" => Ok(Self::ANY),
            o => {
                if o.starts_with("TYPE") {
                    let code = o[4..].parse::<u16>()?;
                    Ok(Self::Unknown(code))
                } else {
                    Err(ProtoErrorKind::UnknownRecordTypeStr(str.to_string()).into())
                }
            },
        }
    }
}

impl Parser {
    pub fn new() -> Self {
        Parser
    }

    pub fn parse(
        &mut self,
        mut lexer: Lexer<'_>,
        mut origin: Name,
        mut class: DNSClass,
    ) -> ParseResult<(Name, BTreeMap<RrKey, RecordSet>)> {
        let mut records: BTreeMap<RrKey, RecordSet> = BTreeMap::new();

        let mut current_name: Option<Name> = None;
        let mut rtype: Option<RecordType> = None;
        let mut ttl: Option<u32> = None;
        let mut state = State::StartLine;

        while let Some(t) = lexer.next_token()? {
            state = match state {
                State::StartLine => {
                    // current_name is not reset on the next line b/c it might be needed from the previous
                    rtype = None;

                    match t {
                        // if Dollar, then $INCLUDE or $ORIGIN
                        Token::Include => {
                            return Err(ParseError::from(ParseErrorKind::Message("The parser does not support $INCLUDE. Consider inlining file before parsing")))
                        },
                        Token::Origin => State::Origin,
                        Token::Ttl => State::Ttl,

                        // if CharData, then Name then ttl_class_type
                        Token::CharData(data) => {
                            current_name = Some(name_from_encoded_str(&data, Some(&origin))?);
                            State::TtlClassType
                        }

                        // @ is a placeholder for specifying the current origin
                        Token::At => {
                            current_name = Some(origin.clone());
                            State::TtlClassType
                        }

                        // if blank, then nothing or ttl_class_type
                        Token::Blank => State::TtlClassType,
                        Token::EOL => State::StartLine, // probably a comment
                        _ => return Err(ParseErrorKind::UnexpectedToken(t).into()),
                    }
                }
                State::Ttl => match t {
                    Token::CharData(data) => {
                        ttl = Some(trust_dns_client::serialize::txt::Parser::parse_time(&data)?);
                        State::StartLine
                    }
                    _ => return Err(ParseErrorKind::UnexpectedToken(t).into()),
                },
                State::Origin => {
                    match t {
                        Token::CharData(data) => {
                            origin = Name::parse(&data, None)?;
                            State::StartLine
                        }
                        _ => return Err(ParseErrorKind::UnexpectedToken(t).into()),
                    }
                }
                State::Include => return Err(ParseError::from(ParseErrorKind::Message(
                    "The parser does not support $INCLUDE. Consider inlining file before parsing",
                ))),
                State::TtlClassType => {
                    match t {
                        // if number, TTL
                        // Token::Number(ref num) => ttl = Some(*num),
                        // One of Class or Type (these cannot be overlapping!)
                        Token::CharData(mut data) => {
                            // if it's a number it's a ttl
                            let result: ParseResult<u32> = trust_dns_client::serialize::txt::Parser::parse_time(&data);
                            if result.is_ok() {
                                ttl = result.ok();
                                State::TtlClassType // hm, should this go to just ClassType?
                            } else {
                                // if can parse DNSClass, then class
                                data.make_ascii_uppercase();
                                if data.chars().any(|x| !char::is_ascii_uppercase(&x)) {
                                    rtype = Some(RecordType::from_str(&data)?);
                                    State::Record(vec![])
                                } else {
                                    let result = DNSClass::from_str(&data);
                                    if result.is_ok() {
                                        class = result.unwrap();
                                        State::TtlClassType
                                    } else {
                                        // if can parse RecordType, then RecordType
                                        rtype = Some(RecordType::from_str(&data)?);
                                        State::Record(vec![])
                                    }
                                }
                            }
                        }
                        // could be nothing if started with blank and is a comment, i.e. EOL
                        Token::EOL => {
                            State::StartLine // next line
                        }
                        _ => return Err(ParseErrorKind::UnexpectedToken(t).into()),
                    }
                }
                State::Record(record_parts) => {
                    // b/c of ownership rules, perhaps, just collect all the RData components as a list of
                    //  tokens to pass into the processor

                    match t {
                        Token::EOL => {
                            Self::flush_record(
                                record_parts,
                                &origin,
                                &current_name,
                                rtype,
                                &mut ttl,
                                class,
                                &mut records,
                            )?;
                            State::StartLine
                        }
                        Token::CharData(part) => {
                            let mut record_parts = record_parts;
                            record_parts.push(part);
                            State::Record(record_parts)
                        }
                        // TODO: we should not tokenize the list...
                        Token::List(list) => {
                            let mut record_parts = record_parts;
                            record_parts.extend(list);
                            State::Record(record_parts)
                        }
                        _ => return Err(ParseErrorKind::UnexpectedToken(t).into()),
                    }
                }
            }
        }

        //Extra flush at the end for the case of missing endline
        if let State::Record(record_parts) = state {
            Self::flush_record(
                record_parts,
                &origin,
                &current_name,
                rtype,
                &mut ttl,
                class,
                &mut records,
            )?;
        }

        Ok((origin, records))
    }

    fn flush_record(
        record_parts: Vec<String>,
        origin: &Name,
        current_name: &Option<Name>,
        rtype: Option<RecordType>,
        ttl: &mut Option<u32>,
        class: DNSClass,
        records: &mut BTreeMap<RrKey, RecordSet>,
    ) -> ParseResult<()> {
        // call out to parsers for difference record types
        // all tokens as part of the Record should be chardata...
        let rtype = rtype.ok_or_else(|| {
            ParseError::from(ParseErrorKind::Message("record type not specified"))
        })?;
        let rdata = if record_parts[0] == "\\#" {
            let len = record_parts[1].parse::<u16>().map_err(|_| {
                ParseError::from(ParseErrorKind::Message("invalid record length"))
            })?;
            let data = hex::decode(&record_parts[2]).map_err(|_| {
                ParseError::from(ParseErrorKind::Message("invalid hex"))
            })?;
            if len != data.len() as u16 {
                return Err(ParseError::from(ParseErrorKind::Message("invalid record length")))
            }
            RData::Unknown {
                code: u16::from(rtype.to_trust()),
                rdata: NULL::with(data)
            }
        } else {
            let tokens = record_parts.iter().map(AsRef::as_ref);
            match rtype {
                RecordType::DNSKEY => RData::DNSSEC(DNSSECRData::DNSKEY(parse_dnskey(tokens)?)),
                RecordType::CDNSKEY => RData::DNSSEC(DNSSECRData::CDNSKEY(parse_dnskey(tokens)?)),
                RecordType::NSEC3PARAM => RData::DNSSEC(DNSSECRData::NSEC3PARAM(parse_nsec3param(tokens)?)),
                RecordType::NSEC3 => RData::DNSSEC(DNSSECRData::NSEC3(parse_nsec3(tokens)?)),
                RecordType::DS => RData::Unknown {
                    code: 43,
                    rdata: parse_ds(tokens)?
                },
                RecordType::CDS => RData::Unknown {
                    code: 59,
                    rdata: parse_ds(tokens)?
                },
                RecordType::RRSIG => RData::DNSSEC(DNSSECRData::SIG(parse_sig(tokens)?)),
                RecordType::KEY => unimplemented!(),
                RecordType::NSEC => unimplemented!(),
                RecordType::DHCID => RData::Unknown {
                    code: 49,
                    rdata: parse_dhcid(tokens)?
                },
                RecordType::DNAME => RData::Unknown {
                    code: 39,
                    rdata: parse_dname(tokens)?
                },
                RecordType::CNAME => RData::CNAME(parse_name(tokens)?),
                RecordType::ANAME => RData::ANAME(parse_name(tokens)?),
                RecordType::LOC => RData::Unknown {
                    code: 29,
                    rdata: parse_loc(tokens)?
                },
                RecordType::RP => RData::Unknown {
                    code: 17,
                    rdata: parse_rp(tokens)?
                },
                _ => {
                    RData::parse(
                        rtype.to_trust(), tokens, Some(&origin),
                    )?
                }
            }
        };


        // verify that we have everything we need for the record
        let mut record = Record::new();
        // TODO COW or RC would reduce mem usage, perhaps Name should have an intern()...
        //  might want to wait until RC.weak() stabilizes, as that would be needed for global
        //  memory where you want
        record.set_name(current_name.clone().ok_or_else(|| {
            ParseError::from(ParseErrorKind::Message("record name not specified"))
        })?);
        record.set_rr_type(rtype.to_trust());
        record.set_dns_class(class);

        // slightly annoying, need to grab the TTL, then move rdata into the record,
        //  then check the Type again and have custom add logic.
        match rtype {
            RecordType::SOA => {
                // TTL for the SOA is set internally...
                // expire is for the SOA, minimum is default for records
                if let RData::SOA(ref soa) = rdata {
                    // TODO, this looks wrong, get_expire() should be get_minimum(), right?
                    record.set_ttl(soa.expire() as u32); // the spec seems a little inaccurate with u32 and i32
                    if ttl.is_none() {
                        *ttl = Some(soa.minimum());
                    } // TODO: should this only set it if it's not set?
                } else {
                    let msg = format!("Invalid RData here, expected SOA: {:?}", rdata);
                    return ParseResult::Err(ParseError::from(ParseErrorKind::Msg(msg)));
                }
            }
            _ => {
                record.set_ttl(ttl.ok_or_else(|| {
                    ParseError::from(ParseErrorKind::Message("record ttl not specified"))
                })?);
            }
        }

        // TODO: validate record, e.g. the name of SRV record allows _ but others do not.

        // move the rdata into record...
        record.set_data(Some(rdata));

        // add to the map
        let key = RrKey::new(LowerName::new(record.name()), record.rr_type());
        match rtype {
            RecordType::SOA => {
                let set = record.into();
                if records.insert(key, set).is_some() {
                    return Err(ParseErrorKind::Message("SOA is already specified").into());
                }
            }
            _ => {
                // add a Vec if it's not there, then add the record to the list
                let set = records
                    .entry(key)
                    .or_insert_with(|| RecordSet::new(record.name(), record.rr_type(), 0));
                set.insert(record, 0);
            }
        }
        Ok(())
    }
}

fn parse_dnskey<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<DNSKEY> {
    let flags = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("flags".to_string())))
        .and_then(|s| s.parse::<u16>().map_err(Into::into))?;
    let version = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("version".to_string())))
        .and_then(|s| s.parse::<u8>().map_err(Into::into))?;
    let algorithm = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("algorithm".to_string())))
        .and_then(|s| s.parse::<u8>().map_err(Into::into))?;
    let pk = tokens
        .next()
        .filter(|fp| !fp.is_empty())
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("public key".to_string())))?
        .as_bytes();

    if version != 3 {
        return Err(ParseError::from(ParseErrorKind::Msg("Only DNSKEY version 3 is supported".to_string())));
    }

    let zone_key = flags & 0b0000_0001_0000_0000 != 0;
    let secure_entry_point = flags & 0b0000_0000_0000_0001 != 0;
    let revoke = flags & 0b0000_0000_1000_0000 != 0;
    let algorithm = trust_dns_proto::rr::dnssec::Algorithm::from_u8(algorithm);
    let pk = base64::engine::general_purpose::STANDARD.decode(pk)
        .map_err(|_| ParseError::from(ParseErrorKind::Msg("Invalid base64".to_string())))?;

    Ok(DNSKEY::new(
        zone_key,
        secure_entry_point,
        revoke,
        algorithm,
        pk,
    ))
}

fn parse_nsec3param<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<NSEC3PARAM> {
    let algorithm = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("algorithm".to_string())))
        .and_then(|s| s.parse::<u8>().map_err(Into::into))?;
    let flags = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("flags".to_string())))
        .and_then(|s| s.parse::<u8>().map_err(Into::into))?;
    let iterations = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("iterations".to_string())))
        .and_then(|s| s.parse::<u16>().map_err(Into::into))?;
    let salt = tokens
        .next()
        .filter(|fp| !fp.is_empty())
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("salt".to_string())))?;


    let opt_out = flags & 0b0000_0001 != 0;
    let algorithm = trust_dns_proto::rr::dnssec::Nsec3HashAlgorithm::from_u8(algorithm)
        .map_err(|_| ParseError::from(ParseErrorKind::Msg("Invalid algorithm".to_string())))?;
    let salt = hex::decode(salt)
        .map_err(|_| ParseError::from(ParseErrorKind::Msg("Invalid hex".to_string())))?;

    Ok(NSEC3PARAM::new(
        algorithm,
        opt_out,
        iterations,
        salt,
    ))
}

fn parse_nsec3<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<NSEC3> {
    let algorithm = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("algorithm".to_string())))
        .and_then(|s| s.parse::<u8>().map_err(Into::into))?;
    let flags = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("flags".to_string())))
        .and_then(|s| s.parse::<u8>().map_err(Into::into))?;
    let iterations = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("iterations".to_string())))
        .and_then(|s| s.parse::<u16>().map_err(Into::into))?;
    let salt = tokens
        .next()
        .filter(|fp| !fp.is_empty())
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("salt".to_string())))?;
    let next_hashed_owner = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("next hashed owner".to_string())))?
        .to_ascii_uppercase();
    let types = tokens
        .map(|t| RecordType::from_str(t).map_err(Into::into).map(|t| t.to_trust()))
        .collect::<Result<Vec<_>, ParseError>>()?;

    let opt_out = flags & 0b0000_0001 != 0;
    let algorithm = trust_dns_proto::rr::dnssec::Nsec3HashAlgorithm::from_u8(algorithm)
        .map_err(|_| ParseError::from(ParseErrorKind::Msg("Invalid algorithm".to_string())))?;
    let salt = hex::decode(salt)
        .map_err(|_| ParseError::from(ParseErrorKind::Msg("Invalid hex".to_string())))?;
    let next_hashed_owner = data_encoding::BASE32HEX.decode(next_hashed_owner.as_bytes())
        .map_err(|_| ParseError::from(ParseErrorKind::Msg("Invalid base32".to_string())))?;

    Ok(NSEC3::new(
        algorithm,
        opt_out,
        iterations,
        salt,
        next_hashed_owner,
        types
    ))
}

#[allow(deprecated)]
pub fn parse_ds<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<NULL> {
    let tag_str: &str = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("key tag not present")))?;
    let algorithm_str: &str = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("algorithm not present")))?;
    let digest_type_str: &str = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("digest type not present")))?;
    let tag: u16 = tag_str.parse()?;
    let algorithm = match algorithm_str {
        // Mnemonics from Appendix A.1.
        "RSAMD5" => trust_dns_proto::rr::dnssec::Algorithm::RSAMD5,
        "DH" => trust_dns_proto::rr::dnssec::Algorithm::Unknown(2),
        "DSA" => trust_dns_proto::rr::dnssec::Algorithm::DSA,
        "ECC" => trust_dns_proto::rr::dnssec::Algorithm::Unknown(4),
        "RSASHA1" => trust_dns_proto::rr::dnssec::Algorithm::RSASHA1,
        "INDIRECT" => trust_dns_proto::rr::dnssec::Algorithm::Unknown(252),
        "PRIVATEDNS" => trust_dns_proto::rr::dnssec::Algorithm::Unknown(253),
        "PRIVATEOID" => trust_dns_proto::rr::dnssec::Algorithm::Unknown(254),
        _ => trust_dns_proto::rr::dnssec::Algorithm::from_u8(algorithm_str.parse()?),
    };
    let digest_type: u8 = digest_type_str.parse()?;
    let digest_str: String = tokens.collect();
    if digest_str.is_empty() {
        return Err(ParseError::from(ParseErrorKind::Message(
            "digest not present",
        )));
    }
    let mut digest = Vec::with_capacity(digest_str.len() / 2);
    let mut s = digest_str.as_str();
    while s.len() >= 2 {
        if !s.is_char_boundary(2) {
            return Err(ParseError::from(ParseErrorKind::Message(
                "digest contains non hexadecimal text",
            )));
        }
        let (byte_str, rest) = s.split_at(2);
        s = rest;
        let byte = u8::from_str_radix(byte_str, 16)?;
        digest.push(byte);
    }

    let mut out = vec![];
    let mut enc = BinEncoder::new(&mut out);

    tag.emit(&mut enc)?;
    algorithm.emit(&mut enc)?;
    enc.emit(digest_type)?;
    digest.emit(&mut enc)?;

    Ok(NULL::with(out))
}

fn parse_sig<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<SIG> {
    let type_covered = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("type covered".to_string())))
        .and_then(|s| RecordType::from_str(s).map_err(Into::into).map(|t| t.to_trust()))?;
    let algorithm = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("algorithm".to_string())))
        .and_then(|s| s.parse::<u8>().map_err(Into::into))?;
    let num_labels = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("num labels".to_string())))
        .and_then(|s| s.parse::<u8>().map_err(Into::into))?;
    let original_ttl = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("original ttl".to_string())))
        .and_then(|s| s.parse::<u32>().map_err(Into::into))?;
    let sig_expiration = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("signature expiration".to_string())))?;
    let sig_inception = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("signature inception".to_string())))?;
    let key_tag = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("key tag".to_string())))
        .and_then(|s| s.parse::<u16>().map_err(Into::into))?;
    let signer_name = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("signer name".to_string())))
        .and_then(|s| name_from_encoded_str(s, None).map_err(Into::into))?;
    let sig = tokens
        .next()
        .filter(|fp| !fp.is_empty())
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("signature".to_string())))?
        .as_bytes();

    let algorithm = trust_dns_proto::rr::dnssec::Algorithm::from_u8(algorithm);
    let sig = base64::engine::general_purpose::STANDARD.decode(sig)
        .map_err(|_| ParseError::from(ParseErrorKind::Msg("Invalid base64".to_string())))?;

    let sig_expiration = parse_datetime(sig_expiration)?;
    let sig_inception = parse_datetime(sig_inception)?;

    Ok(SIG::new(
        type_covered,
        algorithm,
        num_labels,
        original_ttl,
        sig_expiration,
        sig_inception,
        key_tag,
        signer_name,
        sig
    ))
}

fn parse_datetime(dt: &str) -> ParseResult<u32> {
    Ok(if dt.len() == 14 {
        let year = dt[0..4].parse::<u32>()
            .map_err(|_| ParseError::from(ParseErrorKind::Msg("Invalid timestamp".to_string())))?;
        let month = dt[4..6].parse::<u32>()
            .map_err(|_| ParseError::from(ParseErrorKind::Msg("Invalid timestamp".to_string())))?;
        let day = dt[6..8].parse::<u32>()
            .map_err(|_| ParseError::from(ParseErrorKind::Msg("Invalid timestamp".to_string())))?;
        let hour = dt[8..10].parse::<u32>()
            .map_err(|_| ParseError::from(ParseErrorKind::Msg("Invalid timestamp".to_string())))?;
        let minute = dt[10..12].parse::<u32>()
            .map_err(|_| ParseError::from(ParseErrorKind::Msg("Invalid timestamp".to_string())))?;
        let second = dt[12..14].parse::<u32>()
            .map_err(|_| ParseError::from(ParseErrorKind::Msg("Invalid timestamp".to_string())))?;

        chrono::NaiveDate::from_ymd_opt(year as i32, month, day)
            .and_then(|date| date.and_hms_opt(hour, minute, second))
            .ok_or_else(|| ParseError::from(ParseErrorKind::Msg("Invalid timestamp".to_string())))?
            .timestamp() as u32
    } else {
        dt.parse::<u32>()
            .map_err(|_| ParseError::from(ParseErrorKind::Msg("Invalid timestamp".to_string())))?
    })
}

fn parse_dhcid<'i, I: Iterator<Item = &'i str>>(tokens: I) -> ParseResult<NULL> {
    let data_str: String = tokens.collect();
    if data_str.is_empty() {
        return Err(ParseError::from(ParseErrorKind::Message(
            "data not present",
        )));
    }

    let data = base64::engine::general_purpose::STANDARD.decode(data_str)
        .map_err(|_| ParseError::from(ParseErrorKind::Msg("Invalid base64".to_string())))?;

    Ok(NULL::with(data))
}

fn parse_name<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<Name> {
    let target = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("target".to_string())))
        .and_then(|s| name_from_encoded_str(s, None).map_err(Into::into))?;

    Ok(target)
}

fn parse_dname<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<NULL> {
    let target = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("target".to_string())))
        .and_then(|s| name_from_encoded_str(s, None).map_err(Into::into))?;

    let mut out = vec![];
    let mut enc = BinEncoder::new(&mut out);
    target.emit_as_canonical(&mut enc, true)?;
    Ok(NULL::with(out))
}

fn parse_rp<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<NULL> {
    let mbox_dname = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("mbox-dname".to_string())))
        .and_then(|s| Name::from_str(s).map_err(Into::into))?;
    let txt_dname = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("txt-dname".to_string())))
        .and_then(|s| Name::from_str(s).map_err(Into::into))?;

    let mut out = vec![];
    let mut enc = BinEncoder::new(&mut out);
    mbox_dname.emit_as_canonical(&mut enc, true)?;
    txt_dname.emit_as_canonical(&mut enc, true)?;
    Ok(NULL::with(out))
}

fn parse_loc<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<NULL> {
    let d_lat = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("degrees latitude".to_string())))
        .and_then(|s| s.parse::<u32>().map_err(Into::into))?;
    let mut m_lat = 0u32;
    let mut s_lat = 0f64;
    let mut lat_mul = 1f64;

    let n = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("degrees latitude".to_string())))?;
    if n == "N" {
        // do nothing
    } else if n == "S" {
        lat_mul = -1f64;
    } else {
        m_lat = n.parse::<u32>().map_err(Into::<ParseError>::into)?;

        let n = tokens
            .next()
            .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("degrees latitude".to_string())))?;
        if n == "N" {
            // do nothing
        } else if n == "S" {
            lat_mul = -1f64;
        } else {
            s_lat = n.parse::<f64>()
                .map_err(|_| ParseError::from(ParseErrorKind::Message("invald float")))?;

            let n = tokens
                .next()
                .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("degrees latitude".to_string())))?;
            if n == "N" {
                // do nothing
            } else if n == "S" {
                lat_mul = -1f64;
            } else {
                return Err(ParseError::from(ParseErrorKind::Message("Invalid latitude")));
            }
        }
    }

    let d_long = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("degrees latitude".to_string())))
        .and_then(|s| s.parse::<u32>().map_err(Into::into))?;
    let mut m_long = 0u32;
    let mut s_long = 0f64;
    let mut long_mul = 1f64;

    let n = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("degrees longitude".to_string())))?;
    if n == "E" {
        // do nothing
    } else if n == "W" {
        long_mul = -1f64;
    } else {
        m_long = n.parse::<u32>().map_err(Into::<ParseError>::into)?;

        let n = tokens
            .next()
            .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("degrees longitude".to_string())))?;
        if n == "E" {
            // do nothing
        } else if n == "W" {
            long_mul = -1f64;
        } else {
            s_long = n.parse::<f64>()
                .map_err(|_| ParseError::from(ParseErrorKind::Message("invald float")))?;

            let n = tokens
                .next()
                .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("degrees longitude".to_string())))?;
            if n == "E" {
                // do nothing
            } else if n == "W" {
                long_mul = -1f64;
            } else {
                return Err(ParseError::from(ParseErrorKind::Message("Invalid longitude")));
            }
        }
    }

    let alt = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("degrees latitude".to_string())))
        .map(|s| s.trim_end_matches('m'))
        .and_then(|s| s.parse::<f64>()
            .map_err(|_| ParseError::from(ParseErrorKind::Message("invald float"))))?;

    let size = tokens
        .next()
        .map(|s| s.trim_end_matches('m'))
        .map(|s| s.parse::<f64>()
            .map_err(|_| ParseError::from(ParseErrorKind::Message("invald float"))))
        .unwrap_or_else(|| Ok(1f64))?;

    let hp = tokens
        .next()
        .map(|s| s.trim_end_matches('m'))
        .map(|s| s.parse::<f64>()
            .map_err(|_| ParseError::from(ParseErrorKind::Message("invald float"))))
        .unwrap_or_else(|| Ok(10000f64))?;

    let vp = tokens
        .next()
        .map(|s| s.trim_end_matches('m'))
        .map(|s| s.parse::<f64>()
            .map_err(|_| ParseError::from(ParseErrorKind::Message("invald float"))))
        .unwrap_or_else(|| Ok(10f64))?;

    if d_lat > 90 {
        return Err(ParseError::from(ParseErrorKind::Message("Invalid latitude")));
    }
    if m_lat > 59 {
        return Err(ParseError::from(ParseErrorKind::Message("Invalid latitude")));
    }
    if s_lat < 0.0 || s_lat >= 60.0 {
        return Err(ParseError::from(ParseErrorKind::Message("Invalid latitude")));
    }
    if d_long > 180 {
        return Err(ParseError::from(ParseErrorKind::Message("Invalid longitude")));
    }
    if m_long > 59 {
        return Err(ParseError::from(ParseErrorKind::Message("Invalid longitude")));
    }
    if s_long < 0.0 || s_long >= 60.0 {
        return Err(ParseError::from(ParseErrorKind::Message("Invalid longitude")));
    }

    if alt < -100000.00 || alt > 42849672.95 {
        return Err(ParseError::from(ParseErrorKind::Message("Invalid altitude")));
    }

    if size < 0.0 || size > 90000000.00 {
        return Err(ParseError::from(ParseErrorKind::Message("Invalid size")));
    }
    if hp < 0.0 || hp > 90000000.00 {
        return Err(ParseError::from(ParseErrorKind::Message("Invalid horizontal precision")));
    }
    if vp < 0.0 || vp > 90000000.00 {
        return Err(ParseError::from(ParseErrorKind::Message("Invalid vertical precision")));
    }

    let mut out = vec![];
    out.push(0u8);
    out.push(enc_size(size * 100.0));
    out.push(enc_size(hp * 100.0));
    out.push(enc_size(vp * 100.0));

    let lat = ((((d_lat as f64 * 60.0 * 60.0) + (m_lat as f64 * 60.0) + s_lat) * 1000.0 * lat_mul) + 2f64.powi(31)) as u32;
    let long = ((((d_long as f64 * 60.0 * 60.0) + (m_long as f64 * 60.0) + s_long) * 1000.0 * long_mul) + 2f64.powi(31)) as u32;
    let alt = ((alt + 100000.0) * 100.0) as u32;

    out.extend(lat.to_be_bytes());
    out.extend(long.to_be_bytes());
    out.extend(alt.to_be_bytes());

    Ok(NULL::with(out))
}

fn enc_size(size: f64) -> u8 {
    let size_exp = if size != 0.0 {
        size.log10().floor()
    } else {
        0.0
    };
    let size_man = size / 10f64.powf(size_exp);
    (((size_man as u8) << 4) & 0xF0) + (size_exp as u8 & 0x0F)
}

enum ParseState {
    Label,
    Escape1,
    Escape2(u32),
    Escape3(u32, u32),
}

fn name_from_encoded_str(local: &str, origin: Option<&Name>) -> ProtoResult<Name> {
    let mut name = Name::new();
    let mut label = String::new();

    let mut state = ParseState::Label;

    if local == "." {
        name.set_fqdn(true);
        return Ok(name);
    }

    for ch in local.chars() {
        match state {
            ParseState::Label => match ch {
                '.' => {
                    name = name.append_label(Label::from_ascii(&label)?)?;
                    label.clear();
                }
                '\\' => state = ParseState::Escape1,
                ch if !ch.is_control() && !ch.is_whitespace() => label.push(ch),
                _ => return Err(format!("unrecognized char: {ch}").into()),
            },
            ParseState::Escape1 => {
                if ch.is_numeric() {
                    state = ParseState::Escape2(
                        ch.to_digit(8)
                            .ok_or_else(|| ProtoError::from(format!("illegal char: {ch}")))?,
                    );
                } else {
                    // it's a single escaped char
                    label.push(ch);
                    state = ParseState::Label;
                }
            }
            ParseState::Escape2(i) => {
                if ch.is_numeric() {
                    state = ParseState::Escape3(
                        i,
                        ch.to_digit(8)
                            .ok_or_else(|| ProtoError::from(format!("illegal char: {ch}")))?,
                    );
                } else {
                    return Err(ProtoError::from(format!("unrecognized char: {ch}")));
                }
            }
            ParseState::Escape3(i, ii) => {
                if ch.is_numeric() {
                    // octal conversion
                    let val: u32 = (i * 8 * 8)
                        + (ii * 8)
                        + ch.to_digit(8)
                        .ok_or_else(|| ProtoError::from(format!("illegal char: {ch}")))?;
                    let new: char = char::from_u32(val)
                        .ok_or_else(|| ProtoError::from(format!("illegal char: {ch}")))?;
                    label.push(new);
                    state = ParseState::Label;
                } else {
                    return Err(format!("unrecognized char: {ch}").into());
                }
            }
        }
    }

    if !label.is_empty() {
        name = name.append_label(Label::from_ascii(&label)?)?;
    }

    if local.ends_with('.') {
        name.set_fqdn(true);
    } else if let Some(other) = origin {
        return name.append_domain(other);
    }

    Ok(name)
}