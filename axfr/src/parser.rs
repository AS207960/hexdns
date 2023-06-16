use std::collections::BTreeMap;
use std::str::FromStr;
use base64::Engine;
use trust_dns_client::error::*;
use trust_dns_proto::rr::dnssec::rdata::{DNSSECRData, DNSKEY, NSEC3PARAM, NSEC3, DS, SIG};
use trust_dns_client::rr::{DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType, RrKey};
use trust_dns_client::serialize::txt::RDataParser;
use trust_dns_client::serialize::txt::{Lexer, Token};

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
                            current_name = Some(Name::parse(&data, Some(&origin))?);
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
        let tokens = record_parts.iter().map(AsRef::as_ref);
        let rdata =  match rtype {
            RecordType::DNSKEY => RData::DNSSEC(DNSSECRData::DNSKEY(parse_dnskey(tokens)?)),
            RecordType::CDNSKEY => RData::DNSSEC(DNSSECRData::CDNSKEY(parse_dnskey(tokens)?)),
            RecordType::NSEC3PARAM => RData::DNSSEC(DNSSECRData::NSEC3PARAM(parse_nsec3param(tokens)?)),
            RecordType::NSEC3 => RData::DNSSEC(DNSSECRData::NSEC3(parse_nsec3(tokens)?)),
            RecordType::CDS => RData::DNSSEC(DNSSECRData::CDS(parse_ds(tokens)?)),
            RecordType::RRSIG => RData::DNSSEC(DNSSECRData::SIG(parse_sig(tokens)?)),
            RecordType::KEY => unimplemented!(),
            RecordType::NSEC => unimplemented!(),
            _ => RData::parse(
                rtype, tokens, Some(&origin),
            )?
        };

        // verify that we have everything we need for the record
        let mut record = Record::new();
        // TODO COW or RC would reduce mem usage, perhaps Name should have an intern()...
        //  might want to wait until RC.weak() stabilizes, as that would be needed for global
        //  memory where you want
        record.set_name(current_name.clone().ok_or_else(|| {
            ParseError::from(ParseErrorKind::Message("record name not specified"))
        })?);
        record.set_rr_type(rtype);
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
    let types = tokens.map(|t| RecordType::from_str(t).map_err(Into::into))
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
pub fn parse_ds<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<DS> {
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
        "RSAMD5" => trust_dns_proto::rr::dnssec::Algorithm::Unknown(1),
        "DH" => trust_dns_proto::rr::dnssec::Algorithm::Unknown(2),
        "DSA" => trust_dns_proto::rr::dnssec::Algorithm::Unknown(3),
        "ECC" => trust_dns_proto::rr::dnssec::Algorithm::Unknown(4),
        "RSASHA1" => trust_dns_proto::rr::dnssec::Algorithm::RSASHA1,
        "INDIRECT" => trust_dns_proto::rr::dnssec::Algorithm::Unknown(252),
        "PRIVATEDNS" => trust_dns_proto::rr::dnssec::Algorithm::Unknown(253),
        "PRIVATEOID" => trust_dns_proto::rr::dnssec::Algorithm::Unknown(254),
        _ => trust_dns_proto::rr::dnssec::Algorithm::from_u8(algorithm_str.parse()?),
    };
    let digest_type = trust_dns_proto::rr::dnssec::DigestType::from_u8(digest_type_str.parse()?)?;
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
    Ok(DS::new(tag, algorithm, digest_type, digest))
}

fn parse_sig<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<SIG> {
    let type_covered = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("type covered".to_string())))
        .and_then(|s| RecordType::from_str(s).map_err(Into::into))?;
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
        .and_then(|s| Name::from_str(s).map_err(Into::into))?;
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