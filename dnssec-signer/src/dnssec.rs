use std::fmt::Write;
use trust_dns_proto::serialize::binary::BinEncodable;
use base64::Engine;
use itertools::Itertools;
use trust_dns_proto::rr::IntoName;

// RFC 9276
const ITERATIONS: u16 = 0;

pub fn sign_zone(
    zone: &str,
    ksk: &openssl::ec::EcKeyRef<openssl::pkey::Private>,
    zsk: &openssl::ec::EcKeyRef<openssl::pkey::Private>,
) -> Result<String, String> {
    let zone_file_lexer = crate::lexer::Lexer::new(zone);
    let (origin, zone_file) = crate::parser::Parser::new()
        .parse(zone_file_lexer, trust_dns_proto::rr::Name::default(), trust_dns_proto::rr::DNSClass::IN)
        .map_err(|e| format!("Unable to parse zone file: {}", e))?;
    let soa_rrset = zone_file.get(&trust_dns_client::rr::RrKey {
        name: origin.clone().into(),
        record_type: trust_dns_client::rr::RecordType::SOA,
    }).ok_or_else(|| format!("Zone file does not contain SOA record"))?;
    let soa = soa_rrset.records_without_rrsigs().next().unwrap().data().unwrap().as_soa().unwrap();

    let now = chrono::Utc::now() - chrono::Duration::try_minutes(5).unwrap();
    let expiry = now + chrono::Duration::try_days(14).unwrap();

    let default_ttl = std::cmp::min(soa_rrset.ttl(), soa.minimum());
    let mut out_zone = zone_file.clone();

    out_zone.remove(&trust_dns_client::rr::RrKey {
        name: origin.clone().into(),
        record_type: trust_dns_client::rr::RecordType::SOA,
    }).unwrap();
    let new_serial = (now.timestamp() & 0xFFFFFFFF) as u32;
    let out_soa = trust_dns_proto::rr::rdata::soa::SOA::new(
        soa.mname().to_owned(), soa.rname().to_owned(),
        new_serial, soa.refresh(), soa.retry(),
        soa.expire(), soa.minimum()
    );
    let mut out_soa_rrset = trust_dns_proto::rr::RecordSet::new(
        &origin, trust_dns_client::rr::RecordType::SOA, new_serial,
    );
    out_soa_rrset.set_ttl(default_ttl);
    out_soa_rrset.add_rdata(trust_dns_proto::rr::record_data::RData::SOA(
       out_soa
    ));
    out_zone.insert(trust_dns_client::rr::RrKey {
        name: origin.clone().into(),
        record_type: trust_dns_client::rr::RecordType::SOA,
    }, out_soa_rrset);

    let mut ctx = openssl::bn::BigNumContext::new()
        .map_err(|e| format!("Unable to create BigNum context: {}", e))?;
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let alg = trust_dns_proto::rr::dnssec::Algorithm::ECDSAP256SHA256;
    let ksk_public_key = &ksk.public_key().to_bytes(
        &group, openssl::ec::PointConversionForm::UNCOMPRESSED, &mut ctx
    ).map_err(|e| format!("Unable to get KSK public key: {}", e))?;
    let ksk_rr = trust_dns_proto::rr::dnssec::rdata::DNSKEY::new(
        true, true, false,alg,
        ksk_public_key[1..].to_vec(),
    );
    let zsk_public_key = &zsk.public_key().to_bytes(
        &group, openssl::ec::PointConversionForm::UNCOMPRESSED, &mut ctx
    ).map_err(|e| format!("Unable to get ZSK public key: {}", e))?;
    let zsk_rr = trust_dns_proto::rr::dnssec::rdata::DNSKEY::new(
        true, false, false, alg,
        zsk_public_key[1..].to_vec(),
    );

    let alg = trust_dns_proto::rr::dnssec::Algorithm::ECDSAP256SHA256;
    let key_tag = zsk_rr.calculate_key_tag()
        .map_err(|e| format!("Unable to calculate ZSK key tag: {}", e))?;
    let ksk_key_tag = ksk_rr.calculate_key_tag()
        .map_err(|e| format!("Unable to calculate KSK key tag: {}", e))?;

    let mut dnskey_rset = trust_dns_proto::rr::RecordSet::new(
        &origin, trust_dns_client::rr::RecordType::DNSKEY, new_serial,
    );
    dnskey_rset.set_ttl(default_ttl);
    dnskey_rset.add_rdata(trust_dns_proto::rr::record_data::RData::DNSSEC(
        trust_dns_proto::rr::dnssec::rdata::DNSSECRData::DNSKEY(ksk_rr)
    ));
    dnskey_rset.add_rdata(trust_dns_proto::rr::record_data::RData::DNSSEC(
        trust_dns_proto::rr::dnssec::rdata::DNSSECRData::DNSKEY(zsk_rr)
    ));
    out_zone.insert(trust_dns_client::rr::RrKey {
        name: origin.clone().into(),
        record_type: trust_dns_client::rr::RecordType::DNSKEY,
    }, dnskey_rset);

    let mut nsec3_param_rrset = trust_dns_proto::rr::RecordSet::new(
        &origin, trust_dns_client::rr::RecordType::NSEC3PARAM, new_serial,
    );
    nsec3_param_rrset.set_ttl(default_ttl);
    nsec3_param_rrset.add_rdata(trust_dns_proto::rr::record_data::RData::DNSSEC(
        trust_dns_proto::rr::dnssec::rdata::DNSSECRData::NSEC3PARAM(
            trust_dns_proto::rr::dnssec::rdata::NSEC3PARAM::new(
                trust_dns_proto::rr::dnssec::Nsec3HashAlgorithm::SHA1, false,
                ITERATIONS, Vec::new()
            )
        )
    ));
    out_zone.insert(trust_dns_client::rr::RrKey {
        name: origin.clone().into(),
        record_type: trust_dns_client::rr::RecordType::NSEC3PARAM,
    }, nsec3_param_rrset);

    let mut nsec3_records = vec![];
    let mut keys = out_zone.keys().collect::<Vec<_>>();
    keys.sort_by(|k1, k2| k1.name.cmp(&k2.name));
    for (name, rr_keys) in &keys.into_iter().group_by(|k| k.name.clone()) {
        let mut tbs = vec![];
        let mut tbs_bin_encoder = trust_dns_proto::serialize::binary::BinEncoder::with_mode(
            &mut tbs, trust_dns_proto::serialize::binary::EncodeMode::Signing,
        );
        name.emit_as_canonical(&mut tbs_bin_encoder, true)
            .map_err(|e| format!("Unable to emit name: {}", e))?;
        let hashed_name = nsec3_hash(&[], &tbs, ITERATIONS);
        let rtypes = rr_keys.map(|k| k.record_type).collect::<Vec<_>>();
        let mut rr_types = std::collections::BTreeSet::from_iter(rtypes);
        rr_types.insert(trust_dns_client::rr::RecordType::RRSIG);
        nsec3_records.push((hashed_name, rr_types));
        let name_len = name.clone().into_name()
            .map_err(|e| format!("Unable to convert name: {}", e))?.into_iter().len();
        for i in 1..(name_len - origin.iter().len()) {
            let new_name = name.clone().into_name()
                .map_err(|e| format!("Unable to convert name: {}", e))?.trim_to(name_len - i);
            let mut tbs = vec![];
            let mut tbs_bin_encoder = trust_dns_proto::serialize::binary::BinEncoder::with_mode(
                &mut tbs, trust_dns_proto::serialize::binary::EncodeMode::Signing,
            );
            new_name.emit_as_canonical(&mut tbs_bin_encoder, true)
                .map_err(|e| format!("Unable to emit name: {}", e))?;
            let hashed_name = nsec3_hash(&[], &tbs, ITERATIONS);
            nsec3_records.push((hashed_name, std::collections::BTreeSet::new()));
        }
    }

    nsec3_records.sort_by(|(h1, _), (h2, _)| h1.cmp(h2));
    let nsec3_records = nsec3_records.into_iter().group_by(|(h, _)| h.clone())
        .into_iter().map(|(_, g)| {
        g.into_iter().reduce(|(h1, mut s1), (h2, s2)| {
            assert_eq!(h1, h2);
            s1.extend(s2);
            (h1, s1)
        }).unwrap()
    })
        .collect::<Vec<_>>();

    for i in 0..nsec3_records.len() {
        let record = &nsec3_records[i];
        let next_record = &nsec3_records[(i + 1) % nsec3_records.len()];
        let owner_name = data_encoding::BASE32_DNSSEC.encode(&record.0);
        let owner_name = trust_dns_proto::rr::Name::new()
            .append_label(owner_name)
            .map_err(|e| format!("Unable to append label: {}", e))?
            .append_name(&origin)
            .map_err(|e| format!("Unable to append name: {}", e))?;
        let mut nsec_rrset = trust_dns_proto::rr::RecordSet::new(
            &owner_name, trust_dns_client::rr::RecordType::NSEC3, new_serial,
        );
        nsec_rrset.set_ttl(default_ttl);
        nsec_rrset.add_rdata(trust_dns_proto::rr::record_data::RData::DNSSEC(
            trust_dns_proto::rr::dnssec::rdata::DNSSECRData::NSEC3(
                trust_dns_proto::rr::dnssec::rdata::NSEC3::new(
                    trust_dns_proto::rr::dnssec::Nsec3HashAlgorithm::SHA1, false,
                    ITERATIONS, Vec::new(), next_record.0.clone(),
                    record.1.iter().map(|rt| rt.clone()).collect(),
                )
            )
        ));
        out_zone.insert(trust_dns_client::rr::RrKey {
            name: owner_name.into(),
            record_type: trust_dns_client::rr::RecordType::NSEC3,
        }, nsec_rrset);
    }
    let mut new_rrsigs = vec![];
    for (rr_key, record_set) in &out_zone {
        let (key, kt) = if rr_key.record_type == trust_dns_client::rr::RecordType::DNSKEY ||
          rr_key.record_type == trust_dns_client::rr::RecordType::CDS ||
          rr_key.record_type == trust_dns_client::rr::RecordType::CDNSKEY {
            (&ksk, ksk_key_tag)
        } else {
            (&zsk, key_tag)
        };

        let orig_ttl = record_set.ttl();
        let mut tbs = vec![];
        let mut tbs_bin_encoder = trust_dns_proto::serialize::binary::BinEncoder::with_mode(
            &mut tbs, trust_dns_proto::serialize::binary::EncodeMode::Signing,
        );
        trust_dns_proto::rr::dnssec::rdata::sig::emit_pre_sig(
            &mut tbs_bin_encoder,
            rr_key.record_type,
            alg,
            rr_key.name.num_labels(),
            orig_ttl,
            expiry.timestamp() as u32,
            now.timestamp() as u32,
            kt,
            &origin,
        ).map_err(|e| format!("Unable to generate pre-sig: {}", e))?;

        let mut records = record_set.records_without_rrsigs()
            .filter_map(|r| r.data())
            .map(|r| -> Result<Vec<u8>, trust_dns_proto::error::ProtoError> {
                let mut record_tbs: Vec<u8> = vec![];
                let mut record_tbs_bin_encoder = trust_dns_proto::serialize::binary::BinEncoder::with_mode(
                    &mut record_tbs, trust_dns_proto::serialize::binary::EncodeMode::Signing,
                );
                record_tbs_bin_encoder.with_canonical_names(|e| {
                    r.emit(e)
                }).map_err(|e| format!("Unable to emit record: {}", e))?;
                Ok(record_tbs)
            })
            .collect::<Result<Vec<_>, _>>()?;
        records.sort();

        for r in records {
            rr_key.name.emit_as_canonical(&mut tbs_bin_encoder, true)
                .map_err(|e| format!("Unable to emit name: {}", e))?;
            rr_key.record_type.emit(&mut tbs_bin_encoder)
                .map_err(|e| format!("Unable to emit record type: {}", e))?;
            trust_dns_proto::rr::DNSClass::IN.emit(&mut tbs_bin_encoder)
                .map_err(|e| format!("Unable to emit class: {}", e))?;
            orig_ttl.emit(&mut tbs_bin_encoder)
                .map_err(|e| format!("Unable to emit TTL: {}", e))?;
            tbs_bin_encoder.emit_u16(r.len() as u16)
                .map_err(|e| format!("Unable to emit record length: {}", e))?;
            tbs_bin_encoder.emit_vec(&r)
                .map_err(|e| format!("Unable to emit record: {}", e))?;
        }

        let mut hasher = openssl::hash::Hasher::new(
            openssl::hash::MessageDigest::sha256()
        ).unwrap();
        hasher.update(&tbs).unwrap();
        let hash = hasher.finish().unwrap();
        let sig = openssl::ecdsa::EcdsaSig::sign(&hash, key)
            .map_err(|e| format!("Unable to sign: {}", e))?;
        let r = sig.r().to_vec_padded(32).unwrap();
        let s = sig.s().to_vec_padded(32).unwrap();
        let mut sig_bytes = vec![];
        sig_bytes.extend_from_slice(&r);
        sig_bytes.extend_from_slice(&s);

        let rrsig = trust_dns_proto::rr::dnssec::rdata::SIG::new(
            rr_key.record_type,
            alg,
            rr_key.name.num_labels(),
            orig_ttl,
            expiry.timestamp() as u32,
            now.timestamp() as u32,
            kt,
            origin.clone(),
            sig_bytes,
        );
        let mut record = trust_dns_proto::rr::Record::new();
        record.set_ttl(orig_ttl);
        record.set_name(rr_key.name.clone().into());
        record.set_dns_class(trust_dns_proto::rr::DNSClass::IN);
        record.set_record_type(trust_dns_proto::rr::RecordType::RRSIG);
        record.set_data(Some(trust_dns_proto::rr::record_data::RData::DNSSEC(
            trust_dns_proto::rr::dnssec::rdata::DNSSECRData::SIG(rrsig.clone())
        )));
        new_rrsigs.push(record);
    }

    let mut lines = vec![];

    for record_set in out_zone.into_values() {
        for record in record_set.into_iter() {
            lines.push(output_record(&record));
        }
    }

    for rrsig in new_rrsigs {
        lines.push(output_record(&rrsig));
    }

    Ok(lines.join("\n"))
}

fn nsec3_hash(salt: &[u8], x: &[u8], i: u16) -> Vec<u8> {
    if i == 0 {
        let mut hasher = openssl::hash::Hasher::new(
            openssl::hash::MessageDigest::sha1()
        ).unwrap();
        hasher.update(&x).unwrap();
        hasher.update(salt).unwrap();
        hasher.finish().unwrap().to_vec()
    } else {
        let mut hasher = openssl::hash::Hasher::new(
            openssl::hash::MessageDigest::sha1()
        ).unwrap();
        hasher.update(&nsec3_hash(salt, x, i - 1)).unwrap();
        hasher.update(salt).unwrap();
        hasher.finish().unwrap().to_vec()
    }
}

fn encode_type(rr_type: trust_dns_proto::rr::RecordType) -> String {
    match rr_type {
        trust_dns_proto::rr::record_type::RecordType::Unknown(u) => {
            format!("TYPE{}", u)
        }
        o => format!("{}", o)
    }
}

fn encode_byte_string(data: &[u8]) -> String {
    let mut out = String::new();
    for b in data {
        if b.is_ascii() {
            write!(out, "{}", (*b) as char).unwrap();
        } else {
            write!(out, "\\{}", *b).unwrap();
        }
    }
    out
}

fn output_record(record: &trust_dns_proto::rr::Record) -> String {
    let rdata = if let Some(data) = record.data() {
        match data {
            trust_dns_proto::rr::record_data::RData::TXT(txt) => {
                txt.iter().map(|txt| {
                    let txt = encode_byte_string(txt).replace("\"", "\\\"");
                    format!("\"{}\"", txt)
                }).join(" ")
            }
            trust_dns_proto::rr::record_data::RData::CAA(caa) => {
                let txt = match caa.value() {
                    trust_dns_proto::rr::rdata::caa::Value::Issuer(name, values) => {
                        let mut out = String::new();
                        if let Some(name) = name {
                            write!(out, "{}", name.to_ascii()).unwrap();
                            for value in values.iter() {
                                write!(out, "; {value}").unwrap();
                            }
                        } else {
                            write!(out, ";").unwrap();
                        }
                        out
                    },
                    trust_dns_proto::rr::rdata::caa::Value::Url(issue) => {
                        issue.to_string()
                    },
                    trust_dns_proto::rr::rdata::caa::Value::Unknown(v) => {
                        encode_byte_string(v).replace("\"", "\\\"")
                    }
                };
                format!("{} {} \"{}\"", if caa.issuer_critical() {
                    "128"
                } else {
                    "0"
                }, caa.tag(), txt)
            }
            trust_dns_proto::rr::record_data::RData::Unknown {
                rdata, ..
            } => {
                format!("\\# {} {}", rdata.anything().len(), hex::encode(rdata.anything()))
            }
            trust_dns_proto::rr::record_data::RData::DNSSEC(trust_dns_proto::rr::dnssec::rdata::DNSSECRData::SIG(sig)) => {
                format!("{} {} {} {} {} {} {} {} {}",
                        encode_type(sig.type_covered()),
                        sig.algorithm(),
                        sig.num_labels(),
                        sig.original_ttl(),
                        sig.sig_expiration(),
                        sig.sig_inception(),
                        sig.key_tag(),
                        sig.signer_name().to_ascii(),
                        base64::engine::general_purpose::STANDARD.encode(sig.sig())
                )
            }
            trust_dns_proto::rr::record_data::RData::DNSSEC(trust_dns_proto::rr::dnssec::rdata::DNSSECRData::NSEC3(nsec)) => {
                format!("{} {} {} {} {} {}",
                        u8::from(nsec.hash_algorithm()),
                        nsec.flags(),
                        nsec.iterations(),
                        if nsec.salt().len() == 0 {
                            "-".to_string()
                        } else {
                            hex::encode(nsec.salt())
                        },
                        data_encoding::BASE32_DNSSEC.encode(&nsec.next_hashed_owner_name()),
                        nsec.type_bit_maps().iter().map(|t| encode_type(*t)).join(" "),
                )
            }
            o => {
                format!("{}", o)
            }
        }
    } else {
        String::default()
    };
    format!("{} {} {} {} {}", record.name().to_ascii(), record.ttl(), record.dns_class(), encode_type(record.rr_type()), rdata)
}