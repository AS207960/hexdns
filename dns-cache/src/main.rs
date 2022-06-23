#![feature(proc_macro_hygiene)]
#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
#[macro_use]
extern crate prometheus;
#[macro_use]
extern crate lazy_static;

use futures::stream::StreamExt;
use tokio::sync::Mutex;
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};
use prost::Message;

use std::str::FromStr;
use std::sync::Arc;

pub mod dns_proto {
    tonic::include_proto!("coredns.dns");
}

lazy_static! {
    static ref QUERY_COUNTER: prometheus::IntCounterVec =
        register_int_counter_vec!("query_count", "Number of queries received", &["type"]).unwrap();
    static ref QUERY_RESPONSE_TIME: prometheus::HistogramVec =
        register_histogram_vec!("query_response_time", "Time taken to respond to queries", &["type"]).unwrap();
    static ref RESPONSE_COUNTER: prometheus::IntCounterVec =
        register_int_counter_vec!("response_count", "Number of responses sent", &["type"]).unwrap();
    static ref UPSTREAM_QUERY_COUNTER: prometheus::IntCounterVec =
        register_int_counter_vec!("upstream_query_count", "Number of queries sent to the upstream", &["type"]).unwrap();
    static ref UPSTREAM_RESPONSE_TIME: prometheus::Histogram =
        register_histogram!("upstream_response_time", "Time taken by the upstream to respond to queries").unwrap();
    static ref CACHE_COUNTER: prometheus::IntCounterVec =
        register_int_counter_vec!("cache_count", "Number of lookups to the cache", &["type"]).unwrap();
}

const KNOWN_RECORD_TYPES: [trust_dns_proto::rr::record_type::RecordType; 18] = [
    trust_dns_proto::rr::record_type::RecordType::A,
    trust_dns_proto::rr::record_type::RecordType::AAAA,
    trust_dns_proto::rr::record_type::RecordType::CAA,
    trust_dns_proto::rr::record_type::RecordType::CNAME,
    trust_dns_proto::rr::record_type::RecordType::HINFO,
    trust_dns_proto::rr::record_type::RecordType::HTTPS,
    trust_dns_proto::rr::record_type::RecordType::MX,
    trust_dns_proto::rr::record_type::RecordType::NAPTR,
    trust_dns_proto::rr::record_type::RecordType::NS,
    trust_dns_proto::rr::record_type::RecordType::OPENPGPKEY,
    trust_dns_proto::rr::record_type::RecordType::PTR,
    trust_dns_proto::rr::record_type::RecordType::SOA,
    trust_dns_proto::rr::record_type::RecordType::SRV,
    trust_dns_proto::rr::record_type::RecordType::SSHFP,
    trust_dns_proto::rr::record_type::RecordType::SVCB,
    trust_dns_proto::rr::record_type::RecordType::TLSA,
    trust_dns_proto::rr::record_type::RecordType::TXT,
    trust_dns_proto::rr::record_type::RecordType::Unknown(49)
];

#[derive(PartialEq, Eq, Hash, Debug, Clone, Ord, PartialOrd)]
struct CacheKey {
    name: trust_dns_client::rr::LowerName,
    qclass: trust_dns_proto::rr::dns_class::DNSClass,
    qtype: trust_dns_proto::rr::record_type::RecordType,
    is_dnssec: bool,
}

#[derive(Debug, Clone)]
struct CacheData {
    valid_until: std::time::Instant,
    hard_valid_until: std::time::Instant,
    response_code: trust_dns_proto::op::ResponseCode,
    answers: Vec<trust_dns_proto::rr::resource::Record>,
    name_servers: Vec<trust_dns_proto::rr::resource::Record>,
    additionals: Vec<trust_dns_proto::rr::resource::Record>,
    edns: trust_dns_proto::op::Edns,
}

async fn fetch_and_insert<>(
    cache_key: CacheKey,
    msg: &dns_cache::Request,
    client: &mut dns_proto::dns_service_client::DnsServiceClient<tonic::transport::Channel>,
    cache: &Arc<Mutex<lru::LruCache<CacheKey, CacheData>>>,
    in_flight: &Arc<flurry::HashSet<CacheKey>>,
    new: bool,
) -> Result<trust_dns_proto::op::Message, trust_dns_client::op::ResponseCode> {
    let request = tonic::Request::new(dns_proto::DnsPacket {
        msg: msg.raw_bytes.clone()
    });
    in_flight.insert(cache_key.clone(), &in_flight.guard());
    let timer = UPSTREAM_RESPONSE_TIME.start_timer();
    let r_response = client.query(request).await;
    timer.observe_duration();
    let response = match r_response {
        Ok(r) => r,
        Err(e) => {
            error!("Error communicating with upstream: {}", e);
            UPSTREAM_QUERY_COUNTER.with_label_values(&["error"]).inc();
            in_flight.remove(&cache_key, &in_flight.guard());
            return Err(trust_dns_client::op::ResponseCode::ServFail)
        }
    };
    let response_msg = match trust_dns_proto::op::message::Message::from_bytes(&response.into_inner().msg) {
        Ok(r) => r,
        Err(e) => {
            error!("Error parsing response from upstream: {}", e);
            UPSTREAM_QUERY_COUNTER.with_label_values(&["error"]).inc();
            in_flight.remove(&cache_key, &in_flight.guard());
            return Err(trust_dns_client::op::ResponseCode::ServFail)
        }
    };

    UPSTREAM_QUERY_COUNTER.with_label_values(&["ok"]).inc();
    if response_msg.response_code() != trust_dns_client::op::ResponseCode::ServFail || new {
        let new_cache_data = CacheData {
            valid_until: std::time::Instant::now() + std::time::Duration::from_secs(300),
            hard_valid_until: std::time::Instant::now() + std::time::Duration::from_secs(43200),
            response_code: response_msg.response_code(),
            answers: response_msg.answers().to_vec(),
            name_servers: response_msg.name_servers().to_vec(),
            additionals: response_msg.additionals().to_vec(),
            edns: response_msg.edns().map(|e| e.clone()).unwrap_or_else(trust_dns_proto::op::Edns::new)
        };
        cache.lock().await.put(cache_key.clone(), new_cache_data);
    }

    in_flight.remove(&cache_key, &in_flight.guard());

    Ok(response_msg)
}

async fn lookup_cache_or_fetch(
    msg: &dns_cache::Request,
    client: &mut dns_proto::dns_service_client::DnsServiceClient<tonic::transport::Channel>,
    cache: &Arc<Mutex<lru::LruCache<CacheKey, CacheData>>>,
    in_flight: &Arc<flurry::HashSet<CacheKey>>,
) -> Result<trust_dns_proto::op::message::Message, trust_dns_client::op::ResponseCode> {
    let dnssec = match msg.msg.edns() {
        Some(e) => e.dnssec_ok(),
        None => false,
    };
    let cache_key = CacheKey {
        name: msg.query.name().to_owned(),
        qclass: msg.query.query_class(),
        qtype: msg.query.query_type(),
        is_dnssec: dnssec,
    };

    loop {
        if in_flight.contains(&cache_key, &in_flight.guard()) {
            trace!("Request in flight for {:?}", cache_key);
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        } else {
            break;
        }
    }

    let cached_result = match cache.lock().await.get(&cache_key) {
        Some(c) => Some(c.to_owned()),
        None => None
    };

    if let Some(cached_result) = cached_result {
        if cached_result.hard_valid_until < std::time::Instant::now() {
            debug!("Hard expired cached item");
            CACHE_COUNTER.with_label_values(&["hit_hard_stale"]).inc();
        } else {
            if cached_result.valid_until < std::time::Instant::now() {
                debug!("Expired cached item");
                let msg = msg.clone();
                let mut client = client.clone();
                let mut cache = cache.clone();
                let mut in_flight = in_flight.clone();
                CACHE_COUNTER.with_label_values(&["hit_stale"]).inc();
                tokio::spawn(async move {
                    let _ = fetch_and_insert(cache_key, &msg, &mut client, &mut cache, &mut in_flight, false).await;
                });
            } else {
                CACHE_COUNTER.with_label_values(&["hit"]).inc();
            }
            let mut response_msg = trust_dns_proto::op::message::Message::new();
            let mut edns = cached_result.edns;
            response_msg.set_id(msg.msg.id());
            response_msg.set_message_type(trust_dns_proto::op::MessageType::Response);
            response_msg.set_op_code(trust_dns_proto::op::OpCode::Query);
            response_msg.set_authoritative(true);
            response_msg.set_recursion_desired(msg.msg.recursion_desired());
            edns.set_dnssec_ok(dnssec);
            response_msg.set_edns(edns);
            response_msg.set_response_code(cached_result.response_code);
            response_msg.add_query(msg.query.original().clone());
            response_msg.insert_answers(cached_result.answers);
            response_msg.insert_name_servers(cached_result.name_servers);
            response_msg.insert_additionals(cached_result.additionals);
            return Ok(response_msg);
        }
    }

    CACHE_COUNTER.with_label_values(&["miss"]).inc();
    let mut response_msg = fetch_and_insert(cache_key, msg, client, cache, in_flight, true).await?;
    response_msg.set_authoritative(true);

    Ok(response_msg)
}

struct Config {
    server_name: Option<Vec<u8>>,
}

#[derive(Clone)]
struct Cache {
    client: dns_proto::dns_service_client::DnsServiceClient<tonic::transport::Channel>,
    cache: Arc<Mutex<lru::LruCache<CacheKey, CacheData>>>,
    in_flight: Arc<flurry::HashSet<CacheKey>>,
    config: Arc<Config>,
}

async fn handle_request(cache: Cache, request_message: dns_cache::Request, request_context: dns_cache::RequestContext) {
    trace!("request: {:?}", request_message);

    let mut nsid_requested = false;
    if let Some(edns) = request_message.msg.edns() {
        if edns.version() > 0 {
            warn!(
                "request edns version greater than 0: {}",
                edns.version()
            );
            RESPONSE_COUNTER.with_label_values(&["invalid_edns"]).inc();
            let mut res_edns = trust_dns_proto::op::Edns::new();
            res_edns.set_version(0);
            let mut response_msg = trust_dns_proto::op::Message::error_msg(
                request_message.msg.id(), request_message.msg.op_code(),
                trust_dns_client::op::ResponseCode::BADVERS,
            );
            response_msg.set_edns(res_edns);
            request_context.respond(response_msg).await;
            return;
        }
        nsid_requested = edns.option(trust_dns_proto::rr::rdata::opt::EdnsCode::NSID).is_some();
    }

    match request_message.msg.message_type() {
        trust_dns_client::op::MessageType::Query => match request_message.msg.op_code() {
            trust_dns_client::op::OpCode::Query => {
                debug!("query received: {}", request_message.msg.id());
                QUERY_COUNTER.with_label_values(&["query"]).inc();
                let timer = QUERY_RESPONSE_TIME.with_label_values(&["query"]).start_timer();
                let timer_axfr = QUERY_RESPONSE_TIME.with_label_values(&["axfr"]).start_timer();

                if request_message.query.query_type() == trust_dns_proto::rr::record_type::RecordType::AXFR {
                    let mut client = cache.client.clone();
                    let raw_bytes = request_message.raw_bytes.clone();
                    let s = async_stream::stream! {
                        let request = tonic::Request::new(dns_proto::DnsPacket {
                            msg: raw_bytes
                        });
                        let rpc_response = match client.axfr_query(request).await {
                            Ok(x) => x,
                            Err(e) => {
                                error!("Error communicating with upstream: {}", e);
                                UPSTREAM_QUERY_COUNTER.with_label_values(&["error_axfr"]).inc();
                                yield Err(trust_dns_client::op::ResponseCode::ServFail);
                                return;
                            }
                        };
                        let mut response_stream = rpc_response.into_inner();
                        while let Some(next_message) = match response_stream.message().await {
                            Ok(x) => x,
                            Err(e) => {
                                error!("Error communicating with upstream: {}", e);
                                UPSTREAM_QUERY_COUNTER.with_label_values(&["error_axfr"]).inc();
                                yield Err(trust_dns_client::op::ResponseCode::ServFail);
                                return;
                            }
                        } {
                            let response_msg = match trust_dns_proto::op::message::Message::from_bytes(&next_message.msg) {
                                Ok(x) => x,
                                Err(e) => {
                                    error!("Error parsing response from upstream: {}", e);
                                    UPSTREAM_QUERY_COUNTER.with_label_values(&["error_axfr"]).inc();
                                    yield Err(trust_dns_client::op::ResponseCode::ServFail);
                                    return;
                                }
                            };
                            UPSTREAM_QUERY_COUNTER.with_label_values(&["ok_axfr"]).inc();
                            yield Ok(response_msg);
                        }
                    };
                    futures_util::pin_mut!(s);
                    while let Some(val) = s.next().await {
                        match val {
                            Ok(mut response_msg) => {
                                let mut edns = if let Some(edns) = response_msg.edns() {
                                    edns.to_owned()
                                } else {
                                    trust_dns_proto::op::Edns::new()
                                };
                                if nsid_requested {
                                    if let Some(server_name) = &cache.config.server_name {
                                        edns.options_mut().insert(trust_dns_proto::rr::rdata::opt::EdnsOption::Unknown(
                                            trust_dns_proto::rr::rdata::opt::EdnsCode::NSID.into(),
                                            server_name.to_vec(),
                                        ))
                                    }
                                }
                                response_msg.set_edns(edns);
                                RESPONSE_COUNTER.with_label_values(&["ok_axfr"]).inc();
                                request_context.respond(response_msg).await;
                            }
                            Err(e) => {
                                RESPONSE_COUNTER.with_label_values(&["error_axfr"]).inc();
                                let response_msg = trust_dns_proto::op::Message::error_msg(
                                    request_message.msg.id(), request_message.msg.op_code(), e
                                );
                                request_context.respond(response_msg).await;
                            }
                        }
                    }
                    timer.stop_and_discard();
                    timer_axfr.observe_duration();
                } else {
                    let mut timeout_response_msg = trust_dns_proto::op::Message::error_msg(
                        request_message.msg.id(), request_message.msg.op_code(),
                        trust_dns_client::op::ResponseCode::ServFail,
                    );
                    let mut edns = trust_dns_proto::op::Edns::new();
                    if nsid_requested {
                        if let Some(server_name) = &cache.config.server_name {
                            edns.options_mut().insert(trust_dns_proto::rr::rdata::opt::EdnsOption::Unknown(
                                trust_dns_proto::rr::rdata::opt::EdnsCode::NSID.into(),
                                server_name.to_vec(),
                            ))
                        }
                    }
                    timeout_response_msg.set_edns(edns);
                    let timeout_request_context = request_context.clone();
                    let handle = tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        RESPONSE_COUNTER.with_label_values(&["timeout"]).inc();
                        warn!("Timeout talking to upstream");
                        timeout_request_context.respond(timeout_response_msg).await;
                    });
                    match lookup_cache_or_fetch(&request_message, &mut cache.client.clone(), &cache.cache, &cache.in_flight).await {
                        Ok(mut r) => {
                            handle.abort();
                            RESPONSE_COUNTER.with_label_values(&["ok"]).inc();
                            let mut edns = if let Some(edns) = r.edns() {
                                edns.to_owned()
                            } else {
                                trust_dns_proto::op::Edns::new()
                            };
                            if nsid_requested {
                                if let Some(server_name) = &cache.config.server_name {
                                    edns.options_mut().insert(trust_dns_proto::rr::rdata::opt::EdnsOption::Unknown(
                                        trust_dns_proto::rr::rdata::opt::EdnsCode::NSID.into(),
                                        server_name.to_vec(),
                                    ))
                                }
                            }
                            r.set_edns(edns);
                            timer_axfr.stop_and_discard();
                            timer.observe_duration();
                            request_context.respond(r).await;
                        }
                        Err(e) => {
                            handle.abort();
                            RESPONSE_COUNTER.with_label_values(&["error"]).inc();
                            let mut response_msg = trust_dns_proto::op::Message::error_msg(
                                request_message.msg.id(), request_message.msg.op_code(), e
                            );
                            let mut edns = trust_dns_proto::op::Edns::new();
                            if nsid_requested {
                                if let Some(server_name) = &cache.config.server_name {
                                    edns.options_mut().insert(trust_dns_proto::rr::rdata::opt::EdnsOption::Unknown(
                                        trust_dns_proto::rr::rdata::opt::EdnsCode::NSID.into(),
                                        server_name.to_vec(),
                                    ))
                                }
                            }
                            response_msg.set_edns(edns);
                            timer_axfr.stop_and_discard();
                            timer.observe_duration();
                            request_context.respond(response_msg).await;
                        }
                    }
                }
            }
            trust_dns_client::op::OpCode::Update => {
                debug!("update received: {}", request_message.msg.id());
                QUERY_COUNTER.with_label_values(&["update"]).inc();
                let timer = QUERY_RESPONSE_TIME.with_label_values(&["update"]).start_timer();
                let raw_bytes = request_message.raw_bytes.clone();
                let val = async {
                    let request = tonic::Request::new(dns_proto::DnsPacket {
                        msg: raw_bytes
                    });
                    let rpc_response = match cache.client.clone().update_query(request).await {
                        Ok(x) => x,
                        Err(e) => {
                            error!("Error communicating with upstream: {}", e);
                            UPSTREAM_QUERY_COUNTER.with_label_values(&["error_update"]).inc();
                            RESPONSE_COUNTER.with_label_values(&["error_update"]).inc();
                            return Err(trust_dns_client::op::ResponseCode::ServFail);
                        }
                    };
                    UPSTREAM_QUERY_COUNTER.with_label_values(&["ok_update"]).inc();
                    let response = rpc_response.into_inner();
                    let response_msg = match trust_dns_proto::op::message::Message::from_bytes(&response.msg) {
                        Ok(x) => x,
                        Err(e) => {
                            error!("Error parsing response from upstream: {}", e);
                            RESPONSE_COUNTER.with_label_values(&["error_update"]).inc();
                            return Err(trust_dns_client::op::ResponseCode::ServFail);
                        }
                    };
                    RESPONSE_COUNTER.with_label_values(&["ok_update"]).inc();
                    Ok(response_msg)
                }.await;
                match val {
                    Ok(response_msg) => {
                        request_context.respond(response_msg).await;
                    }
                    Err(e) => {
                        let mut response_msg = trust_dns_proto::op::Message::error_msg(
                            request_message.msg.id(), request_message.msg.op_code(), e
                        );
                        let mut edns = trust_dns_proto::op::Edns::new();
                        if nsid_requested {
                            if let Some(server_name) = &cache.config.server_name {
                                edns.options_mut().insert(trust_dns_proto::rr::rdata::opt::EdnsOption::Unknown(
                                    trust_dns_proto::rr::rdata::opt::EdnsCode::NSID.into(),
                                    server_name.to_vec(),
                                ))
                            }
                        }
                        response_msg.set_edns(edns);
                        request_context.respond(response_msg).await;
                    }
                }
                timer.observe_duration();
            }
            c => {
                warn!("unimplemented op_code: {:?}", c);
                QUERY_COUNTER.with_label_values(&["unknown"]).inc();
                let mut response_msg = trust_dns_proto::op::Message::error_msg(
                    request_message.msg.id(), request_message.msg.op_code(),
                    trust_dns_client::op::ResponseCode::NotImp,
                );
                let mut edns = trust_dns_proto::op::Edns::new();
                if nsid_requested {
                    if let Some(server_name) = &cache.config.server_name {
                        edns.options_mut().insert(trust_dns_proto::rr::rdata::opt::EdnsOption::Unknown(
                            trust_dns_proto::rr::rdata::opt::EdnsCode::NSID.into(),
                            server_name.to_vec(),
                        ))
                    }
                }
                response_msg.set_edns(edns);
                request_context.respond(response_msg).await;
            }
        },
        trust_dns_client::op::MessageType::Response => {
            warn!(
                "got a response as a request from id: {}",
                request_message.msg.id()
            );
            QUERY_COUNTER.with_label_values(&["response"]).inc();
            let mut response_msg = trust_dns_proto::op::Message::error_msg(
                request_message.msg.id(), request_message.msg.op_code(),
                trust_dns_client::op::ResponseCode::FormErr,
            );
            let mut edns = trust_dns_proto::op::Edns::new();
            if nsid_requested {
                if let Some(server_name) = &cache.config.server_name {
                    edns.options_mut().insert(trust_dns_proto::rr::rdata::opt::EdnsOption::Unknown(
                        trust_dns_proto::rr::rdata::opt::EdnsCode::NSID.into(),
                        server_name.to_vec(),
                    ))
                }
            }
            response_msg.set_edns(edns);
            request_context.respond(response_msg).await;
        }
    }
}

fn rabbitmq_listener(flusher_cache: Arc<Mutex<lru::LruCache<CacheKey, CacheData>>>, rpc_url: String) -> ! {
    loop {
        info!("Starting RabbitMQ listener");
        let mut amqp_conn = amiquip::Connection::insecure_open(&rpc_url).expect("Unable to connect to RabbitMQ server");
        let amqp_channel = amqp_conn.open_channel(None).expect("Unable to open RabbitMQ channel");

        let listen_queue = amqp_channel.queue_declare("", amiquip::QueueDeclareOptions {
            exclusive: true,
            ..amiquip::QueueDeclareOptions::default()
        }).expect("Unable to declare RabbitMQ queue");
        let flush_exchange = amqp_channel.exchange_declare(
            amiquip::ExchangeType::Fanout,
            "hexdns_flush",
            amiquip::ExchangeDeclareOptions {
                durable: true,
                ..amiquip::ExchangeDeclareOptions::default()
            },
        ).expect("Unable to declare RabbitMQ exchange");
        amqp_channel.queue_bind(
            listen_queue.name(), flush_exchange.name(), "",
            amiquip::FieldTable::new(),
        ).expect("Unable to bind RabbitMQ queue to exchange");
        let flush_consumer = listen_queue.consume(amiquip::ConsumerOptions::default()).expect("Unable to start consuming on RabbitMQ queue");
        info!("RabbitMQ listener started");
        for message in flush_consumer.receiver().iter() {
            let server_cache = flusher_cache.clone();
            match message {
                amiquip::ConsumerMessage::Delivery(delivery) => {
                    flush_consumer.ack(delivery.clone()).unwrap();
                    let body = delivery.body.clone();
                    match dns_proto::ClearCache::decode(&body[..]) {
                        Ok(clear_message) => {
                            trace!("Got clear cache message: {:#?}", clear_message);
                            let name = match trust_dns_proto::rr::domain::Name::from_str(&clear_message.label) {
                                Ok(n) => n,
                                Err(_) => continue
                            };
                            let qclass = match trust_dns_proto::rr::dns_class::DNSClass::from_u16(clear_message.dns_class as u16) {
                                Ok(n) => n,
                                Err(_) => continue
                            };
                            let qtype = trust_dns_proto::rr::record_type::RecordType::from(clear_message.record_type as u16);
                            let mut keys_to_clear = vec![];

                            let mut add_key = |qclass| {
                                if qtype.is_any() {
                                    for qtype in &KNOWN_RECORD_TYPES {
                                        keys_to_clear.push(CacheKey {
                                            name: trust_dns_client::rr::LowerName::new(&name),
                                            qclass,
                                            qtype: *qtype,
                                            is_dnssec: false,
                                        });
                                        keys_to_clear.push(CacheKey {
                                            name: trust_dns_client::rr::LowerName::new(&name),
                                            qclass,
                                            qtype: *qtype,
                                            is_dnssec: true,
                                        });
                                    }
                                } else {
                                    keys_to_clear.push(CacheKey {
                                        name: trust_dns_client::rr::LowerName::new(&name),
                                        qclass,
                                        qtype,
                                        is_dnssec: false,
                                    });
                                    keys_to_clear.push(CacheKey {
                                        name: trust_dns_client::rr::LowerName::new(&name),
                                        qclass,
                                        qtype,
                                        is_dnssec: true,
                                    });
                                }
                            };

                            if qclass == trust_dns_proto::rr::dns_class::DNSClass::ANY {
                                add_key(trust_dns_proto::rr::dns_class::DNSClass::IN);
                                add_key(trust_dns_proto::rr::dns_class::DNSClass::CH);
                                add_key(trust_dns_proto::rr::dns_class::DNSClass::HS);
                            } else {
                                add_key(qclass);
                            }

                            trace!("Going to clear keys: {:#?}", keys_to_clear);

                            tokio::spawn(async move {
                                for key in keys_to_clear {
                                    server_cache.lock().await.pop(&key);
                                }
                            });
                        }
                        Err(e) => {
                            warn!("Unable to decode RPC message: {}", e);
                        }
                    }
                }
                amiquip::ConsumerMessage::ServerClosedChannel(err)
                | amiquip::ConsumerMessage::ServerClosedConnection(err) => {
                    error!("Error or RabbitMQ, restarting: {}", err);
                }
                amiquip::ConsumerMessage::ClientCancelled
                | amiquip::ConsumerMessage::ServerCancelled
                | amiquip::ConsumerMessage::ClientClosedChannel
                | amiquip::ConsumerMessage::ClientClosedConnection => {
                    break;
                }
            }
        }
        std::thread::sleep(std::time::Duration::new(15, 0));
    }
}

async fn cache_updater(
    mut updater_cache: Arc<Mutex<lru::LruCache<CacheKey, CacheData>>>,
    mut updater_in_flight: Arc<flurry::HashSet<CacheKey>>,
    mut client: dns_proto::dns_service_client::DnsServiceClient<tonic::transport::Channel>
) -> ! {
    loop {
        info!("Starting cache updater");
        tokio::time::sleep(std::time::Duration::new(60, 0)).await;

        let mut to_update = vec![];

        for (cache_key, cache_record) in updater_cache.lock().await.iter() {
            if cache_record.valid_until < std::time::Instant::now() {
                let mut msg = trust_dns_proto::op::message::Message::new();
                let mut edns = trust_dns_proto::op::Edns::new();
                msg.set_id(0);
                msg.set_message_type(trust_dns_proto::op::MessageType::Query);
                msg.set_op_code(trust_dns_proto::op::OpCode::Query);
                edns.set_dnssec_ok(cache_key.is_dnssec);
                msg.set_edns(edns);
                let mut query = trust_dns_proto::op::Query::new();
                query.set_query_class(cache_key.qclass);
                query.set_query_type(cache_key.qtype);
                query.set_name(cache_key.name.clone().into());
                msg.add_query(query.clone());

                to_update.push((cache_key.clone(), msg, trust_dns_client::op::LowerQuery::query(query)));
            }
        }

        for (cache_key, msg, query) in to_update {
            let _ = fetch_and_insert(cache_key, &dns_cache::Request {
                raw_bytes: msg.to_bytes().unwrap(),
                msg,
                query
            }, &mut client, &mut updater_cache, &mut updater_in_flight, false).await;
        }
    }
}

fn main() {
    pretty_env_logger::init();

    let args = clap::App::new(clap::crate_name!())
        .about(clap::crate_description!())
        .version(clap::crate_version!())
        .author(clap::crate_authors!(", "))
        .arg(clap::Arg::with_name("port")
            .short("p")
            .long("port")
            .env("DNS_PORT")
            .help("Port to listen on for DNS queries")
            .takes_value(true)
            .default_value("53"))
        .arg(clap::Arg::with_name("addr")
            .short("a")
            .long("addr")
            .env("DNS_ADDR")
            .help("Addresses to listen on for DNS queries")
            .takes_value(true)
            .multiple(true)
            .default_value("::"))
        .arg(clap::Arg::with_name("name")
            .short("n")
            .long("name")
            .env("DNS_SERVER_NAME")
            .help("Name to uso for NSID")
            .takes_value(true))
        .arg(clap::Arg::with_name("upstream")
            .short("u")
            .long("upstream")
            .env("DNS_UPSTREAM")
            .required(true)
            .help("gRPC upstream server (e.g. http://[::1]:50051)")
            .takes_value(true))
        .arg(clap::Arg::with_name("rpc_server")
            .short("r")
            .long("rpc-server")
            .env("RABBITMQ_RPC_URL")
            .help("Connection URL for the RabbitMQ server")
            .takes_value(true)
            .required(false))
        .get_matches();

    let ip_addrs = clap::values_t_or_exit!(args, "addr", std::net::IpAddr);
    let port = clap::value_t_or_exit!(args, "port", u16);

    let sockaddrs: Vec<std::net::SocketAddr> = ip_addrs.into_iter()
        .map(|a| std::net::SocketAddr::new(a, port)).collect();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(1024)
        .event_interval(120)
        .worker_threads(16)
        .enable_all()
        .build()
        .expect("failed to initialize Tokio Runtime");

    let client = runtime.block_on(
        dns_proto::dns_service_client::DnsServiceClient::connect(args.value_of("upstream").unwrap().to_string())
    ).expect("Unable to connect to upstream server");

    // let tcp_request_timeout = std::time::Duration::from_secs(5);
    let server_cache = Arc::new(Mutex::new(lru::LruCache::new(65535)));
    let server_in_flight = Arc::new(flurry::HashSet::new());

    let cache = Cache {
        client: client.clone(),
        cache: server_cache.clone(),
        in_flight: server_in_flight.clone(),
        config: Arc::new(Config {
            server_name: args.value_of("name").map(|s| s.to_string().into_bytes())
        }),
    };

    info!("starting prometheus exporter on [::]:9184");
    prometheus_exporter::start("[::]:9184".parse().unwrap()).unwrap();

    if let Some(rpc_url) = args.value_of("rpc_server") {
        let flusher_cache = server_cache.clone();
        let rpc_url = rpc_url.to_owned();
        runtime.spawn_blocking(move || {
            rabbitmq_listener(flusher_cache, rpc_url);
        });
    }

    let updater_cache = server_cache.clone();
    let updater_in_flight = server_in_flight.clone();
    runtime.spawn(async move {
        cache_updater(updater_cache, updater_in_flight, client).await;
    });

    let server = dns_cache::Server {
        sockaddrs,
        handler: handle_request,
        context: cache
    };

    info!("Server starting up");
    match runtime.block_on(server.start_server()) {
        Ok(()) => {
            info!("stopping...");
        }
        Err(e) => {
            let error_msg = format!(
                "Error: {}",
                e
            );

            error!("{}", error_msg);
            panic!("{}", error_msg);
        }
    };
}
