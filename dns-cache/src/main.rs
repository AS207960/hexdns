#![feature(proc_macro_hygiene)]
#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
#[macro_use]
extern crate prometheus;
#[macro_use]
extern crate lazy_static;

use std::ops::Deref;
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

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
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
    msg: &trust_dns_server::authority::MessageRequest,
    client: &mut dns_proto::dns_service_client::DnsServiceClient<tonic::transport::Channel>,
    cache: &Arc<Mutex<lru::LruCache<CacheKey, CacheData>>>,
    in_flight: &Arc<Mutex<std::collections::HashSet<CacheKey>>>,
    new: bool,
) -> Result<trust_dns_proto::op::Message, trust_dns_client::op::ResponseCode> {
    let mut in_flight_lock = in_flight.lock().await;
    in_flight_lock.insert(cache_key.clone());

    let request = tonic::Request::new(dns_proto::DnsPacket {
        msg: msg.to_bytes().map_err(|_| {
            in_flight_lock.remove(&cache_key);
            trust_dns_client::op::ResponseCode::FormErr
        })?
    });
    let timer = UPSTREAM_RESPONSE_TIME.start_timer();
    std::mem::drop(in_flight_lock);
    let r_response = client.query(request).await;
    let mut in_flight_lock = in_flight.lock().await;
    timer.observe_duration();
    let response = r_response.map_err(|e| {
        error!("Error communicating with upstream: {}", e);
        UPSTREAM_QUERY_COUNTER.with_label_values(&["error"]).inc();
        in_flight_lock.remove(&cache_key);
        trust_dns_client::op::ResponseCode::ServFail
    })?;
    let response_msg = trust_dns_proto::op::message::Message::from_bytes(&response.into_inner().msg).map_err(|e| {
        error!("Error parsing response from upstream: {}", e);
        UPSTREAM_QUERY_COUNTER.with_label_values(&["error"]).inc();
        in_flight_lock.remove(&cache_key);
        trust_dns_client::op::ResponseCode::ServFail
    })?;

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

    in_flight_lock.remove(&cache_key);

    Ok(response_msg)
}

async fn lookup_cache_or_fetch(
    msg: &trust_dns_server::authority::MessageRequest,
    client: &mut dns_proto::dns_service_client::DnsServiceClient<tonic::transport::Channel>,
    cache: &Arc<Mutex<lru::LruCache<CacheKey, CacheData>>>,
    in_flight: &Arc<Mutex<std::collections::HashSet<CacheKey>>>,
) -> Result<trust_dns_proto::op::message::Message, trust_dns_client::op::ResponseCode> {
    let dnssec = match msg.edns() {
        Some(e) => e.dnssec_ok(),
        None => false,
    };
    let query = msg.query();
    let cache_key = CacheKey {
        name: query.name().to_owned(),
        qclass: query.query_class(),
        qtype: query.query_type(),
        is_dnssec: dnssec,
    };

    loop {
        if in_flight.lock().await.contains(&cache_key) {
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
                let msg = msg.to_bytes().unwrap();
                let mut client = client.clone();
                let mut cache = cache.clone();
                let mut in_flight = in_flight.clone();
                CACHE_COUNTER.with_label_values(&["hit_stale"]).inc();
                tokio::spawn(async move {
                    let msg = trust_dns_server::authority::MessageRequest::from_bytes(&msg).unwrap();
                    let _ = fetch_and_insert(cache_key, &msg, &mut client, &mut cache, &mut in_flight, false).await;
                });
            } else {
                CACHE_COUNTER.with_label_values(&["hit"]).inc();
            }
            let mut response_msg = trust_dns_proto::op::message::Message::new();
            let mut edns = cached_result.edns;
            response_msg.set_id(msg.id());
            response_msg.set_message_type(trust_dns_proto::op::MessageType::Response);
            response_msg.set_op_code(trust_dns_proto::op::OpCode::Query);
            response_msg.set_authoritative(true);
            edns.set_dnssec_ok(dnssec);
            response_msg.set_edns(edns);
            response_msg.set_response_code(cached_result.response_code);
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

struct Cache {
    client: dns_proto::dns_service_client::DnsServiceClient<tonic::transport::Channel>,
    cache: Arc<Mutex<lru::LruCache<CacheKey, CacheData>>>,
    in_flight: Arc<Mutex<std::collections::HashSet<CacheKey>>>,
    config: Arc<Config>,
}

#[async_trait::async_trait]
impl trust_dns_server::server::RequestHandler for Cache {
    async fn handle_request<R: trust_dns_server::server::ResponseHandler>(&self, request: &trust_dns_server::server::Request, mut response_handle: R) -> trust_dns_server::server::ResponseInfo {
        let request_message: &trust_dns_server::authority::MessageRequest = request.deref();
        trace!("request: {:?}", request_message);

        match request_message.message_type() {
            trust_dns_client::op::MessageType::Query => match request_message.op_code() {
                trust_dns_client::op::OpCode::Query => {
                    debug!("query received: {}", request_message.id());
                    QUERY_COUNTER.with_label_values(&["query"]).inc();
                    let timer = QUERY_RESPONSE_TIME.with_label_values(&["query"]).start_timer();
                    let timer_axfr = QUERY_RESPONSE_TIME.with_label_values(&["axfr"]).start_timer();
                    let mut response = trust_dns_server::authority::MessageResponseBuilder::from_message_request(&request_message);

                    let mut msg = trust_dns_proto::op::message::Message::new();
                    msg.set_id(request_message.id());
                    msg.set_message_type(trust_dns_proto::op::MessageType::Query);
                    msg.set_op_code(trust_dns_proto::op::OpCode::Query);
                    let mut nsid_requested = false;
                    if let Some(edns) = request_message.edns() {
                        msg.set_edns(edns.to_owned());
                        if edns.version() > 0 {
                            warn!(
                                "request edns version greater than 0: {}",
                                edns.version()
                            );
                            RESPONSE_COUNTER.with_label_values(&["invalid_edns"]).inc();
                            let mut res_edns = trust_dns_proto::op::Edns::new();
                            res_edns.set_version(0);
                            response.edns(res_edns);

                            let res = response_handle.send_response(response.error_msg(
                                &request_message.header(),
                                trust_dns_client::op::ResponseCode::BADVERS,
                            )).await;
                            timer_axfr.stop_and_discard();
                            timer.observe_duration();
                            match res {
                                Ok(r) => return r,
                                Err(err) => {
                                    error!("Failed to send response: {}", err);
                                    return request_message.header().to_owned().into();
                                }
                            }
                        }
                        nsid_requested = edns.option(trust_dns_proto::rr::rdata::opt::EdnsCode::NSID).is_some();
                    }

                    if request_message.query().query_type() == trust_dns_proto::rr::record_type::RecordType::AXFR {
                        let request_bytes = request_message.to_bytes();
                        let mut client = self.client.clone();
                        let s = async_stream::stream! {
                            let request = tonic::Request::new(dns_proto::DnsPacket {
                                msg: match request_bytes {
                                    Ok(b) => b,
                                    Err(_) => {
                                        yield Err(trust_dns_client::op::ResponseCode::FormErr);
                                        return;
                                    }
                                }
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
                            let mut response = trust_dns_server::authority::MessageResponseBuilder::from_message_request(&request_message);
                            match val {
                                Ok(response_msg) => {
                                    let mut edns = if let Some(edns) = response_msg.edns() {
                                        edns.to_owned()
                                    } else {
                                        trust_dns_proto::op::Edns::new()
                                    };
                                    if nsid_requested {
                                        if let Some(server_name) = &self.config.server_name {
                                            edns.options_mut().insert(trust_dns_proto::rr::rdata::opt::EdnsOption::Unknown(
                                                trust_dns_proto::rr::rdata::opt::EdnsCode::NSID.into(),
                                                server_name.to_vec(),
                                            ))
                                        }
                                    }
                                    response.edns(edns);
                                    RESPONSE_COUNTER.with_label_values(&["ok_axfr"]).inc();
                                    match response_handle.send_response(response.build(
                                        response_msg.header().to_owned(),
                                        Box::new(response_msg.answers().iter()) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                        Box::new(response_msg.name_servers().iter()) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                        Box::new(vec![].iter()) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                        Box::new(response_msg.additionals().iter()) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                    )).await {
                                        Ok(_) => {},
                                        Err(err) => {
                                            error!("Failed to send response: {}", err);
                                            return request_message.header().to_owned().into();
                                        }
                                    }
                                }
                                Err(e) => {
                                    RESPONSE_COUNTER.with_label_values(&["error_axfr"]).inc();
                                    match response_handle.send_response(response.error_msg(
                                        request_message.header(),
                                        e,
                                    )).await {
                                        Ok(_) => {},
                                        Err(err) => {
                                            error!("Failed to send response: {}", err);
                                            return request_message.header().to_owned().into();
                                        }
                                    }
                                }
                            }
                        }
                        timer.stop_and_discard();
                        timer_axfr.observe_duration();
                        request_message.header().to_owned().into()
                    } else {
                        match match lookup_cache_or_fetch(request_message, &mut self.client.clone(), &self.cache, &self.in_flight).await {
                            Ok(r) => {
                                RESPONSE_COUNTER.with_label_values(&["ok"]).inc();
                                let mut edns = if let Some(edns) = r.edns() {
                                    edns.to_owned()
                                } else {
                                    trust_dns_proto::op::Edns::new()
                                };
                                if nsid_requested {
                                    if let Some(server_name) = &self.config.server_name {
                                        edns.options_mut().insert(trust_dns_proto::rr::rdata::opt::EdnsOption::Unknown(
                                            trust_dns_proto::rr::rdata::opt::EdnsCode::NSID.into(),
                                            server_name.to_vec(),
                                        ))
                                    }
                                }
                                let mut response_msg = trust_dns_server::authority::MessageResponseBuilder::from_message_request(&request_message);
                                response_msg.edns(edns);
                                let res = response_handle.send_response(response_msg.build(
                                    r.header().clone(),
                                    r.answers(),
                                    r.name_servers(),
                                    vec![],
                                    r.additionals()
                                )).await;
                                timer_axfr.stop_and_discard();
                                timer.observe_duration();
                                res
                            }
                            Err(e) => {
                                RESPONSE_COUNTER.with_label_values(&["error"]).inc();
                                let res = response_handle.send_response(response.error_msg(
                                    request_message.header(),
                                    e,
                                )).await;
                                timer_axfr.stop_and_discard();
                                timer.observe_duration();
                                res
                            }
                        } {
                            Ok(r) => r,
                            Err(err) => {
                                error!("Failed to send response: {}", err);
                                request_message.header().to_owned().into()
                            }
                        }
                    }
                }
                trust_dns_client::op::OpCode::Update => {
                    debug!("update received: {}", request_message.id());
                    QUERY_COUNTER.with_label_values(&["update"]).inc();
                    let timer = QUERY_RESPONSE_TIME.with_label_values(&["update"]).start_timer();
                    let request_bytes = request_message.to_bytes();
                    let val = async move {
                        let request = tonic::Request::new(dns_proto::DnsPacket {
                            msg: match request_bytes {
                                Ok(b) => b,
                                Err(_) => {
                                    RESPONSE_COUNTER.with_label_values(&["invalid_update"]).inc();
                                    return Err(trust_dns_client::op::ResponseCode::ServFail);
                                }
                            }
                        });
                        let rpc_response = match self.client.clone().update_query(request).await {
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
                    let response = trust_dns_server::authority::MessageResponseBuilder::from_message_request(&request_message);
                    let res = match val {
                        Ok(response_msg) => {
                            response_handle.send_response(response.build(
                                response_msg.header().to_owned(),
                                Box::new(response_msg.answers().iter()) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                Box::new(response_msg.name_servers().iter()) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                Box::new(vec![].iter()) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                Box::new(response_msg.additionals().iter()) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                            )).await
                        }
                        Err(e) => {
                            response_handle.send_response(response.error_msg(
                                request_message.header(),
                                e,
                            )).await
                        }
                    };
                    timer.observe_duration();
                    match res {
                        Ok(r) => r,
                        Err(err) => {
                            error!("Failed to send response: {}", err);
                            request_message.header().to_owned().into()
                        }
                    }
                }
                c => {
                    warn!("unimplemented op_code: {:?}", c);
                    QUERY_COUNTER.with_label_values(&["unknown"]).inc();
                    let response = trust_dns_server::authority::MessageResponseBuilder::from_message_request(&request_message);
                    match response_handle.send_response(response.error_msg(
                        request_message.header(),
                        trust_dns_client::op::ResponseCode::NotImp,
                    )).await {
                        Ok(r) => r,
                        Err(err) => {
                            error!("Failed to send response: {}", err);
                            request_message.header().to_owned().into()
                        }
                    }
                }
            },
            trust_dns_client::op::MessageType::Response => {
                warn!(
                    "got a response as a request from id: {}",
                    request_message.id()
                );
                QUERY_COUNTER.with_label_values(&["response"]).inc();
                let response = trust_dns_server::authority::MessageResponseBuilder::from_message_request(&request_message);

                match response_handle.send_response(response.error_msg(
                    request_message.header(),
                    trust_dns_client::op::ResponseCode::FormErr,
                )).await {
                    Ok(r) => r,
                    Err(err) => {
                        error!("Failed to send response: {}", err);
                        request_message.header().to_owned().into()
                    }
                }
            }
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
        .enable_all()
        .build()
        .expect("failed to initialize Tokio Runtime");

    let mut client = runtime.block_on(
        dns_proto::dns_service_client::DnsServiceClient::connect(args.value_of("upstream").unwrap().to_string())
    ).expect("Unable to connect to upstream server");

    let tcp_request_timeout = std::time::Duration::from_secs(5);
    let server_cache = Arc::new(Mutex::new(lru::LruCache::new(65535)));
    let server_in_flight = Arc::new(Mutex::new(std::collections::HashSet::new()));

    let catalog = Cache {
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
        });
    }

    let mut updater_cache = server_cache.clone();
    let mut updater_in_flight = server_in_flight.clone();
    runtime.spawn(async move {
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
                    msg.add_query(query);

                    to_update.push((cache_key.clone(), msg));
                }
            }

            for (cache_key, msg) in to_update {
                let msg = trust_dns_server::authority::MessageRequest::from_bytes(&msg.to_bytes().unwrap()).unwrap();
                let _ = fetch_and_insert(cache_key, &msg, &mut client, &mut updater_cache, &mut updater_in_flight, false).await;
            }
        }
    });

    let mut server = trust_dns_server::ServerFuture::new(catalog);

    for udp_socket in &sockaddrs {
        info!("binding UDP to {:?}", udp_socket);
        let udp_socket = runtime.block_on(tokio::net::UdpSocket::bind(udp_socket))
            .expect("Could not bind to UDP socket");

        info!(
            "listening for UDP on {:?}",
            udp_socket
                .local_addr()
                .expect("could not lookup local address")
        );

        {
            let _guard = runtime.enter();
            server.register_socket(udp_socket)
        }
    }

    for tcp_listener in &sockaddrs {
        info!("binding TCP to {:?}", tcp_listener);
        let tcp_listener = runtime.block_on(tokio::net::TcpListener::bind(tcp_listener))
            .expect("Could not bind to TCP socket");

        info!(
            "listening for TCP on {:?}",
            tcp_listener
                .local_addr()
                .expect("could not lookup local address")
        );


        {
            let _guard = runtime.enter();
            server.register_listener(tcp_listener, tcp_request_timeout)
        }
    }

    info!("Server starting up");
    match runtime.block_on(server.block_until_done()) {
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
