#![feature(proc_macro_hygiene)]
#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
#[macro_use]
extern crate prometheus;
#[macro_use]
extern crate lazy_static;

use prometheus::Encoder;
use futures::future::Future;
use futures::stream::StreamExt;
use tokio::sync::Mutex;
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

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

#[derive(PartialEq, Eq, Hash)]
struct CacheKey {
    name: trust_dns_proto::rr::domain::Name,
    qclass: trust_dns_proto::rr::dns_class::DNSClass,
    qtype: trust_dns_proto::rr::record_type::RecordType,
    is_dnssec: bool,
}

#[derive(Debug, Clone)]
struct CacheData {
    valid_until: std::time::Instant,
    response_code: trust_dns_proto::op::ResponseCode,
    answers: Vec<trust_dns_proto::rr::resource::Record>,
    name_servers: Vec<trust_dns_proto::rr::resource::Record>,
    additionals: Vec<trust_dns_proto::rr::resource::Record>,
}

pub enum HandleRequest {
    LookupFuture(std::pin::Pin<Box<dyn Future<Output=()> + Send>>),
    Result(tokio::io::Result<()>),
}

impl HandleRequest {
    fn lookup(lookup_future: impl Future<Output=()> + Send + 'static) -> Self {
        let lookup = Box::pin(lookup_future) as std::pin::Pin<Box<dyn Future<Output=()> + Send>>;
        HandleRequest::LookupFuture(lookup)
    }

    fn result(result: tokio::io::Result<()>) -> Self {
        HandleRequest::Result(result)
    }
}

impl Future for HandleRequest {
    type Output = ();

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut futures::task::Context) -> futures::task::Poll<Self::Output> {
        match *self {
            HandleRequest::LookupFuture(ref mut lookup) => lookup.as_mut().poll(cx),
            HandleRequest::Result(Ok(_)) => futures::task::Poll::Ready(()),
            HandleRequest::Result(Err(ref res)) => {
                error!("request failed: {}", res);
                futures::task::Poll::Ready(())
            }
        }
    }
}

async fn fetch_and_insert(
    cache_key: CacheKey,
    msg: trust_dns_proto::op::message::Message,
    mut client: dns_proto::dns_service_client::DnsServiceClient<tonic::transport::Channel>,
    cache: &mut Arc<Mutex<lru::LruCache<CacheKey, CacheData>>>,
) -> Result<trust_dns_proto::op::message::Message, trust_dns_client::op::ResponseCode> {
    let request = tonic::Request::new(dns_proto::DnsPacket {
        msg: msg.to_bytes().map_err(|_| trust_dns_client::op::ResponseCode::FormErr)?
    });
    let timer = UPSTREAM_RESPONSE_TIME.start_timer();
    let r_response = client.query(request).await;
    timer.observe_duration();
    let response = r_response.map_err(|e| {
        error!("Error communicating with upstream: {}", e);
        UPSTREAM_QUERY_COUNTER.with_label_values(&["error"]).inc();
        trust_dns_client::op::ResponseCode::ServFail
    })?;
    let response_msg = trust_dns_proto::op::message::Message::from_bytes(&response.into_inner().msg).map_err(|e| {
        error!("Error parsing response from upstream: {}", e);
        UPSTREAM_QUERY_COUNTER.with_label_values(&["error"]).inc();
        trust_dns_client::op::ResponseCode::ServFail
    })?;

    UPSTREAM_QUERY_COUNTER.with_label_values(&["ok"]).inc();
    let new_cache_data = CacheData {
        valid_until: std::time::Instant::now() + std::time::Duration::from_secs(30),
        response_code: response_msg.response_code(),
        answers: response_msg.answers().to_vec(),
        name_servers: response_msg.name_servers().to_vec(),
        additionals: response_msg.additionals().to_vec(),
    };
    cache.lock().await.put(cache_key, new_cache_data);

    Ok(response_msg)
}

async fn lookup_cache_or_fetch(
    msg: trust_dns_proto::op::message::Message,
    client: dns_proto::dns_service_client::DnsServiceClient<tonic::transport::Channel>,
    mut cache: Arc<Mutex<lru::LruCache<CacheKey, CacheData>>>,
) -> Result<trust_dns_proto::op::message::Message, trust_dns_client::op::ResponseCode> {
    let dnssec = match msg.edns() {
        Some(e) => e.dnssec_ok(),
        None => false,
    };
    let query = msg.queries().first().unwrap();
    let cache_key = CacheKey {
        name: query.name().to_owned(),
        qclass: query.query_class(),
        qtype: query.query_type(),
        is_dnssec: dnssec,
    };
    let cached_result = match cache.lock().await.get(&cache_key) {
        Some(c) => Some(c.to_owned()),
        None => None
    };

    if let Some(cached_result) = cached_result {
        if cached_result.valid_until < std::time::Instant::now() {
            debug!("Expired cached item");
            let msg = msg.clone();
            CACHE_COUNTER.with_label_values(&["hit_stale"]).inc();
            tokio::spawn(async move {
                let _ = fetch_and_insert(cache_key, msg, client, &mut cache).await;
            });
        } else {
            CACHE_COUNTER.with_label_values(&["hit"]).inc();
        }
        let mut response_msg = trust_dns_proto::op::message::Message::new();
        let mut edns = trust_dns_proto::op::Edns::new();
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

    CACHE_COUNTER.with_label_values(&["miss"]).inc();
    let mut response_msg = fetch_and_insert(cache_key, msg, client, &mut cache).await?;
    response_msg.set_authoritative(true);

    Ok(response_msg)
}

struct Config {
    server_name: Option<Vec<u8>>
}

struct Cache {
    client: dns_proto::dns_service_client::DnsServiceClient<tonic::transport::Channel>,
    cache: Arc<Mutex<lru::LruCache<CacheKey, CacheData>>>,
    config: Arc<Config>,
}

impl trust_dns_server::server::RequestHandler for Cache {
    type ResponseFuture = HandleRequest;

    fn handle_request<R: trust_dns_server::server::ResponseHandler>(&self, request: trust_dns_server::server::Request, response_handle: R) -> Self::ResponseFuture {
        let request_message = request.message;
        trace!("request: {:?}", request_message);

        match request_message.message_type() {
            trust_dns_client::op::MessageType::Query => match request_message.op_code() {
                trust_dns_client::op::OpCode::Query => {
                    debug!("query received: {}", request_message.id());
                    QUERY_COUNTER.with_label_values(&["query"]).inc();
                    let timer = QUERY_RESPONSE_TIME.with_label_values(&["query"]).start_timer();
                    let timer_axfr = QUERY_RESPONSE_TIME.with_label_values(&["axfr"]).start_timer();
                    let mut client = self.client.clone();
                    let cache = self.cache.clone();
                    let config = self.config.clone();
                    let lookup = async move {
                        let mut response = trust_dns_server::authority::MessageResponseBuilder::new(Some(request_message.raw_queries()));

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

                                let _ = response_handle.send_response(response.error_msg(
                                    request_message.id(),
                                    request_message.op_code(),
                                    trust_dns_client::op::ResponseCode::BADVERS,
                                ));
                                timer_axfr.stop_and_discard();
                                timer.observe_duration();
                                return;
                            }
                            nsid_requested = edns.option(trust_dns_proto::rr::rdata::opt::EdnsCode::NSID).is_some();
                        }

                        let queries = request_message.queries().into_iter().map(|q| q.original().to_owned()).collect::<Vec<_>>();

                        if queries.is_empty() {
                            let _ = response_handle.send_response(response.error_msg(
                                request_message.id(),
                                request_message.op_code(),
                                trust_dns_client::op::ResponseCode::FormErr,
                            ));
                        } else {
                            if queries.len() == 1 && queries[0].query_type() == trust_dns_proto::rr::record_type::RecordType::AXFR {
                                let request_bytes = request_message.to_bytes();
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
                                    let mut response = trust_dns_server::authority::MessageResponseBuilder::new(Some(request_message.raw_queries()));
                                    match val {
                                        Ok(response_msg) => {
                                            let mut edns = if let Some(edns) = response_msg.edns() {
                                                edns.to_owned()
                                            } else {
                                                trust_dns_proto::op::Edns::new()
                                            };
                                            if nsid_requested {
                                                if let Some(server_name) = &config.server_name {
                                                    edns.set_option(trust_dns_proto::rr::rdata::opt::EdnsOption::Unknown(
                                                        trust_dns_proto::rr::rdata::opt::EdnsCode::NSID.into(),
                                                        server_name.to_vec(),
                                                    ))
                                                }
                                            }
                                            response.edns(edns);
                                            RESPONSE_COUNTER.with_label_values(&["ok_axfr"]).inc();
                                            let _ = response_handle.send_response(response.build(
                                                response_msg.header().to_owned(),
                                                Box::new(response_msg.answers().iter()) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                                Box::new(response_msg.name_servers().iter()) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                                Box::new(vec![].iter()) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                                Box::new(response_msg.additionals().iter()) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                            ));
                                        }
                                        Err(e) => {
                                            RESPONSE_COUNTER.with_label_values(&["error_axfr"]).inc();
                                            let _ = response_handle.send_response(response.error_msg(
                                                request_message.id(),
                                                request_message.op_code(),
                                                e,
                                            ));
                                        }
                                    }
                                }
                                timer.stop_and_discard();
                                timer_axfr.observe_duration();
                            } else {
                                let responses: Result<Vec<_>, _> = futures::stream::iter(queries)
                                    .then(|q| {
                                        let mut new_msg = msg.clone();
                                        let n_client = client.clone();
                                        let n_cache = cache.clone();
                                        new_msg.add_query(q);
                                        lookup_cache_or_fetch(new_msg, n_client, n_cache)
                                    })
                                    .collect::<Vec<_>>().await.into_iter().collect();

                                match responses {
                                    Ok(r) => {
                                        RESPONSE_COUNTER.with_label_values(&["ok"]).inc();
                                        let first_r = r.first().unwrap();
                                        let mut edns = if let Some(edns) = first_r.edns() {
                                            edns.to_owned()
                                        } else {
                                            trust_dns_proto::op::Edns::new()
                                        };
                                        if nsid_requested {
                                            if let Some(server_name) = &config.server_name {
                                                edns.set_option(trust_dns_proto::rr::rdata::opt::EdnsOption::Unknown(
                                                    trust_dns_proto::rr::rdata::opt::EdnsCode::NSID.into(),
                                                    server_name.to_vec(),
                                                ))
                                            }
                                        }
                                        response.edns(edns);
                                        let answers = r.iter().map(|r| r.answers().iter()).flatten();
                                        let name_servers = r.iter().map(|r| r.name_servers().iter()).flatten();
                                        let additionals = r.iter().map(|r| r.additionals().iter()).flatten();
                                        let _ = response_handle.send_response(response.build(
                                            first_r.header().to_owned(),
                                            Box::new(answers) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                            Box::new(name_servers) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                            Box::new(vec![].iter()) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                            Box::new(additionals) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                        ));
                                        timer_axfr.stop_and_discard();
                                        timer.observe_duration();
                                    }
                                    Err(e) => {
                                        RESPONSE_COUNTER.with_label_values(&["error"]).inc();
                                        let _ = response_handle.send_response(response.error_msg(
                                            request_message.id(),
                                            request_message.op_code(),
                                            e,
                                        ));
                                        timer_axfr.stop_and_discard();
                                        timer.observe_duration();
                                    }
                                }
                            }
                        }
                    };
                    HandleRequest::lookup(lookup)
                }
                trust_dns_client::op::OpCode::Update => {
                    debug!("update received: {}", request_message.id());
                    QUERY_COUNTER.with_label_values(&["update"]).inc();
                    let timer = QUERY_RESPONSE_TIME.with_label_values(&["update"]).start_timer();
                    let mut client = self.client.clone();
                    let lookup = async move {
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
                            let rpc_response = match client.update_query(request).await {
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
                        let response = trust_dns_server::authority::MessageResponseBuilder::new(Some(request_message.raw_queries()));
                        match val {
                            Ok(response_msg) => {
                                let _ = response_handle.send_response(response.build(
                                    response_msg.header().to_owned(),
                                    Box::new(response_msg.answers().iter()) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                    Box::new(response_msg.name_servers().iter()) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                    Box::new(vec![].iter()) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                    Box::new(response_msg.additionals().iter()) as Box<dyn std::iter::Iterator<Item=&trust_dns_proto::rr::resource::Record> + std::marker::Send>,
                                ));
                            }
                            Err(e) => {
                                let _ = response_handle.send_response(response.error_msg(
                                    request_message.id(),
                                    request_message.op_code(),
                                    e,
                                ));
                            }
                        }
                        timer.observe_duration();
                    };
                    HandleRequest::lookup(lookup)
                }
                c => {
                    warn!("unimplemented op_code: {:?}", c);
                    QUERY_COUNTER.with_label_values(&["unknown"]).inc();
                    let response = trust_dns_server::authority::MessageResponseBuilder::new(Some(request_message.raw_queries()));
                    let result = response_handle.send_response(response.error_msg(
                        request_message.id(),
                        request_message.op_code(),
                        trust_dns_client::op::ResponseCode::NotImp,
                    ));
                    HandleRequest::result(result)
                }
            },
            trust_dns_client::op::MessageType::Response => {
                warn!(
                    "got a response as a request from id: {}",
                    request_message.id()
                );
                QUERY_COUNTER.with_label_values(&["response"]).inc();
                let response = trust_dns_server::authority::MessageResponseBuilder::new(Some(request_message.raw_queries()));

                let result = response_handle.send_response(response.error_msg(
                    request_message.id(),
                    request_message.op_code(),
                    trust_dns_client::op::ResponseCode::FormErr,
                ));
                HandleRequest::result(result)
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
        .get_matches();

    let ip_addrs = clap::values_t_or_exit!(args, "addr", std::net::IpAddr);
    let port = clap::value_t_or_exit!(args, "port", u16);

    let sockaddrs: Vec<std::net::SocketAddr> = ip_addrs.into_iter()
        .map(|a| std::net::SocketAddr::new(a, port)).collect();

    let mut runtime = tokio::runtime::Builder::new()
        .enable_all()
        .threaded_scheduler()
        .build()
        .expect("failed to initialize Tokio Runtime");

    let client = runtime.block_on(
        dns_proto::dns_service_client::DnsServiceClient::connect(args.value_of("upstream").unwrap().to_string())
    ).expect("Unable to connect to upstream server");

    let tcp_request_timeout = std::time::Duration::from_secs(5);

    let catalog = Cache {
        client,
        cache: Arc::new(Mutex::new(lru::LruCache::new(65535))),
        config: Arc::new(Config {
            server_name: args.value_of("name").map(|s| s.to_string().into_bytes())
        }),
    };

    info!("starting prometheus exporter on [::]:9184");
    prometheus_exporter::start("[::]:9184".parse().unwrap()).unwrap();

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

        runtime.enter(|| server.register_socket(udp_socket, &runtime));
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

        runtime.enter(|| {
            server
                .register_listener(tcp_listener, tcp_request_timeout, &runtime)
                .expect("could not register TCP listener")
        });
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
            panic!(error_msg);
        }
    };
}
