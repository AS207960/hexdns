#[macro_use] extern crate log;

pub mod axfr_proto {
    tonic::include_proto!("as207960.dns.axfr");
}

mod parser;

use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use trust_dns_proto::error::ProtoResult;
use hmac::Mac;

struct ServerTask(tokio::task::JoinHandle<()>);

impl std::future::Future for ServerTask {
    type Output = Result<(), tokio::task::JoinError>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.0).poll(cx)
    }
}

impl Drop for ServerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

enum ReadTcpState {
    Len,
    Msg {
        size: u16
    }
}

struct IncomingMessage {
    msg: Vec<u8>,
    addr: std::net::SocketAddr,
    context: MessageContext,
}

#[derive(Debug, Clone)]
enum MessageContext {
    Udp {
        res_tx: tokio::sync::mpsc::Sender<(std::net::SocketAddr, Vec<u8>)>,
    },
    Tcp {
        res_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    }
}

impl MessageContext {
    fn protocol(&self) -> &'static str {
        match self {
            MessageContext::Udp { .. } => "udp",
            MessageContext::Tcp { .. } => "tcp",
        }
    }
}

fn map_nat64(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V4(a) => std::net::IpAddr::V4(a),
        std::net::IpAddr::V6(a) => {
            if let [0x2a0d, 0x1a40, 0x7900, 0x0006, _, _, ab, cd] = a.segments() {
                let [a, b] = ab.to_be_bytes();
                let [c, d] = cd.to_be_bytes();
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
            } else {
                std::net::IpAddr::V6(a)
            }
        }
    }
}

struct TSIGContext {
    name: trust_dns_proto::rr::Name,
    algorithm: trust_dns_proto::rr::dnssec::rdata::tsig::TsigAlgorithm,
    key: Vec<u8>,
    hash: Vec<u8>,
    first: bool,
}

async fn handle_request(
    mut client: axfr_proto::axfr_service_client::AxfrServiceClient<tonic::transport::Channel>,
    zone_root: std::path::PathBuf,
    msg: trust_dns_proto::op::Message,
    msg_bytes: Vec<u8>,
    query: trust_dns_client::op::LowerQuery,
    addr: std::net::SocketAddr,
    context: MessageContext,
) {
    if msg.message_type() != trust_dns_proto::op::header::MessageType::Query ||
        msg.op_code() != trust_dns_proto::op::op_code::OpCode::Query ||
        msg.response_code() != trust_dns_proto::op::response_code::ResponseCode::NoError ||
        msg.query_count() != 1 || msg.answer_count() != 0 || msg.name_server_count() != 0 ||
        query.query_type() != trust_dns_proto::rr::record_type::RecordType::AXFR ||
        query.query_class() != trust_dns_proto::rr::dns_class::DNSClass::IN {
        let response_msg = trust_dns_proto::op::Message::error_msg(
            msg.id(), msg.op_code(),
            trust_dns_client::op::ResponseCode::Refused,
        );
        send_response(response_msg, addr, context).await;
        return;
    }

    let mut tsig_context = None;

    if !msg.signature().is_empty() {
        let (signed_data, sig) = match trust_dns_proto::rr::dnssec::rdata::tsig::signed_bitmessage_to_buf(
            None, &msg_bytes, true
        ) {
            Ok(r) => r,
            Err(e) => {
                warn!("failed to parse TSIG signature: {}", e);
                let response_msg = trust_dns_proto::op::Message::error_msg(
                    msg.id(), msg.op_code(),
                    trust_dns_client::op::ResponseCode::BADSIG,
                );
                send_response(response_msg, addr, context).await;
                return;
            }
        };

        let data = sig.data().unwrap().as_dnssec().unwrap().as_tsig().unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        if (now as i64 - data.time() as i64).abs() > data.fudge() as i64 {
            let response_msg = trust_dns_proto::op::Message::error_msg(
                msg.id(), msg.op_code(),
                trust_dns_client::op::ResponseCode::BADTIME,
            );
            send_response(response_msg, addr, context).await;
            return;
        }

        let name = sig.name();
        let key = match client.get_tsig_secret(axfr_proto::TsigRequest {
            key_name: name.to_string(),
        }).await {
            Ok(r) => r.into_inner().secret,
            Err(e) => {
                warn!("failed to get TSIG key: {}", e);
                let response_msg = trust_dns_proto::op::Message::error_msg(
                    msg.id(), msg.op_code(),
                    trust_dns_client::op::ResponseCode::BADSIG,
                );
                send_response(response_msg, addr, context).await;
                return;
            }
        };

        let computed_sig: Vec<u8> = match data.algorithm() {
            trust_dns_proto::rr::dnssec::rdata::tsig::TsigAlgorithm::HmacSha224 => {
                let mut hmac = hmac::Hmac::<sha2::Sha224>::new_from_slice(&key).unwrap();
                hmac.update(&signed_data);
                hmac.finalize().into_bytes().to_vec()
            }
            trust_dns_proto::rr::dnssec::rdata::tsig::TsigAlgorithm::HmacSha256 => {
                let mut hmac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&key).unwrap();
                hmac.update(&signed_data);
                hmac.finalize().into_bytes().to_vec()
            }
            trust_dns_proto::rr::dnssec::rdata::tsig::TsigAlgorithm::HmacSha384 => {
                let mut hmac = hmac::Hmac::<sha2::Sha384>::new_from_slice(&key).unwrap();
                hmac.update(&signed_data);
                hmac.finalize().into_bytes().to_vec()
            }
            trust_dns_proto::rr::dnssec::rdata::tsig::TsigAlgorithm::HmacSha512 => {
                let mut hmac = hmac::Hmac::<sha2::Sha512>::new_from_slice(&key).unwrap();
                hmac.update(&signed_data);
                hmac.finalize().into_bytes().to_vec()
            }
            trust_dns_proto::rr::dnssec::rdata::tsig::TsigAlgorithm::HmacSha512_256 => {
                let mut hmac = hmac::Hmac::<sha2::Sha512_256>::new_from_slice(&key).unwrap();
                hmac.update(&signed_data);
                hmac.finalize().into_bytes().to_vec()
            }
            _ => {
                let response_msg = trust_dns_proto::op::Message::error_msg(
                    msg.id(), msg.op_code(),
                    trust_dns_client::op::ResponseCode::BADALG,
                );
                send_response(response_msg, addr, context).await;
                return;
            }
        };

        if !constant_time_eq::constant_time_eq(data.mac(), &computed_sig) {
            let response_msg = trust_dns_proto::op::Message::error_msg(
                msg.id(), msg.op_code(),
                trust_dns_client::op::ResponseCode::BADSIG,
            );
            send_response(response_msg, addr, context).await;
            return;
        }

        tsig_context = Some(TSIGContext {
            name: name.clone(),
            algorithm: data.algorithm().clone(),
            key,
            hash: data.mac().to_vec(),
            first: true
        })
    } else {
        let resp = match client.check_ipacl(axfr_proto::IpaclRequest {
            zone_name: query.name().to_string(),
            ip_addr: Some(match addr.ip() {
                std::net::IpAddr::V4(ip) => axfr_proto::ipacl_request::IpAddr::V4(u32::from_be_bytes(ip.octets())),
                std::net::IpAddr::V6(ip) => match ip.to_ipv4() {
                    Some(ip) => axfr_proto::ipacl_request::IpAddr::V4(u32::from_be_bytes(ip.octets())),
                    None => axfr_proto::ipacl_request::IpAddr::V6(ip.octets().to_vec()),
                }
            })
        }).await {
            Ok(r) => r.into_inner(),
            Err(e) => {
                warn!("failed to check IP ACL: {}", e);
                let response_msg = trust_dns_proto::op::Message::error_msg(
                    msg.id(), msg.op_code(),
                    trust_dns_client::op::ResponseCode::BADSIG,
                );
                send_response(response_msg, addr, context).await;
                return;
            }
        };

        if !resp.allowed {
            let response_msg = trust_dns_proto::op::Message::error_msg(
                msg.id(), msg.op_code(),
                trust_dns_client::op::ResponseCode::Refused,
            );
            send_response(response_msg, addr, context).await;
            return;
        }
    }

    let zone_file_path = zone_root.join(format!("{}zone", query.name()));
    let zone_file_contents = match std::fs::read_to_string(zone_file_path) {
        Ok(r) => r,
        Err(e) => {
            error!("failed to read zone file: {}", e);
            let response_msg = trust_dns_proto::op::Message::error_msg(
                msg.id(), msg.op_code(),
                trust_dns_client::op::ResponseCode::ServFail,
            );
            send_response(response_msg, addr, context).await;
            return;
        }
    };

    let zone_file_lexer = trust_dns_client::serialize::txt::Lexer::new(&zone_file_contents);
    let (origin, mut zone_file) = match parser::Parser::new()
        .parse(zone_file_lexer, query.name().into(), trust_dns_proto::rr::DNSClass::IN) {
        Ok(r) => r,
        Err(e) => {
            error!("failed to parse zone file: {}", e);
            let response_msg = trust_dns_proto::op::Message::error_msg(
                msg.id(), msg.op_code(),
                trust_dns_client::op::ResponseCode::ServFail,
            );
            send_response(response_msg, addr, context).await;
            return;
        }
    };

    let soa = match zone_file.remove(&trust_dns_client::rr::RrKey {
        name: origin.into(),
        record_type: trust_dns_client::rr::RecordType::SOA
    }) {
        Some(s) => s,
        None => {
            let response_msg = trust_dns_proto::op::Message::error_msg(
                msg.id(), msg.op_code(),
                trust_dns_client::op::ResponseCode::ServFail,
            );
            send_response(response_msg, addr, context).await;
            return;
        }
    };

    let mut header = trust_dns_proto::op::Header::new();
    header.set_id(msg.id());
    header.set_message_type(trust_dns_proto::op::MessageType::Response);
    header.set_op_code(trust_dns_proto::op::OpCode::Query);
    header.set_authoritative(true);
    header.set_recursion_desired(msg.recursion_desired());
    header.set_recursion_available(false);

    let mut soa_response = trust_dns_proto::op::Message::new();
    soa_response.set_header(header.clone());
    soa_response.add_query(query.original().clone());
    soa_response.add_answers(soa.records_without_rrsigs().cloned());

    let mut soa_response_1 = soa_response.clone();
    match sign_message(&mut soa_response_1, &mut tsig_context) {
        Ok(_) => {}
        Err(e) => {
            warn!("failed to sign message: {}", e);
            let response_msg = trust_dns_proto::op::Message::error_msg(
                msg.id(), msg.op_code(),
                trust_dns_client::op::ResponseCode::ServFail,
            );
            send_response(response_msg, addr, context).await;
            return;
        }
    }
    send_response(soa_response_1, addr, context.clone()).await;

    for (_, v) in zone_file.into_iter() {
        for r in v.records(true, trust_dns_proto::rr::dnssec::SupportedAlgorithms::all()) {
            let mut response = trust_dns_proto::op::Message::new();
            response.set_header(header.clone());
            response.add_query(query.original().clone());
            response.add_answer(r.clone());
            match sign_message(&mut response, &mut tsig_context) {
                Ok(_) => {}
                Err(e) => {
                    warn!("failed to sign message: {}", e);
                    let response_msg = trust_dns_proto::op::Message::error_msg(
                        msg.id(), msg.op_code(),
                        trust_dns_client::op::ResponseCode::ServFail,
                    );
                    send_response(response_msg, addr, context).await;
                    return;
                }
            }
            send_response(response, addr, context.clone()).await;
        }
    }

    let mut soa_response_2 = soa_response.clone();
    match sign_message(&mut soa_response_2, &mut tsig_context) {
        Ok(_) => {}
        Err(e) => {
            warn!("failed to sign message: {}", e);
            let response_msg = trust_dns_proto::op::Message::error_msg(
                msg.id(), msg.op_code(),
                trust_dns_client::op::ResponseCode::ServFail,
            );
            send_response(response_msg, addr, context).await;
            return;
        }
    }
    send_response(soa_response_2, addr, context.clone()).await;
}

fn sign_message(message: &mut trust_dns_proto::op::Message, tsig_context: &mut Option<TSIGContext>) -> ProtoResult<()> {
    if let Some(tsig_context) = tsig_context {
        let now = chrono::Utc::now();
        let tsig = trust_dns_proto::rr::dnssec::rdata::tsig::TSIG::new(
            tsig_context.algorithm.clone(),
            now.timestamp() as u64,
            300,
            vec![],
            message.id(),
            0,
            vec![],
        );

        let mut tbs: Vec<u8> = Vec::with_capacity(512);
        let mut encoder= trust_dns_proto::serialize::binary::BinEncoder::with_mode(
            &mut tbs, trust_dns_proto::serialize::binary::EncodeMode::Signing
        );
        encoder.set_canonical_names(true);
        encoder.emit_u16(tsig_context.hash.len() as u16)?;
        encoder.emit_vec(&tsig_context.hash)?;
        message.emit(&mut encoder)?;
        if tsig_context.first {
            tsig.emit_tsig_for_mac(&mut encoder, &tsig_context.name)?;
        } else {
            encoder.emit_u16((tsig.time() >> 32) as u16)?;
            encoder.emit_u32(tsig.time() as u32)?;
            encoder.emit_u16(tsig.fudge())?;
        }

        let computed_sig: Vec<u8> = match tsig_context.algorithm {
            trust_dns_proto::rr::dnssec::rdata::tsig::TsigAlgorithm::HmacSha224 => {
                let mut hmac = hmac::Hmac::<sha2::Sha224>::new_from_slice(&tsig_context.key).unwrap();
                hmac.update(&tbs);
                hmac.finalize().into_bytes().to_vec()
            }
            trust_dns_proto::rr::dnssec::rdata::tsig::TsigAlgorithm::HmacSha256 => {
                let mut hmac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&tsig_context.key).unwrap();
                hmac.update(&tbs);
                hmac.finalize().into_bytes().to_vec()
            }
            trust_dns_proto::rr::dnssec::rdata::tsig::TsigAlgorithm::HmacSha384 => {
                let mut hmac = hmac::Hmac::<sha2::Sha384>::new_from_slice(&tsig_context.key).unwrap();
                hmac.update(&tbs);
                hmac.finalize().into_bytes().to_vec()
            }
            trust_dns_proto::rr::dnssec::rdata::tsig::TsigAlgorithm::HmacSha512 => {
                let mut hmac = hmac::Hmac::<sha2::Sha512>::new_from_slice(&tsig_context.key).unwrap();
                hmac.update(&tbs);
                hmac.finalize().into_bytes().to_vec()
            }
            trust_dns_proto::rr::dnssec::rdata::tsig::TsigAlgorithm::HmacSha512_256 => {
                let mut hmac = hmac::Hmac::<sha2::Sha512_256>::new_from_slice(&tsig_context.key).unwrap();
                hmac.update(&tbs);
                hmac.finalize().into_bytes().to_vec()
            }
            _ => unreachable!()
        };

        tsig_context.first = false;
        tsig_context.hash = computed_sig.clone();
        message.add_tsig(trust_dns_proto::rr::dnssec::rdata::tsig::make_tsig_record(
            tsig_context.name.clone(), tsig.set_mac(computed_sig)
        ));
    }

    Ok(())
}

async fn send_response(
    msg: trust_dns_proto::op::Message,
    addr: std::net::SocketAddr,
    context: MessageContext,
) {
    let mut bytes: Vec<u8> = Vec::with_capacity(512);
    let mut encoder= trust_dns_proto::serialize::binary::BinEncoder::with_mode(
        &mut bytes, trust_dns_proto::serialize::binary::EncodeMode::Normal
    );
    encoder.set_canonical_names(true);

    match msg.emit(&mut encoder) {
        Ok(_) => {}
        Err(e) => {
            error!("failed to serialise DNS message: {}", e);
            return;
        }
    }

    info!("response:{id:<5} src:{proto}://{addr}#{port:<5} response:{code:?} rflags:{rflags}",
                id = msg.id(),
                proto = context.protocol(),
                addr = addr.ip(),
                port = addr.port(),
                code = msg.response_code(),
                rflags = msg.flags()
            );

    match context {
        MessageContext::Udp { res_tx } => {
            let _ = res_tx.send((addr, bytes)).await;
        }
        MessageContext::Tcp { res_tx } => {
            let _ = res_tx.send(bytes).await;
        }
    }
}

async fn handle_requests(
    client: axfr_proto::axfr_service_client::AxfrServiceClient<tonic::transport::Channel>,
    zone_root: std::path::PathBuf,
    mut req_rx: tokio::sync::mpsc::Receiver<IncomingMessage>
) {
    while let Some(req) = req_rx.recv().await {
        match trust_dns_proto::op::Message::from_bytes(&req.msg) {
            Ok(m) => {
                let query = match m.queries().get(0) {
                    Some(q) => trust_dns_client::op::LowerQuery::query(q.clone()),
                    None => {
                        continue;
                    }
                };
                let addr = map_nat64(req.addr.ip());
                let socket_addr = std::net::SocketAddr::new(addr, req.addr.port());

                info!(
                        "request:{id:<5} src:{proto}://{addr}#{port:<5} {op}:{query}:{qtype}:{class} qflags:{qflags} type:{message_type}",
                        id = m.id(),
                        proto = req.context.protocol(),
                        addr = addr,
                        port = req.addr.port(),
                        message_type = m.message_type(),
                        op = m.op_code(),
                        query = query.name(),
                        qtype = query.query_type(),
                        class = query.query_class(),
                        qflags = m.header().flags(),
                    );

                let c = client.clone();
                let z = zone_root.clone();
                tokio::spawn(async move {
                    handle_request(
                        c, z, m, req.msg, query, socket_addr,
                        req.context
                    ).await;
                });
            }
            Err(e) => {
                warn!("received malformed DNS message: {}", e);
            }
        }
    }
}

fn main() {
    pretty_env_logger::init();

    let args = clap::Command::new(clap::crate_name!())
        .about(clap::crate_description!())
        .version(clap::crate_version!())
        .author(clap::crate_authors!(", "))
        .arg(clap::Arg::new("port")
            .short('p')
            .long("port")
            .value_name("PORT")
            .value_parser(clap::value_parser!(u16))
            .env("DNS_PORT")
            .help("Port to listen on for DNS queries")
            .default_value("53"))
        .arg(clap::Arg::new("addr")
            .short('a')
            .long("addr")
            .value_name("ADDR")
            .value_parser(clap::value_parser!(std::net::IpAddr))
            .env("DNS_ADDR")
            .help("Addresses to listen on for DNS queries")
            .num_args(1..)
            .default_value("::"))
        .arg(clap::Arg::new("upstream")
            .short('u')
            .long("upstream")
            .value_name("UPSTREAM")
            .env("DNS_UPSTREAM")
            .required(true)
            .help("gRPC upstream server (e.g. http://[::1]:50051)"))
        .arg(clap::Arg::new("zones")
            .short('z')
            .long("zones")
            .value_name("DIR")
            .value_parser(clap::value_parser!(std::path::PathBuf))
            .env("DNS_ZONES")
            .help("Directory containing zone files")
            .required(true))
        .get_matches();

    let ip_addrs: Vec<_> = args.get_many::<std::net::IpAddr>("addr")
        .expect("`addr` is required")
        .copied().collect();
    let port = *args.get_one::<u16>("port").expect("`port` is required");
    let zone_root = args.get_one::<std::path::PathBuf>("zones").expect("`zones` is required").to_owned();

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
        axfr_proto::axfr_service_client::AxfrServiceClient::connect(args.get_one::<String>("upstream").unwrap().to_string())
    ).expect("Unable to connect to upstream server");

    let (req_tx, req_rx) = tokio::sync::mpsc::channel::<IncomingMessage>(1024);

    let mut tasks: Vec<ServerTask> = vec![];

    let task = runtime.spawn(handle_requests(client, zone_root, req_rx));
    tasks.push(ServerTask(task));

    for udp_socket in &sockaddrs {
        info!("binding UDP to {:?}", udp_socket);
        let udp_socket = std::sync::Arc::new(runtime.block_on(tokio::net::UdpSocket::bind(udp_socket))
            .expect("Could not bind to UDP socket"));

        info!(
                "listening for UDP on {:?}",
                udp_socket
                    .local_addr()
                    .expect("could not lookup local address")
            );

        let task_req_tx = req_tx.clone();
        let send_udp_socket = udp_socket.clone();
        let (udp_res_tx, mut udp_res_rx) = tokio::sync::mpsc::channel(1024);

        let task = tokio::spawn(async move {
            let mut buf = [0; 4096];
            loop {
                let (len, addr) = match udp_socket.recv_from(&mut buf).await {
                    Ok(m) => m,
                    Err(e) => {
                        warn!("error receiving UDP connection: {}", e);
                        continue;
                    }
                };
                let msg: Vec<u8> = buf.iter().take(len).cloned().collect();
                if let Err(_) = task_req_tx.send(IncomingMessage {
                    msg,
                    addr,
                    context: MessageContext::Udp {
                        res_tx: udp_res_tx.clone()
                    }
                }).await {
                    break;
                }
            }
        });
        tasks.push(ServerTask(task));

        let task = tokio::spawn(async move {
            while let Some(res) = udp_res_rx.recv().await {
                if let Err(e) = send_udp_socket.send_to(&res.1, res.0).await {
                    warn!("failed to send UDP response: {}", e);
                }
            }
        });
        tasks.push(ServerTask(task));
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

        let task_req_tx = req_tx.clone();
        let task = runtime.spawn(async move {
            loop {
                let (tcp_stream, addr) = match tcp_listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("error receiving TCP connection: {}", e);
                        continue;
                    }
                };

                let stream_req_tx = task_req_tx.clone();
                let (tcp_stream_rx, mut tcp_stream_tx) = tcp_stream.into_split();
                let (tcp_res_tx, mut tcp_res_rx) = tokio::sync::mpsc::channel(1024);
                tokio::spawn(async move {
                    let mut buf_tcp_stream = tokio::io::BufReader::new(tcp_stream_rx);
                    let mut state = ReadTcpState::Len;
                    'outer: loop {
                        match state {
                            ReadTcpState::Len => {
                                let timeout = tokio::time::sleep(std::time::Duration::from_secs(5));
                                tokio::pin!(timeout);
                                tokio::select! {
                                        _ = &mut timeout => {
                                            debug!("timeout reading TCP packet length");
                                            break 'outer;
                                        }
                                        r = buf_tcp_stream.read_u16() => {
                                            match r {
                                                Ok(len) => {
                                                    state = ReadTcpState::Msg {
                                                        size: len
                                                    }
                                                }
                                                Err(e) => {
                                                    match e.kind() {
                                                        std::io::ErrorKind::UnexpectedEof => {
                                                            debug!("unexpected EOF reading TCP packet length");
                                                        }
                                                        _ => {
                                                            warn!("error reading TCP packet length: {}", e);
                                                        }
                                                    }
                                                    break 'outer;
                                                }
                                            }
                                        }
                                    }
                            },
                            ReadTcpState::Msg { size } => {
                                let mut msg = vec![0; size as usize];
                                let timeout = tokio::time::sleep(std::time::Duration::from_secs(5));
                                tokio::pin!(timeout);
                                tokio::select! {
                                        _ = &mut timeout => {
                                            debug!("timeout reading TCP packet length");
                                            break 'outer;
                                        }
                                        r = buf_tcp_stream.read_exact(&mut msg) => {
                                            match r {
                                                Ok(len) => {
                                                    if len != size as usize {
                                                        warn!("didn't read the full TCP packet");
                                                        break 'outer;
                                                    }
                                                    state = ReadTcpState::Len;
                                                    if let Err(_) = stream_req_tx.send(IncomingMessage {
                                                        msg,
                                                        addr,
                                                        context: MessageContext::Tcp {
                                                            res_tx: tcp_res_tx.clone()
                                                        }
                                                    }).await {
                                                        break;
                                                    }
                                                }
                                                Err(e) => {
                                                    match e.kind() {
                                                        std::io::ErrorKind::UnexpectedEof => {
                                                            debug!("unexpected EOF reading TCP packet");
                                                        }
                                                        _ => {
                                                            warn!("error reading TCP packet: {}", e);
                                                        }
                                                    }
                                                    break 'outer;
                                                }
                                            }
                                        }
                                    }
                            }
                        }
                    }
                });

                tokio::spawn(async move {
                    while let Some(res) = tcp_res_rx.recv().await {
                        if let Err(e) = tcp_stream_tx.write_u16(res.len() as u16).await {
                            warn!("failed to send TCP response: {}", e);
                        }
                        if let Err(e) = tcp_stream_tx.write(&res).await {
                            warn!("failed to send TCP response: {}", e);
                        }
                    }
                });
            }
        });
        tasks.push(ServerTask(task));
    }

    info!("Server starting up");
    match runtime.block_on(futures_util::future::select_all(tasks)) {
        (Ok(()), _, _) => {
            info!("stopping...");
        }
        (Err(e), _, _) => {
            let error_msg = format!(
                "Error: {}",
                e
            );

            error!("{}", error_msg);
            panic!("{}", error_msg);
        }
    };
}