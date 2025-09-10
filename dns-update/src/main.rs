#[macro_use] extern crate log;
#[macro_use] extern crate clap;

use trust_dns_proto::serialize::binary::{BinDecodable};

pub mod dns_proto {
    tonic::include_proto!("coredns.dns");
}

#[derive(Clone)]
struct Context {
    client: dns_proto::dns_service_client::DnsServiceClient<tonic::transport::Channel>,
}

async fn handle_request(mut context: Context, request_message: dns_cache::Request, request_context: dns_cache::RequestContext) {
    if let Some(edns) = request_message.msg.extensions() {
        if edns.version() > 0 {
            warn!(
                "request edns version greater than 0: {}",
                edns.version()
            );
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
    }

    match request_message.msg.message_type() {
        trust_dns_client::op::MessageType::Query => {
			let raw_bytes = request_message.raw_bytes.clone();
			let request = tonic::Request::new(dns_proto::DnsPacket {
				msg: raw_bytes
			});
			match request_message.msg.op_code() {
				trust_dns_client::op::OpCode::Update => {
					debug!("update received: {}", request_message.msg.id());
					let val = async {
						let rpc_response = match context.client.update_query(request).await {
							Ok(x) => x,
							Err(e) => {
								error!("Error communicating with upstream: {}", e);
								return Err(trust_dns_client::op::ResponseCode::ServFail);
							}
						};
						let response = rpc_response.into_inner();
						let response_msg = match trust_dns_proto::op::message::Message::from_bytes(&response.msg) {
							Ok(x) => x,
							Err(e) => {
								error!("Error parsing update response from upstream: {}", e);
								return Err(trust_dns_client::op::ResponseCode::ServFail);
							}
						};
						Ok(response_msg)
					}.await;
					match val {
						Ok(response_msg) => {
							request_context.respond(response_msg).await;
						}
						Err(e) => {
							let response_msg = trust_dns_proto::op::Message::error_msg(
								request_message.msg.id(), request_message.msg.op_code(), e
							);
							request_context.respond(response_msg).await;
						}
					}
				}
				trust_dns_client::op::OpCode::Notify => {
					debug!("notify received: {}", request_message.msg.id());
					let val = async {
						let rpc_response = match context.client.notify_query(request).await {
							Ok(x) => x,
							Err(e) => {
								error!("Error communicating with upstream: {}", e);
								return Err(trust_dns_client::op::ResponseCode::ServFail);
							}
						};
						let response = rpc_response.into_inner();
						let response_msg = match trust_dns_proto::op::message::Message::from_bytes(&response.msg) {
							Ok(x) => x,
							Err(e) => {
								error!("Error parsing notify response from upstream: {}", e);
								return Err(trust_dns_client::op::ResponseCode::ServFail);
							}
						};
						Ok(response_msg)
					}.await;
					match val {
						Ok(response_msg) => {
							request_context.respond(response_msg).await;
						}
						Err(e) => {
							let response_msg = trust_dns_proto::op::Message::error_msg(
								request_message.msg.id(), request_message.msg.op_code(), e
							);
							request_context.respond(response_msg).await;
						}
					}
				}
				c => {
					warn!("unimplemented op_code: {:?}", c);
					let response_msg = trust_dns_proto::op::Message::error_msg(
						request_message.msg.id(), request_message.msg.op_code(),
						trust_dns_client::op::ResponseCode::NotImp,
					);
					request_context.respond(response_msg).await;
				}
			}
		},
        trust_dns_client::op::MessageType::Response => {
            warn!(
                "got a response as a request from id: {}",
                request_message.msg.id()
            );
            let response_msg = trust_dns_proto::op::Message::error_msg(
                request_message.msg.id(), request_message.msg.op_code(),
                trust_dns_client::op::ResponseCode::FormErr,
            );
            request_context.respond(response_msg).await;
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
            .env("DNS_PORT")
            .help("Port to listen on for DNS queries")
			.value_parser(value_parser!(u16))
			.action(clap::ArgAction::Set)
            .default_value("53"))
        .arg(clap::Arg::new("addr")
            .short('a')
            .long("addr")
            .env("DNS_ADDR")
            .help("Addresses to listen on for DNS queries")
            .action(clap::ArgAction::Append)
			.value_parser(value_parser!(std::net::SocketAddr))
            .default_value("::"))
        .arg(clap::Arg::new("upstream")
            .short('u')
            .long("upstream")
            .env("DNS_UPSTREAM")
            .required(true)
            .help("gRPC upstream server (e.g. http://[::1]:50051)")
			.action(clap::ArgAction::Set))
        .get_matches();

    let ip_addrs = args.get_many::<std::net::IpAddr>("addr").unwrap();
    let port = args.get_one::<u16>("port").unwrap();

    let sockaddrs: Vec<std::net::SocketAddr> = ip_addrs.into_iter()
        .map(|a| std::net::SocketAddr::new(*a, *port)).collect();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(1024)
        .event_interval(120)
        .worker_threads(16)
        .enable_all()
        .build()
        .expect("failed to initialize Tokio Runtime");

    let client = runtime.block_on(
        dns_proto::dns_service_client::DnsServiceClient::connect(args.get_one::<String>("upstream").unwrap().to_string())
    ).expect("Unable to connect to upstream server");

    let server = dns_cache::Server {
        sockaddrs,
        handler: handle_request,
        context: Context {
            client,
        }
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