#[macro_use] extern crate log;

use prost::Message;
use std::net::ToSocketAddrs;
use std::io::Write;
use rand::prelude::*;

pub mod axfr_proto {
    tonic::include_proto!("as207960.dns.axfr");
}

fn main() {
    pretty_env_logger::init();

    let args = clap::Command::new(clap::crate_name!())
        .about(clap::crate_description!())
        .version(clap::crate_version!())
        .author(clap::crate_authors!(", "))
        .arg(clap::Arg::new("rpc_server")
            .short('r')
            .long("rpc-server")
            .env("RABBITMQ_RPC_URL")
            .value_name("URL")
            .help("Connection URL for the RabbitMQ server")
            .required(true))
        .get_matches();

    let rpc_url = args.get_one::<String>("rpc_server").unwrap();

    let mut rng = rand::thread_rng();

    info!("Starting RabbitMQ listener");
    let mut amqp_conn = amiquip::Connection::insecure_open(&rpc_url).expect("Unable to connect to RabbitMQ server");
    let amqp_channel = amqp_conn.open_channel(None).expect("Unable to open RabbitMQ channel");

    let listen_queue = amqp_channel.queue_declare("hexdns_axfr_notify", amiquip::QueueDeclareOptions {
        durable: true,
        ..amiquip::QueueDeclareOptions::default()
    }).expect("Unable to declare RabbitMQ queue");

    let consumer = listen_queue.consume(amiquip::ConsumerOptions::default()).expect("Unable to start consuming on RabbitMQ queue");
    info!("RabbitMQ listener started");

    for message in consumer.receiver().iter() {
        match message {
            amiquip::ConsumerMessage::Delivery(delivery) => {
                let body = delivery.body.clone();

                match axfr_proto::Notify::decode(&body[..]) {
                    Ok(notify_message) => {
                        trace!("Got notify message: {:#?}", notify_message);

                        let zone = match trust_dns_proto::rr::domain::Name::from_str_relaxed(&notify_message.zone) {
                            Ok(z) => z,
                            Err(e) => {
                                warn!("Unable to parse zone name: {}", e);
                                continue;
                            }
                        };

                        let addrs = match (notify_message.server.as_str(), notify_message.port as u16).to_socket_addrs() {
                            Ok(a) => a.collect::<Vec<_>>(),
                            Err(e) => {
                                warn!("Unable to resolve {}: {}", notify_message.server, e);
                                continue;
                            }
                        };


                        let mut header = trust_dns_proto::op::Header::new();
                        header.set_id(rng.gen());
                        header.set_message_type(trust_dns_proto::op::MessageType::Query);
                        header.set_op_code(trust_dns_proto::op::OpCode::Notify);
                        header.set_authoritative(true);

                        let mut notify_msg = trust_dns_proto::op::Message::new();
                        notify_msg.set_header(header);
                        notify_msg.add_query(trust_dns_proto::op::query::Query::query(
                            zone, trust_dns_proto::rr::record_type::RecordType::SOA
                        ));

                        let msg_bytes = notify_msg.to_vec().unwrap();

                        for addr in addrs {
                            match std::net::TcpStream::connect(addr) {
                                Ok(mut stream) => {
                                    if let Err(e) = stream.write_all(&(msg_bytes.len() as u16).to_be_bytes()) {
                                        warn!("Unable to send notify message to {}: {}", addr, e);
                                        continue;
                                    }
                                    if let Err(e) = stream.write_all(&msg_bytes) {
                                        warn!("Unable to send notify message to {}: {}", addr, e);
                                        continue;
                                    }
                                    break;
                                }
                                Err(e) => {
                                    warn!("Unable to connect to {}: {}", addr, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Unable to decode RPC message: {}", e);
                    }
                }

                consumer.ack(delivery.clone()).unwrap();
            }
            amiquip::ConsumerMessage::ServerClosedChannel(err)
            | amiquip::ConsumerMessage::ServerClosedConnection(err) => {
                error!("Error or RabbitMQ restarting: {}", err);
            }
            amiquip::ConsumerMessage::ClientCancelled
            | amiquip::ConsumerMessage::ServerCancelled
            | amiquip::ConsumerMessage::ClientClosedChannel
            | amiquip::ConsumerMessage::ClientClosedConnection => {
                return;
            }
        }
    }
}
