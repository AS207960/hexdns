#[macro_use]
extern crate log;

use std::ops::Deref;
use futures_util::StreamExt;
use tokio::io::AsyncReadExt;
use sha2::Digest;

mod parser;
mod lexer;
mod dnssec;

#[derive(Debug)]
pub struct TokioSleep;

impl aws_sdk_s3::config::AsyncSleep for TokioSleep {
    fn sleep(&self, duration: std::time::Duration) -> aws_sdk_s3::config::Sleep {
        aws_sdk_s3::config::Sleep::new(tokio::time::sleep(duration))
    }
}

#[tokio::main]
async fn main() {
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
        .arg(clap::Arg::new("ksk_path")
            .long("ksk-path")
            .value_name("PATH")
            .env("KSK_PATH")
            .help("Path to the file with the KSK (EC/Ed25519, PEM encoded)")
            .required(true)
            .num_args(1..)
            .value_delimiter(";"))
        .arg(clap::Arg::new("s3_endpoint")
            .long("s3-endpoint")
            .value_name("URL")
            .env("S3_ENDPOINT")
            .help("S3 endpoint to use")
            .required(true))
        .arg(clap::Arg::new("s3_region")
            .long("s3-region")
            .value_name("REGION")
            .env("S3_REGION")
            .help("S3 region name")
            .required(true))
        .arg(clap::Arg::new("s3_bucket")
            .long("s3-bucket")
            .value_name("BUCKET")
            .env("S3_BUCKET")
            .help("S3 bucket name")
            .required(true))
        .arg(clap::Arg::new("s3_access_key_id")
            .long("s3-access-key-id")
            .value_name("KEY_ID")
            .env("S3_ACCESS_KEY_ID")
            .help("S3 access key ID")
            .required(true))
        .arg(clap::Arg::new("s3_secret_access_key")
            .long("s3-secret-access-key")
            .value_name("SECRET_KEY")
            .env("S3_SECRET_ACCESS_KEY")
            .help("S3 secret access key")
            .required(true))
        .get_matches();

    let rpc_url = args.get_one::<String>("rpc_server").unwrap();
    let ksk_path = args.get_many::<String>("ksk_path").unwrap();

    let ksk_data = futures_util::stream::iter(ksk_path).then(|p| async move {
        tokio::fs::read(p).await
    }).collect::<Vec<_>>().await.into_iter().collect::<Result<Vec<_>, _>>().expect("Unable to read KSK file");
    let ksk = ksk_data.iter()
        .map(|k| openssl::pkey::PKey::private_key_from_pem(k))
        .collect::<Result<Vec<_>, _>>().expect("Unable to parse KSK file");

    let s3_endpoint = args.get_one::<String>("s3_endpoint").unwrap();
    let s3_region = aws_sdk_s3::config::Region::new(
        args.get_one::<String>("s3_region").unwrap().clone(),
    );
    let s3_bucket = args.get_one::<String>("s3_bucket").unwrap().to_string();
    let s3_access_key_id = args.get_one::<String>("s3_access_key_id").unwrap();
    let s3_secret_access_key = args.get_one::<String>("s3_secret_access_key").unwrap();

    let s3_creds = aws_credential_types::Credentials::new(
        s3_access_key_id.to_string(),
        s3_secret_access_key.to_string(),
        None,
        None,
        clap::crate_name!(),
    );

    let s3_app_name = aws_sdk_s3::config::AppName::new(clap::crate_name!()).unwrap();
    let sleep_impl = std::sync::Arc::new(TokioSleep);

    let s3_config = aws_sdk_s3::config::Builder::new()
        .app_name(s3_app_name)
        .endpoint_url(s3_endpoint)
        .credentials_provider(s3_creds)
        .region(s3_region)
        .retry_config(aws_sdk_s3::config::retry::RetryConfig::standard())
        .sleep_impl(aws_sdk_s3::config::SharedAsyncSleep::new(sleep_impl))
        .build();
    let s3_client = aws_sdk_s3::Client::from_conf(s3_config);

    info!("Starting RabbitMQ listener");
    let amqp_conn = lapin::Connection::connect(
        &rpc_url,
        lapin::ConnectionProperties::default(),
    ).await.expect("Unable to connect to RabbitMQ server");
    let amqp_channel = amqp_conn.create_channel().await.expect("Unable to open RabbitMQ channel");

    amqp_channel.queue_declare("hexdns_resign", lapin::options::QueueDeclareOptions {
        durable: true,
        ..lapin::options::QueueDeclareOptions::default()
    }, lapin::types::FieldTable::default()).await.expect("Unable to declare RabbitMQ queue");
    amqp_channel.exchange_declare("hexdns_primary_reload", lapin::ExchangeKind::Fanout, lapin::options::ExchangeDeclareOptions {
        durable: true,
        ..lapin::options::ExchangeDeclareOptions::default()
    }, lapin::types::FieldTable::default()).await.expect("Unable to declare RabbitMQ exchange");

    let mut consumer = amqp_channel.basic_consume("hexdns_resign", "", lapin::options::BasicConsumeOptions {
        no_ack: false,
        ..lapin::options::BasicConsumeOptions::default()
    }, lapin::types::FieldTable::default()).await.expect("Unable to start consuming on RabbitMQ queue");

    info!("Running...");
    while let Some(delivery) = consumer.next().await {
        let delivery = delivery.expect("error in consumer");
        let s3_client = s3_client.clone();
        let ksk = ksk.clone();
        let amqp_channel = amqp_channel.clone();
        let s3_bucket = s3_bucket.clone();
        tokio::task::spawn(async move {
            let zone_name = match String::from_utf8(delivery.data.clone()) {
                Ok(z) => z,
                Err(err) => {
                    warn!("Unable to parse zone name as UTF-8: {:?}", err);
                    delivery
                        .reject(lapin::options::BasicRejectOptions {
                            requeue: true,
                        })
                        .await
                        .expect("unable to nack");
                    return;
                }
            };

            info!("Signing zone zone={}", zone_name);

            let zone_contents = match s3_client.get_object()
                .bucket(&s3_bucket)
                .key(format!("{}zone", zone_name))
                .send().await {
                Ok(r) => {
                    let mut body = r.body.into_async_read();
                    let mut contents = vec![];
                    if let Err(err) = body.read_to_end(&mut contents).await {
                        warn!("Unable to read zone contents zone={}: {:?}", zone_name, err);
                        delivery
                            .reject(lapin::options::BasicRejectOptions {
                                requeue: true,
                            })
                            .await
                            .expect("unable to nack");
                        return;
                    }
                    match String::from_utf8(contents) {
                        Ok(c) => c,
                        Err(err) => {
                            warn!("Unable to parse zone contents as UTF-8 zone={}: {:?}", zone_name, err);
                            delivery
                                .reject(lapin::options::BasicRejectOptions {
                                    requeue: true,
                                })
                                .await
                                .expect("unable to nack");
                            return;
                        }
                    }
                },
                Err(e) => {
                    warn!("Unable to fetch zone contents zone={}: {:?}", zone_name, e);
                    delivery
                        .reject(lapin::options::BasicRejectOptions {
                            requeue: true,
                        })
                        .await
                        .expect("unable to nack");
                    return;
                }
            };
            let zsk_pem = match s3_client.get_object()
                .bucket(&s3_bucket)
                .key(format!("{}key", zone_name))
                .send().await {
                Ok(r) => {
                    let mut body = r.body.into_async_read();
                    let mut contents = vec![];
                    if let Err(err) = body.read_to_end(&mut contents).await {
                        warn!("Unable to read ZSK zone={}: {:?}", zone_name, err);
                        delivery
                            .reject(lapin::options::BasicRejectOptions {
                                requeue: true,
                            })
                            .await
                            .expect("unable to nack");
                        return;
                    }
                    contents
                },
                Err(e) => {
                    warn!("Unable to fetch ZSK zone={}: {:?}", zone_name, e);
                    delivery
                        .reject(lapin::options::BasicRejectOptions {
                            requeue: true,
                        })
                        .await
                        .expect("unable to nack");
                    return;
                }
            };

            let mut zsk_indicies = zsk_pem
                .windows(2)
                .enumerate()
                .filter(|(_, w)| matches!(*w, b"\n\n"))
                .map(|(i, _)| i)
                .collect::<Vec<_>>();
            zsk_indicies.insert(0, 0);

            let mut zsk = vec![];
            for i in zsk_indicies {
                match openssl::pkey::PKey::private_key_from_pem(&zsk_pem[i..]) {
                    Ok(k) => zsk.push(k),
                    Err(e) => {
                        warn!("Unable to parse ZSK zone={}: {:?}", zone_name, e);
                        delivery
                            .reject(lapin::options::BasicRejectOptions {
                                requeue: true,
                            })
                            .await
                            .expect("unable to nack");
                        return;
                    }
                }
            }

            let zone_signed = match dnssec::sign_zone(&zone_contents, ksk.deref(), zsk.deref()) {
                Ok(z) => z,
                Err(e) => {
                    warn!("Unable to sign zone zone={}: {:?}", zone_name, e);
                    delivery
                        .reject(lapin::options::BasicRejectOptions {
                            requeue: true,
                        })
                        .await
                        .expect("unable to nack");
                    return;
                }
            };

            let mut hasher = sha2::Sha256::new();
            hasher.update(zone_signed.as_bytes());
            let zone_hash = hasher.finalize();

            let byte_stream = aws_sdk_s3::primitives::ByteStream::from(zone_signed.as_bytes().to_vec());
            if let Err(err) = s3_client.put_object()
                .bucket(&s3_bucket)
                .key(format!("{}zone.signed", zone_name))
                .body(byte_stream)
                .send().await {
                warn!("Unable to upload signed zone zone={}: {:?}", zone_name, err);
                delivery
                    .reject(lapin::options::BasicRejectOptions {
                        requeue: true,
                    })
                    .await
                    .expect("unable to nack");
                return;
            }

            info!("Signed zone zone={}", zone_name);

            amqp_channel.basic_publish(
                "hexdns_primary_reload", "",
                lapin::options::BasicPublishOptions::default(),
                format!("{}:{}", hex::encode(zone_hash), zone_name).as_bytes(),
                lapin::BasicProperties::default()
                    .with_expiration("3600000".into())
            ).await.expect("Unable to publish to RabbitMQ exchange");

            delivery
                .ack(lapin::options::BasicAckOptions::default())
                .await
                .expect("unable to ack");
        });
    }
}