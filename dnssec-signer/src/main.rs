#[macro_use]
extern crate log;

use futures_util::StreamExt;
use tokio::io::AsyncReadExt;

mod parser;
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
            .help("Path to the file with the KSK (EC, PEM encoded)")
            .required(true))
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
    let ksk_path = args.get_one::<String>("ksk_path").unwrap();

    let ksk_data = tokio::fs::read(ksk_path).await.expect("Unable to read KSK file");
    let ksk = openssl::ec::EcKey::private_key_from_pem(&ksk_data).expect("Unable to parse KSK file");

    let s3_endpoint = args.get_one::<String>("s3_endpoint").unwrap();
    let s3_region = aws_sdk_s3::config::Region::new(
        args.get_one::<String>("s3_region").unwrap().clone(),
    );
    let s3_bucket = args.get_one::<String>("s3_bucket").unwrap();
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

    let mut consumer = amqp_channel.basic_consume("hexdns_resign", "", lapin::options::BasicConsumeOptions {
        no_ack: true,
        ..lapin::options::BasicConsumeOptions::default()
    }, lapin::types::FieldTable::default()).await.expect("Unable to start consuming on RabbitMQ queue");

    info!("Running...");
    while let Some(delivery) = consumer.next().await {
        let delivery = delivery.expect("error in consumer");
        let zone_name = match String::from_utf8(delivery.data.clone()) {
            Ok(z) => z,
            Err(err) => {
                warn!("Unable to parse zone name as UTF-8: {}", err);
                delivery
                    .nack(lapin::options::BasicNackOptions::default())
                    .await
                    .expect("unable to nack");
                continue;
            }
        };

        let zone_contents = match s3_client.get_object()
            .bucket(s3_bucket)
            .key(format!("{}zone", zone_name))
            .send().await {
            Ok(r) => {
                let mut body = r.body.into_async_read();
                let mut contents = vec![];
                if let Err(err) = body.read_to_end(&mut contents).await {
                    warn!("Unable to read zone contents: {}", err);
                    delivery
                        .nack(lapin::options::BasicNackOptions::default())
                        .await
                        .expect("unable to nack");
                    continue;
                }
                match String::from_utf8(contents) {
                    Ok(c) => c,
                    Err(err) => {
                        warn!("Unable to parse zone contents as UTF-8: {}", err);
                        delivery
                            .nack(lapin::options::BasicNackOptions::default())
                            .await
                            .expect("unable to nack");
                        continue;
                    }
                }
            },
            Err(e) => {
                warn!("Unable to fetch zone contents: {}", e);
                delivery
                    .nack(lapin::options::BasicNackOptions::default())
                    .await
                    .expect("unable to nack");
                continue;
            }
        };
        let zsk_pem = match s3_client.get_object()
            .bucket(s3_bucket)
            .key(format!("{}key", zone_name))
            .send().await {
            Ok(r) => {
                let mut body = r.body.into_async_read();
                let mut contents = vec![];
                if let Err(err) = body.read_to_end(&mut contents).await {
                    warn!("Unable to read ZSK: {}", err);
                    delivery
                        .nack(lapin::options::BasicNackOptions::default())
                        .await
                        .expect("unable to nack");
                    continue;
                }
                contents
            },
            Err(e) => {
                warn!("Unable to fetch ZSK: {}", e);
                delivery
                    .nack(lapin::options::BasicNackOptions::default())
                    .await
                    .expect("unable to nack");
                continue;
            }
        };

        let zsk = match openssl::ec::EcKey::private_key_from_pem(&zsk_pem) {
            Ok(k) => k,
            Err(e) => {
                warn!("Unable to parse ZSK: {}", e);
                delivery
                    .nack(lapin::options::BasicNackOptions::default())
                    .await
                    .expect("unable to nack");
                continue;
            }
        };

        let zone_signed = match dnssec::sign_zone(&zone_contents, &ksk, &zsk) {
            Ok(z) => z,
            Err(e) => {
                warn!("Unable to sign zone: {}", e);
                delivery
                    .nack(lapin::options::BasicNackOptions::default())
                    .await
                    .expect("unable to nack");
                continue;
            }
        };

        let byte_stream = aws_sdk_s3::primitives::ByteStream::from(zone_signed.as_bytes().to_vec());
        if let Err(err) = s3_client.put_object()
            .bucket(s3_bucket)
            .key(format!("{}zone.signed", zone_name))
            .body(byte_stream)
            .send().await {
            warn!("Unable to upload signed zone: {}", err);
            delivery
                .nack(lapin::options::BasicNackOptions::default())
                .await
                .expect("unable to nack");
            continue;
        }

        delivery
            .ack(lapin::options::BasicAckOptions::default())
            .await
            .expect("unable to ack");
    }
}