#[macro_use] extern crate log;

use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinError;

#[derive(Debug, Clone)]
pub struct Request {
    pub msg: trust_dns_proto::op::Message,
    pub query: trust_dns_proto::op::LowerQuery,
    pub raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RequestContext {
    context: MessageContext,
    addr: std::net::SocketAddr,
    header: trust_dns_proto::op::Header,
    query: trust_dns_proto::op::LowerQuery,
    res_tx: tokio::sync::mpsc::Sender<OutgoingMessage>
}

impl RequestContext {
    pub async fn respond(&self, msg: trust_dns_proto::op::Message) {
        let _ = self.res_tx.send(OutgoingMessage {
            msg,
            addr: self.addr,
            context: self.context.clone(),
            header: self.header,
            query: self.query.clone(),
        }).await;
    }
}

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

struct OutgoingMessage {
    msg: trust_dns_proto::op::Message,
    addr: std::net::SocketAddr,
    header: trust_dns_proto::op::Header,
    query: trust_dns_proto::op::LowerQuery,
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

pub struct Server<T: Clone + 'static, H: Fn(T, Request, RequestContext) -> R, R: std::future::Future<Output = ()>> {
    pub sockaddrs: Vec<std::net::SocketAddr>,
    pub handler: H,
    pub context: T
}

impl<
    T: Clone + Send + 'static,
    H: Fn(T, Request, RequestContext) -> R + Clone + Send + Sync + 'static,
    R: std::future::Future<Output = ()> + Send + 'static
> Server<T, H, R> {
    async fn handle_requests(context: T, handler: H, mut req_rx: tokio::sync::mpsc::Receiver<IncomingMessage>, res_tx: tokio::sync::mpsc::Sender<OutgoingMessage>) {
        while let Some(req) = req_rx.recv().await {
            match trust_dns_proto::op::Message::from_bytes(&req.msg) {
                Ok(m) => {
                    let query = match m.queries().get(0) {
                        Some(q) => trust_dns_proto::op::LowerQuery::query(q.clone()),
                        None => {
                            continue;
                        }
                    };

                    info!(
                        " request:{id:<5} src:{proto}://{addr}#{port:<5} {op}:{query}:{qtype}:{class} qflags:{qflags} type:{message_type} dnssec:{is_dnssec}",
                        id = m.id(),
                        proto = req.context.protocol(),
                        addr = map_nat64(req.addr.ip()),
                        port = req.addr.port(),
                        message_type = m.message_type(),
                        is_dnssec = m.extensions().as_ref().map_or(false, trust_dns_proto::op::Edns::dnssec_ok),
                        op = m.op_code(),
                        query = query.name(),
                        qtype = query.query_type(),
                        class = query.query_class(),
                        qflags = m.header().flags(),
                    );

                    let c = context.clone();
                    let h = handler.clone();
                    let tx = res_tx.clone();
                    tokio::spawn(async move {
                        let header = m.header().clone();
                        h(c, Request {
                            msg: m,
                            query: query.clone(),
                            raw_bytes: req.msg,
                        }, RequestContext {
                            context: req.context,
                            res_tx: tx,
                            query,
                            header,
                            addr: req.addr,
                        }).await;
                    });
                }
                Err(e) => {
                    warn!("received malformed DNS message: {}", e);
                }
            }
        }
    }

    async fn handle_responses(mut res_rx: tokio::sync::mpsc::Receiver<OutgoingMessage>) {
        while let Some(res) = res_rx.recv().await {
            match res.msg.to_bytes() {
                Ok(b) => {
                    info!("response:{id:<5} src:{proto}://{addr}#{port:<5} {op}:{query}:{qtype}:{class} qflags:{qflags} response:{code:?} rr:{answers}/{authorities}/{additionals} rflags:{rflags}",
                        id = res.msg.id(),
                        proto = res.context.protocol(),
                        addr = map_nat64(res.addr.ip()),
                        port = res.addr.port(),
                        op = res.header.op_code(),
                        query = res.query.name(),
                        qtype = res.query.query_type(),
                        class = res.query.query_class(),
                        qflags = res.header.flags(),
                        code = res.msg.response_code(),
                        answers = res.msg.answer_count(),
                        authorities = res.msg.query_count(),
                        additionals = res.msg.additional_count(),
                        rflags = res.msg.flags()
                    );

                    match res.context {
                        MessageContext::Udp { res_tx } => {
                            let _ = res_tx.send((res.addr, b)).await;
                        }
                        MessageContext::Tcp { res_tx } => {
                            let _ = res_tx.send(b).await;
                        }
                    }
                }
                Err(e) => {
                    error!("failed to serialise DNS message: {}", e);
                }
            }
        }
    }

    pub async fn start_server(self) -> Result<(), JoinError> {
        let mut tasks: Vec<ServerTask> = vec![];

        let (req_tx, req_rx) = tokio::sync::mpsc::channel::<IncomingMessage>(1024);
        let (res_tx, res_rx) = tokio::sync::mpsc::channel::<OutgoingMessage>(1024);

        let task = tokio::spawn(Self::handle_requests(self.context.clone(), self.handler.clone(), req_rx, res_tx));
        tasks.push(ServerTask(task));

        let task = tokio::spawn(Self::handle_responses(res_rx));
        tasks.push(ServerTask(task));

        for udp_socket in &self.sockaddrs {
            info!("binding UDP to {:?}", udp_socket);
            let udp_socket = std::sync::Arc::new(tokio::net::UdpSocket::bind(udp_socket).await
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

        for tcp_listener in &self.sockaddrs {
            info!("binding TCP to {:?}", tcp_listener);
            let tcp_listener = tokio::net::TcpListener::bind(tcp_listener).await
                .expect("Could not bind to TCP socket");

            info!(
                "listening for TCP on {:?}",
                tcp_listener
                    .local_addr()
                    .expect("could not lookup local address")
            );

            let task_req_tx = req_tx.clone();
            let task = tokio::spawn(async move {
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
                            if let Err(e) = tcp_stream_tx.write_all(&res).await {
                                warn!("failed to send TCP response: {}", e);
                            }
                        }
                    });
                }
            });
            tasks.push(ServerTask(task));
        }

        match futures_util::future::select_all(tasks).await {
            (Ok(()), _, _) => {
                Ok(())
            }
            (Err(e), _, _) => {
                Err(e)
            }
        }
    }
}