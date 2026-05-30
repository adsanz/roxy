//! Roxy-owned proxy control path.
//!
//! This module is adapted from hudsucker 0.24.0's private proxy internals. Roxy
//! owns this copy so we can enforce connection lifetime deadlines that hyper's
//! HTTP/2 server builder does not expose and hudsucker cannot inject from its
//! public API.

use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse,
    certificate_authority::CertificateAuthority,
    futures::{SinkExt, StreamExt},
    hyper::{
        Method, Request, Response, StatusCode, Uri,
        body::{Bytes, Incoming},
        header::Entry,
        service::service_fn,
        upgrade::Upgraded,
    },
    hyper_util::{
        client::legacy::{Builder as ClientBuilder, Client, connect::Connect},
        rt::{TokioExecutor, TokioIo},
        server::conn::auto::Builder as ServerBuilder,
    },
    tokio_tungstenite::{
        Connector, WebSocketStream,
        tungstenite::{self, Message},
    },
};
use std::{
    convert::Infallible,
    future::Future,
    io::{self, IoSlice},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tokio_graceful::Shutdown;
use tokio_rustls::TlsAcceptor;
use tracing::{Instrument, Span, error, info, info_span, instrument, warn};

/// Connection lifetime settings enforced by Roxy's vendored proxy path.
#[derive(Clone, Copy, Debug)]
pub struct ConnectionLifecycle {
    pub max_connection_age: Option<Duration>,
    pub max_connection_age_grace: Duration,
    pub connect_initial_read_timeout: Option<Duration>,
    pub tls_handshake_timeout: Option<Duration>,
}

impl Default for ConnectionLifecycle {
    fn default() -> Self {
        Self {
            max_connection_age: Some(Duration::from_secs(30 * 60)),
            max_connection_age_grace: Duration::from_secs(30),
            connect_initial_read_timeout: Some(Duration::from_secs(15)),
            tls_handshake_timeout: Some(Duration::from_secs(15)),
        }
    }
}

/// Proxy runner equivalent to `hudsucker::Proxy::start`, with Roxy deadlines.
pub struct RoxyProxy<C, CA, H, F> {
    listener: TcpListener,
    ca: Arc<CA>,
    http_connector: C,
    client_builder: ClientBuilder,
    server: ServerBuilder<TokioExecutor>,
    http_handler: H,
    websocket_connector: Option<Connector>,
    graceful_shutdown: F,
    lifecycle: ConnectionLifecycle,
}

impl<C, CA, H, F> RoxyProxy<C, CA, H, F>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    F: Future<Output = ()> + Send + 'static,
{
    #[allow(clippy::too_many_arguments)] // This is a port of an existing constructor pattern in hudsucker::Proxy. I just want to add lifecycle without altering much of the existing structure.
    pub fn new(
        listener: TcpListener,
        ca: CA,
        http_connector: C,
        client_builder: ClientBuilder,
        server: ServerBuilder<TokioExecutor>,
        http_handler: H,
        graceful_shutdown: F,
        lifecycle: ConnectionLifecycle,
    ) -> Self {
        Self {
            listener,
            ca: Arc::new(ca),
            http_connector,
            client_builder,
            server,
            http_handler,
            websocket_connector: None,
            graceful_shutdown,
            lifecycle,
        }
    }
}

impl<C, CA, H, F> RoxyProxy<C, CA, H, F>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    F: Future<Output = ()> + Send + 'static,
{
    pub async fn start(self) -> Result<(), hudsucker::Error> {
        let client = self.client_builder.build(self.http_connector);
        let shutdown = Shutdown::new(self.graceful_shutdown);
        let guard = shutdown.guard_weak();

        loop {
            tokio::select! {
                res = self.listener.accept() => {
                    let (tcp, client_addr) = match res {
                        Ok((tcp, client_addr)) => (tcp, client_addr),
                        Err(e) => {
                            error!(target: "proxy", error = %e, "Failed to accept incoming connection");
                            continue;
                        }
                    };

                    let client = client.clone();
                    let server = self.server.clone();
                    let ca = Arc::clone(&self.ca);
                    let http_handler = self.http_handler.clone();
                    let websocket_connector = self.websocket_connector.clone();
                    let lifecycle = self.lifecycle;
                    let deadline = lifecycle.max_connection_age.map(|age| tokio::time::Instant::now() + age);

                    shutdown.spawn_task_fn(move |guard| async move {
                        let service = service_fn(|req| {
                            InternalProxy {
                                ca: Arc::clone(&ca),
                                client: client.clone(),
                                server: server.clone(),
                                http_handler: http_handler.clone(),
                                websocket_connector: websocket_connector.clone(),
                                client_addr,
                                lifecycle,
                                deadline,
                            }
                            .proxy(req)
                        });

                        let conn = server.serve_connection_with_upgrades(TokioIo::new(tcp), service);
                        let mut conn = std::pin::pin!(conn);

                        tokio::select! {
                            res = conn.as_mut() => {
                                if let Err(err) = res {
                                    error!(target: "proxy", error = %err, "Error serving connection");
                                }
                            }
                            _ = guard.cancelled() => {
                                conn.as_mut().graceful_shutdown();
                                if let Err(err) = conn.await {
                                    error!(target: "proxy", error = %err, "Error serving connection during graceful shutdown");
                                }
                            }
                            _ = sleep_until_deadline(deadline), if deadline.is_some() => {
                                info!(target: "proxy", client_addr = %client_addr, "Inbound connection reached max age; starting graceful shutdown");
                                conn.as_mut().graceful_shutdown();
                                match tokio::time::timeout(lifecycle.max_connection_age_grace, conn.as_mut()).await {
                                    Ok(Ok(())) => {
                                        info!(target: "proxy", client_addr = %client_addr, "Inbound connection drained after max-age shutdown");
                                    }
                                    Ok(Err(err)) => {
                                        error!(target: "proxy", client_addr = %client_addr, error = %err, "Error serving connection after max-age shutdown");
                                    }
                                    Err(_) => {
                                        warn!(target: "proxy", client_addr = %client_addr, grace_secs = lifecycle.max_connection_age_grace.as_secs(), "Inbound connection exceeded max-age grace; force closing");
                                    }
                                }
                            }
                        }
                    });
                }
                _ = guard.cancelled() => break,
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
struct Rewind<T> {
    pre: Option<Bytes>,
    inner: T,
}

impl<T> Rewind<T> {
    fn new(io: T, buf: Bytes) -> Self {
        Self {
            pre: Some(buf),
            inner: io,
        }
    }
}

impl<T> AsyncRead for Rewind<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(mut prefix) = self.pre.take()
            && !prefix.is_empty()
        {
            let copy_len = std::cmp::min(prefix.len(), buf.remaining());
            buf.put_slice(&prefix.split_to(copy_len));
            if !prefix.is_empty() {
                self.pre = Some(prefix);
            }
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for Rewind<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

struct InternalProxy<C, CA, H> {
    ca: Arc<CA>,
    client: Client<C, Body>,
    server: ServerBuilder<TokioExecutor>,
    http_handler: H,
    websocket_connector: Option<Connector>,
    client_addr: SocketAddr,
    lifecycle: ConnectionLifecycle,
    deadline: Option<tokio::time::Instant>,
}

impl<C, CA, H> Clone for InternalProxy<C, CA, H>
where
    C: Clone,
    H: Clone,
{
    fn clone(&self) -> Self {
        Self {
            ca: Arc::clone(&self.ca),
            client: self.client.clone(),
            server: self.server.clone(),
            http_handler: self.http_handler.clone(),
            websocket_connector: self.websocket_connector.clone(),
            client_addr: self.client_addr,
            lifecycle: self.lifecycle,
            deadline: self.deadline,
        }
    }
}

impl<C, CA, H> InternalProxy<C, CA, H>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
{
    fn context(&self) -> HttpContext {
        make_http_context(self.client_addr)
    }

    #[instrument(
        skip_all,
        fields(
            version = ?req.version(),
            method = %req.method(),
            uri=%req.uri(),
            client_addr = %self.client_addr,
        )
    )]
    async fn proxy(mut self, req: Request<Incoming>) -> Result<Response<Body>, Infallible> {
        let ctx = self.context();

        let req = match self
            .http_handler
            .handle_request(&ctx, req.map(Body::from))
            .instrument(info_span!("handle_request"))
            .await
        {
            RequestOrResponse::Request(req) => req,
            RequestOrResponse::Response(res) => return Ok(res),
        };

        if req.method() == Method::CONNECT {
            Ok(self.process_connect(req))
        } else if hyper_tungstenite::is_upgrade_request(&req) {
            Ok(self.upgrade_websocket(req))
        } else {
            let res = self
                .client
                .request(normalize_request(req))
                .instrument(info_span!("proxy_request"))
                .await;

            match res {
                Ok(res) => Ok(self
                    .http_handler
                    .handle_response(&ctx, res.map(Body::from))
                    .instrument(info_span!("handle_response"))
                    .await),
                Err(err) => Ok(self
                    .http_handler
                    .handle_error(&ctx, err)
                    .instrument(info_span!("handle_error"))
                    .await),
            }
        }
    }

    fn process_connect(mut self, mut req: Request<Body>) -> Response<Body> {
        match req.uri().authority().cloned() {
            Some(authority) => {
                let span = info_span!("process_connect");
                let fut = async move {
                    match hyper::upgrade::on(&mut req).await {
                        Ok(upgraded) => {
                            let mut upgraded = TokioIo::new(upgraded);
                            let mut buffer = [0; 4];
                            let read = upgraded.read(&mut buffer);
                            let bytes_read = match self.lifecycle.connect_initial_read_timeout {
                                Some(timeout) => match tokio::time::timeout(timeout, read).await {
                                    Ok(Ok(bytes_read)) => bytes_read,
                                    Ok(Err(e)) => {
                                        error!(target: "proxy", error = %e, "Failed to read from upgraded CONNECT connection");
                                        return;
                                    }
                                    Err(_) => {
                                        warn!(target: "proxy", authority = %authority, timeout_secs = timeout.as_secs(), "CONNECT initial read timed out");
                                        return;
                                    }
                                },
                                None => match read.await {
                                    Ok(bytes_read) => bytes_read,
                                    Err(e) => {
                                        error!(target: "proxy", error = %e, "Failed to read from upgraded CONNECT connection");
                                        return;
                                    }
                                },
                            };

                            let mut upgraded = Rewind::new(
                                upgraded,
                                Bytes::copy_from_slice(buffer[..bytes_read].as_ref()),
                            );

                            if self
                                .http_handler
                                .should_intercept(&self.context(), &req)
                                .await
                            {
                                if buffer == *b"GET " {
                                    if let Err(e) = self
                                        .serve_stream(
                                            TokioIo::new(upgraded),
                                            http::uri::Scheme::HTTP,
                                            authority,
                                        )
                                        .await
                                    {
                                        error!(target: "proxy", error = %e, "WebSocket connect error");
                                    }
                                    return;
                                } else if buffer[..2] == *b"\x16\x03" {
                                    let server_config = self
                                        .ca
                                        .gen_server_config(&authority)
                                        .instrument(info_span!("gen_server_config"))
                                        .await;

                                    let accept = TlsAcceptor::from(server_config).accept(upgraded);
                                    let stream = match self.lifecycle.tls_handshake_timeout {
                                        Some(timeout) => {
                                            match tokio::time::timeout(timeout, accept).await {
                                                Ok(Ok(stream)) => TokioIo::new(stream),
                                                Ok(Err(e)) => {
                                                    error!(target: "proxy", error = %e, "Failed to establish TLS connection");
                                                    return;
                                                }
                                                Err(_) => {
                                                    warn!(target: "proxy", authority = %authority, timeout_secs = timeout.as_secs(), "TLS handshake timed out");
                                                    return;
                                                }
                                            }
                                        }
                                        None => match accept.await {
                                            Ok(stream) => TokioIo::new(stream),
                                            Err(e) => {
                                                error!(target: "proxy", error = %e, "Failed to establish TLS connection");
                                                return;
                                            }
                                        },
                                    };

                                    if let Err(e) = self
                                        .serve_stream(stream, http::uri::Scheme::HTTPS, authority)
                                        .await
                                        && !e
                                            .to_string()
                                            .starts_with("error shutting down connection")
                                        {
                                            error!(target: "proxy", error = %e, "HTTPS connect error");
                                        }
                                    return;
                                } else {
                                    warn!(target: "proxy", bytes = ?&buffer[..bytes_read], "Unknown CONNECT protocol");
                                }
                            }

                            let mut server = match TcpStream::connect(authority.as_ref()).await {
                                Ok(server) => server,
                                Err(e) => {
                                    error!(target: "proxy", authority = %authority, error = %e, "Failed to connect raw tunnel");
                                    return;
                                }
                            };

                            let copy = tokio::io::copy_bidirectional(&mut upgraded, &mut server);
                            tokio::select! {
                                res = copy => {
                                    if let Err(e) = res {
                                        error!(target: "proxy", authority = %authority, error = %e, "Failed to tunnel");
                                    }
                                }
                                _ = sleep_until_deadline(self.deadline), if self.deadline.is_some() => {
                                    info!(target: "proxy", authority = %authority, "Raw CONNECT tunnel reached max age; closing");
                                }
                            }
                        }
                        Err(e) => error!(target: "proxy", error = %e, "Upgrade error"),
                    };
                };

                spawn_with_trace(fut, span);
                Response::new(Body::empty())
            }
            None => bad_request(),
        }
    }

    #[instrument(skip_all)]
    fn upgrade_websocket(self, req: Request<Body>) -> Response<Body> {
        let mut req = {
            let (mut parts, _) = req.into_parts();

            parts.uri = {
                let mut parts = parts.uri.into_parts();
                parts.scheme =
                    if parts.scheme.unwrap_or(http::uri::Scheme::HTTP) == http::uri::Scheme::HTTP {
                        Some("ws".try_into().expect("Failed to convert scheme"))
                    } else {
                        Some("wss".try_into().expect("Failed to convert scheme"))
                    };

                match Uri::from_parts(parts) {
                    Ok(uri) => uri,
                    Err(_) => return bad_request(),
                }
            };

            Request::from_parts(parts, ())
        };

        match hyper_tungstenite::upgrade(&mut req, None) {
            Ok((res, websocket)) => {
                let span = info_span!("websocket");
                let fut = async move {
                    match websocket.await {
                        Ok(ws) => {
                            if let Err(e) = self.handle_websocket(ws, req).await {
                                error!(target: "proxy", error = %e, "Failed to handle WebSocket");
                            }
                        }
                        Err(e) => {
                            error!(target: "proxy", error = %e, "Failed to upgrade to WebSocket")
                        }
                    }
                };

                spawn_with_trace(fut, span);
                res.map(Body::from)
            }
            Err(_) => bad_request(),
        }
    }

    #[instrument(skip_all)]
    async fn handle_websocket(
        self,
        client_socket: WebSocketStream<TokioIo<Upgraded>>,
        req: Request<()>,
    ) -> Result<(), tungstenite::Error> {
        let uri = req.uri().clone();
        let (server_socket, _) = hudsucker::tokio_tungstenite::connect_async_tls_with_config(
            req,
            None,
            false,
            self.websocket_connector,
        )
        .await?;

        let (server_sink, server_stream) = server_socket.split();
        let (client_sink, client_stream) = client_socket.split();

        spawn_websocket_forwarder(server_stream, client_sink, uri.clone(), self.client_addr);
        spawn_websocket_forwarder(client_stream, server_sink, uri, self.client_addr);

        Ok(())
    }

    #[instrument(skip_all)]
    async fn serve_stream<I>(
        self,
        stream: I,
        scheme: http::uri::Scheme,
        authority: http::uri::Authority,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        let client_addr = self.client_addr;
        let lifecycle = self.lifecycle;
        let deadline = self.deadline;
        let service = service_fn(|mut req| {
            if req.version() == hyper::Version::HTTP_10 || req.version() == hyper::Version::HTTP_11
            {
                let (mut parts, body) = req.into_parts();

                parts.uri = {
                    let mut parts = parts.uri.into_parts();
                    parts.scheme = Some(scheme.clone());
                    parts.authority = Some(authority.clone());
                    Uri::from_parts(parts).expect("Failed to build URI")
                };

                req = Request::from_parts(parts, body);
            };

            self.clone().proxy(req)
        });

        let conn = self.server.serve_connection_with_upgrades(stream, service);
        let mut conn = std::pin::pin!(conn);

        tokio::select! {
            res = conn.as_mut() => res,
            _ = sleep_until_deadline(deadline), if deadline.is_some() => {
                info!(target: "proxy", client_addr = %client_addr, "MITM stream reached max age; starting graceful shutdown");
                conn.as_mut().graceful_shutdown();
                match tokio::time::timeout(lifecycle.max_connection_age_grace, conn.as_mut()).await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => Err(e),
                    Err(_) => {
                        warn!(target: "proxy", client_addr = %client_addr, grace_secs = lifecycle.max_connection_age_grace.as_secs(), "MITM stream exceeded max-age grace; force closing");
                        Ok(())
                    }
                }
            }
        }
    }
}

fn bad_request() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::empty())
        .expect("Failed to build response")
}

fn spawn_with_trace<T: Send + Sync + 'static>(
    fut: impl Future<Output = T> + Send + 'static,
    span: Span,
) -> tokio::task::JoinHandle<T> {
    tokio::spawn(fut.instrument(span))
}

fn spawn_websocket_forwarder<S, K>(mut stream: S, mut sink: K, uri: Uri, client_addr: SocketAddr)
where
    S: hudsucker::futures::Stream<Item = Result<Message, tungstenite::Error>>
        + Unpin
        + Send
        + 'static,
    K: hudsucker::futures::Sink<Message, Error = tungstenite::Error> + Unpin + Send + 'static,
{
    let span = info_span!("message_forwarder", %uri, %client_addr);
    let fut = async move {
        while let Some(message) = stream.next().await {
            match message {
                Ok(message) => {
                    if let Err(e) = sink.send(message).await {
                        error!(target: "proxy", error = %e, "Failed to forward WebSocket message");
                        break;
                    }
                }
                Err(e) => {
                    error!(target: "proxy", error = %e, "Failed to read WebSocket message");
                    break;
                }
            }
        }
    };
    spawn_with_trace(fut, span);
}

fn make_http_context(client_addr: SocketAddr) -> HttpContext {
    // hudsucker marks HttpContext as #[non_exhaustive] but exposes no public
    // constructor. Its 0.24.0 layout contains exactly the public client_addr
    // field. This is the smallest compatibility shim needed for a vendored
    // proxy control path while still using hudsucker's public HttpHandler API.
    unsafe {
        let mut ctx = std::mem::MaybeUninit::<HttpContext>::uninit();
        let ptr = ctx.as_mut_ptr();
        std::ptr::addr_of_mut!((*ptr).client_addr).write(client_addr);
        ctx.assume_init()
    }
}

#[instrument(skip_all)]
fn normalize_request<T>(mut req: Request<T>) -> Request<T> {
    req.headers_mut().remove(hyper::header::HOST);

    if let Entry::Occupied(mut cookies) = req.headers_mut().entry(hyper::header::COOKIE) {
        let mut joined = Vec::new();
        for (index, value) in cookies.iter().enumerate() {
            if index > 0 {
                joined.extend_from_slice(b"; ");
            }
            joined.extend_from_slice(value.as_bytes());
        }
        cookies.insert(joined.try_into().expect("Failed to join cookies"));
    }

    *req.version_mut() = hyper::Version::HTTP_11;
    req
}

async fn sleep_until_deadline(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending::<()>().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hudsucker::hyper_util::client::legacy::connect::HttpConnector;
    use hudsucker::rustls::ServerConfig;

    struct CA;

    impl CertificateAuthority for CA {
        async fn gen_server_config(&self, _authority: &http::uri::Authority) -> Arc<ServerConfig> {
            unimplemented!();
        }
    }

    #[derive(Clone)]
    struct TestHandler;

    impl HttpHandler for TestHandler {}

    fn build_proxy() -> InternalProxy<HttpConnector, CA, TestHandler> {
        InternalProxy {
            ca: Arc::new(CA),
            client: Client::builder(TokioExecutor::new()).build(HttpConnector::new()),
            server: ServerBuilder::new(TokioExecutor::new()),
            http_handler: TestHandler,
            websocket_connector: None,
            client_addr: "127.0.0.1:8080".parse().unwrap(),
            lifecycle: ConnectionLifecycle::default(),
            deadline: None,
        }
    }

    #[test]
    fn bad_request_status() {
        let res = bad_request();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn normalize_request_removes_host_header() {
        let req = Request::builder()
            .uri("http://example.com/")
            .header(hyper::header::HOST, "example.com")
            .body(())
            .unwrap();

        let req = normalize_request(req);
        assert_eq!(req.headers().get(hyper::header::HOST), None);
    }

    #[test]
    fn normalize_request_joins_cookies() {
        let req = Request::builder()
            .uri("http://example.com/")
            .header(hyper::header::COOKIE, "foo=bar")
            .header(hyper::header::COOKIE, "baz=qux")
            .body(())
            .unwrap();

        let req = normalize_request(req);
        assert_eq!(
            req.headers().get_all(hyper::header::COOKIE).iter().count(),
            1
        );
        assert_eq!(
            req.headers().get(hyper::header::COOKIE),
            Some(&"foo=bar; baz=qux".parse().unwrap())
        );
    }

    #[test]
    fn process_connect_returns_bad_request_without_authority() {
        let proxy = build_proxy();
        let req = Request::builder()
            .uri("/foo/bar?baz")
            .body(Body::empty())
            .unwrap();

        let res = proxy.process_connect(req);
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
}
