use crate::{
    Result, dns, linux,
    types::{Fallback, Mode, Profile},
};
use anyhow::{Context, bail, ensure};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsRawFd,
    path::Path,
    process::Child,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time::timeout,
};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type Connection = Box<dyn Stream>;
static TLS: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
fn tls_config() -> Result<Arc<rustls::ClientConfig>> {
    if let Some(config) = TLS.get() {
        return Ok(config.clone());
    }
    let mut roots = rustls::RootCertStore::empty();
    let certificates = rustls_native_certs::load_native_certs();
    for cert in certificates.certs {
        let _ = roots.add(cert);
    }
    ensure!(
        !roots.is_empty(),
        "No trusted system TLS certificates are available"
    );
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let _ = TLS.set(config.clone());
    Ok(config)
}
pub async fn tls(stream: Connection, host: &str) -> Result<Connection> {
    let server = rustls::pki_types::ServerName::try_from(host.to_owned())
        .context("Invalid TLS server name")?;
    let stream = tokio_rustls::TlsConnector::from(tls_config()?)
        .connect(server, stream)
        .await
        .context("TLS certificate verification or negotiation failed")?;
    Ok(Box::new(stream))
}
pub async fn direct(host: &str, port: u16) -> Result<Connection> {
    Ok(Box::new(TcpStream::connect((host, port)).await?))
}
pub async fn read_until(
    stream: &mut (impl AsyncRead + Unpin + ?Sized),
    delimiter: &[u8],
    limit: usize,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        ensure!(bytes.len() < limit, "HTTP response headers are too large");
        let byte = stream.read_u8().await.context("Incomplete HTTP response")?;
        bytes.push(byte);
        if bytes.ends_with(delimiter) {
            return Ok(bytes);
        }
    }
}
pub fn http_status(header: &[u8]) -> Result<u16> {
    let line = header
        .split(|b| *b == b'\n')
        .next()
        .context("Missing HTTP status")?;
    let text = std::str::from_utf8(line)?;
    let parts: Vec<_> = text.split_whitespace().collect();
    ensure!(
        parts.len() >= 2
            && ["HTTP/1.0", "HTTP/1.1"].contains(&parts[0])
            && parts[1].len() == 3
            && parts[1].bytes().all(|c| c.is_ascii_digit()),
        "Invalid HTTP response status"
    );
    Ok(parts[1].parse()?)
}
pub async fn open_tunnel(profile: &Profile, host: &str, port: u16) -> Result<Connection> {
    let mut stream = direct(&profile.host, profile.port).await?;
    if profile.protocol == "https" {
        stream = tls(stream, &profile.host).await?;
    }
    if profile.protocol == "socks5" {
        let auth = !profile.username.is_empty();
        let method = if auth { 2 } else { 0 };
        stream.write_all(&[5, 1, method]).await?;
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await?;
        ensure!(
            reply == [5, method],
            "SOCKS5 authentication method was rejected"
        );
        if auth {
            let mut credentials = vec![1, profile.username.len() as u8];
            credentials.extend(profile.username.as_bytes());
            credentials.push(profile.password.len() as u8);
            credentials.extend(profile.password.as_bytes());
            stream.write_all(&credentials).await?;
            stream.read_exact(&mut reply).await?;
            ensure!(reply == [1, 0], "SOCKS5 authentication failed");
        }
        let mut request = vec![5, 1, 0];
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                request.push(1);
                request.extend(ip.octets());
            }
            Ok(IpAddr::V6(ip)) => {
                request.push(4);
                request.extend(ip.octets());
            }
            Err(_) => {
                let domain = idna::domain_to_ascii(host)
                    .map_err(|_| anyhow::anyhow!("Invalid SOCKS5 destination hostname"))?;
                ensure!(
                    !domain.is_empty() && domain.len() <= 255,
                    "Invalid SOCKS5 destination hostname"
                );
                request.extend([3, domain.len() as u8]);
                request.extend(domain.as_bytes());
            }
        }
        request.extend(port.to_be_bytes());
        stream.write_all(&request).await?;
        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).await?;
        ensure!(reply[..3] == [5, 0, 0], "SOCKS5 CONNECT was rejected");
        let size = match reply[3] {
            1 => 4,
            4 => 16,
            3 => usize::from(stream.read_u8().await?),
            _ => bail!("Invalid SOCKS5 reply"),
        };
        let mut address = vec![0u8; size + 2];
        stream.read_exact(&mut address).await?;
    } else {
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        ensure!(
            !authority.chars().any(|c| c.is_control()),
            "Invalid HTTP CONNECT destination"
        );
        let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if !profile.username.is_empty() {
            request.push_str(&format!(
                "Proxy-Authorization: Basic {}\r\n",
                base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{}", profile.username, profile.password))
            ));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;
        let header = read_until(&mut stream, b"\r\n\r\n", 16384).await?;
        ensure!(
            (200..300).contains(&http_status(&header)?),
            "HTTP CONNECT was rejected"
        );
    }
    Ok(stream)
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Settings {
    pub profile: Profile,
    pub mode: Mode,
    #[serde(default)]
    pub fallback: Fallback,
}
pub fn original_destination(stream: &TcpStream) -> Result<SocketAddr> {
    let ipv6 = stream.local_addr()?.is_ipv6();
    let mut bytes = [0u8; 28];
    let mut length = if ipv6 { 28 } else { 16 };
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            if ipv6 {
                libc::IPPROTO_IPV6
            } else {
                libc::SOL_IP
            },
            80,
            bytes.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    ensure!(
        length >= if ipv6 { 28 } else { 16 },
        "Invalid original destination"
    );
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let ip = if ipv6 {
        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24])?))
    } else {
        IpAddr::V4(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]))
    };
    ensure!(
        port > 0
            && !ip.is_loopback()
            && !matches!(ip,IpAddr::V6(v) if v.to_ipv4_mapped().is_some_and(|a| a.is_loopback())),
        "Only redirected connections are accepted"
    );
    Ok(SocketAddr::new(ip, port))
}
fn local_address(ip: IpAddr) -> bool {
    [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ]
    .iter()
    .any(|n| n.parse::<ipnet::IpNet>().unwrap().contains(&ip))
}
async fn pump(
    mut source: impl AsyncRead + Unpin,
    mut target: impl AsyncWrite + Unpin,
) -> Result<()> {
    let mut bytes = [0u8; 65536];
    loop {
        let size = timeout(Duration::from_secs(300), source.read(&mut bytes)).await??;
        if size == 0 {
            timeout(Duration::from_secs(300), target.shutdown()).await??;
            return Ok(());
        }
        timeout(Duration::from_secs(300), target.write_all(&bytes[..size])).await??;
    }
}
async fn relay(stream: TcpStream, settings: Arc<Settings>) -> Result<()> {
    let address = original_destination(&stream)?;
    ensure!(
        settings.mode != Mode::Local || local_address(address.ip()),
        "Destination is outside the local network"
    );
    let remote = timeout(
        Duration::from_secs(10),
        open_tunnel(&settings.profile, &address.ip().to_string(), address.port()),
    )
    .await;
    let remote = match remote {
        Ok(Ok(stream)) => stream,
        _ if settings.fallback == Fallback::Direct => {
            timeout(
                Duration::from_secs(10),
                direct(&address.ip().to_string(), address.port()),
            )
            .await??
        }
        _ => bail!("Proxy connection failed"),
    };
    let (input, output) = tokio::io::split(stream);
    let (remote_input, remote_output) = tokio::io::split(remote);
    tokio::try_join!(pump(input, remote_output), pump(remote_input, output))?;
    Ok(())
}
async fn accept(
    listener: TcpListener,
    settings: Arc<Settings>,
    permits: Arc<Semaphore>,
) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let settings = settings.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = relay(stream, settings).await;
        });
    }
}
pub async fn serve(settings: Settings) -> Result<()> {
    let settings = Arc::new(settings);
    let first = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = first.local_addr()?.port();
    let second = if linux::ipv6_loopback()? {
        Some(TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await?)
    } else {
        None
    };
    let dns = dns::Listeners::bind().await?;
    let dns_port = dns.port()?;
    {
        let mut out = std::io::stdout().lock();
        serde_json::to_writer(&mut out, &json!({"port":port,"dns_port":dns_port}))?;
        out.write_all(b"\n")?;
        out.flush()?;
    }
    let permits = Arc::new(Semaphore::new(256));
    tokio::try_join!(
        accept(first, settings.clone(), permits.clone()),
        async {
            match second {
                Some(listener) => accept(listener, settings.clone(), permits).await,
                None => std::future::pending::<Result<()>>().await,
            }
        },
        dns.serve(settings.clone())
    )?;
    Ok(())
}
pub fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}
pub fn worker() -> Result<()> {
    ensure!(
        linux::uid() != 0,
        "Proxy workers must run as the desktop user"
    );
    let mut line = String::new();
    std::io::stdin().take(65537).read_to_string(&mut line)?;
    ensure!(line.len() <= 65536, "Proxy settings are too large");
    let raw: Value = serde_json::from_str(&line)?;
    let settings = Settings {
        profile: Profile::parse(&raw["profile"], None)?,
        mode: serde_json::from_value(raw["mode"].clone())?,
        fallback: serde_json::from_value(raw.get("fallback").cloned().unwrap_or(json!("block")))?,
    };
    runtime()?.block_on(serve(settings))
}
pub async fn probe(profile: &Profile) -> Result<Value> {
    let started = Instant::now();
    timeout(Duration::from_secs(15),async {
        let mut stream=tls(open_tunnel(profile,"cp.cloudflare.com",443).await?,"cp.cloudflare.com").await?;
        stream.write_all(b"GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nConnection: close\r\n\r\n").await?;
        let header=read_until(&mut stream,b"\r\n\r\n",16384).await?; let status=http_status(&header)?; ensure!(status==204,"The HTTPS test endpoint returned HTTP {status}; expected HTTP 204");
        Ok(json!({"elapsed_ms":started.elapsed().as_millis().max(1),"target":"https://cp.cloudflare.com/generate_204"}))
    }).await.context("Proxy test timed out after 15 seconds")?
}
pub struct Relay {
    child: Child,
    pub port: u16,
    pub dns_port: u16,
}
impl Relay {
    pub fn start(uid: u32, group: &Path, settings: &Settings) -> Result<Self> {
        let child = linux::spawn_worker(&linux::user(uid)?, group)?;
        let mut relay = Self {
            child,
            port: 0,
            dns_port: 0,
        };
        let result = (|| -> Result<()> {
            {
                let mut pipe = relay.child.stdin.take().context("Missing worker input")?;
                serde_json::to_writer(&mut pipe, settings)?;
                pipe.write_all(b"\n")?;
            }
            let mut pipe = relay.child.stdout.take().context("Missing worker output")?;
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut line = Vec::new();
            loop {
                ensure!(Instant::now() < deadline, "Proxy relay startup timed out");
                ensure!(
                    linux::poll(
                        pipe.as_raw_fd(),
                        deadline
                            .saturating_duration_since(Instant::now())
                            .as_millis()
                            .min(5000) as i32
                    )?,
                    "Proxy relay startup timed out"
                );
                let mut byte = [0u8; 1];
                ensure!(
                    pipe.read(&mut byte)? == 1,
                    "Proxy relay exited before startup"
                );
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
                ensure!(line.len() <= 4096, "Invalid proxy relay readiness");
            }
            let ready: Value = serde_json::from_slice(&line)?;
            relay.port = ready["port"]
                .as_u64()
                .filter(|p| (1..=65535).contains(p))
                .context("Invalid relay port")? as u16;
            relay.dns_port = ready["dns_port"]
                .as_u64()
                .filter(|p| (1..=65535).contains(p))
                .context("Invalid DNS relay port")? as u16;
            Ok(())
        })();
        result.context("Unable to start the proxy relay")?;
        Ok(relay)
    }
    pub fn ended(&mut self) -> bool {
        self.child.try_wait().map(|s| s.is_some()).unwrap_or(true)
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            unsafe {
                libc::kill(self.child.id() as i32, libc::SIGTERM);
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                if self.child.try_wait().ok().flatten().is_some() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}
