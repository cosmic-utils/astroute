use crate::{
    Result, linux,
    proxy::{self, Connection, Settings},
    types::Fallback,
};
use anyhow::{Context, ensure};
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    time::timeout,
};

pub fn question(query: &[u8]) -> Result<&[u8]> {
    ensure!(
        (12..=65535).contains(&query.len()) && query[2] & 0x80 == 0 && query[4..6] == [0, 1],
        "Invalid DNS query"
    );
    let mut offset = 12;
    let mut labels = 0;
    loop {
        let size = *query.get(offset).context("Incomplete DNS name")?;
        offset += 1;
        if size == 0 {
            break;
        }
        if size & 0xc0 == 0xc0 {
            let low = *query.get(offset).context("Incomplete DNS pointer")?;
            let pointer = (usize::from(size & 0x3f) << 8) | usize::from(low);
            ensure!(pointer < query.len(), "Invalid DNS pointer");
            offset += 1;
            break;
        }
        ensure!(size <= 63, "Invalid DNS name");
        offset += usize::from(size);
        labels += usize::from(size) + 1;
        ensure!(offset < query.len() && labels <= 255, "Incomplete DNS name");
    }
    ensure!(offset + 4 <= query.len(), "Incomplete DNS question");
    Ok(&query[12..offset + 4])
}
pub fn short_reply(query: &[u8], flags: u16) -> Result<Vec<u8>> {
    let question = question(query)?;
    let mut reply = query[..2].to_vec();
    reply.extend(flags.to_be_bytes());
    reply.extend([0, 1, 0, 0, 0, 0, 0, 0]);
    reply.extend(question);
    Ok(reply)
}
pub async fn response_body(stream: &mut Connection) -> Result<Vec<u8>> {
    let header = proxy::read_until(stream, b"\r\n\r\n", 16384).await?;
    ensure!(
        proxy::http_status(&header)? == 200,
        "DNS HTTPS returned an unexpected status"
    );
    let text = std::str::from_utf8(&header)?;
    let mut fields = BTreeMap::new();
    for line in text.split("\r\n").skip(1).filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':').context("Invalid DNS HTTPS headers")?;
        let name = name.to_ascii_lowercase();
        ensure!(
            !fields.contains_key(&name)
                || !["content-length", "content-type", "transfer-encoding"]
                    .contains(&name.as_str()),
            "Duplicate DNS HTTPS headers"
        );
        fields.insert(name, value.trim().to_owned());
    }
    ensure!(
        fields
            .get("content-type")
            .and_then(|v| v.split(';').next())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/dns-message")),
        "Unexpected DNS HTTPS content type"
    );
    if let Some(encoding) = fields.get("transfer-encoding") {
        ensure!(
            encoding.eq_ignore_ascii_case("chunked") && !fields.contains_key("content-length"),
            "Invalid DNS HTTPS response encoding"
        );
        let mut body = Vec::new();
        loop {
            let line = proxy::read_until(stream, b"\r\n", 128).await?;
            let size = usize::from_str_radix(
                std::str::from_utf8(&line)?
                    .split(';')
                    .next()
                    .unwrap()
                    .trim(),
                16,
            )?;
            ensure!(
                size <= 65535 - body.len(),
                "DNS HTTPS response is too large"
            );
            if size == 0 {
                break;
            }
            let offset = body.len();
            body.resize(offset + size, 0);
            stream.read_exact(&mut body[offset..]).await?;
            let mut ending = [0u8; 2];
            stream.read_exact(&mut ending).await?;
            ensure!(ending == *b"\r\n", "Invalid DNS HTTPS chunk");
        }
        ensure!(body.len() >= 12, "Invalid DNS HTTPS response length");
        Ok(body)
    } else {
        let size: usize = fields
            .get("content-length")
            .context("Missing DNS HTTPS response length")?
            .parse()?;
        ensure!(
            (12..=65535).contains(&size),
            "Invalid DNS HTTPS response length"
        );
        let mut body = vec![0u8; size];
        stream.read_exact(&mut body).await?;
        Ok(body)
    }
}
async fn https_query(settings: &Settings, query: &[u8], direct: bool) -> Result<Vec<u8>> {
    let stream = if direct {
        proxy::direct("1.1.1.1", 443).await?
    } else {
        proxy::open_tunnel(&settings.profile, "1.1.1.1", 443).await?
    };
    let mut stream = proxy::tls(stream, "cloudflare-dns.com").await?;
    let header = format!(
        "POST /dns-query HTTP/1.1\r\nHost: cloudflare-dns.com\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        query.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(query).await?;
    let response = response_body(&mut stream).await?;
    ensure!(
        response[..2] == query[..2] && response[2] & 0x80 != 0,
        "Invalid DNS HTTPS answer"
    );
    Ok(response)
}
async fn resolve(settings: &Settings, query: &[u8]) -> Result<Vec<u8>> {
    question(query)?;
    if let Ok(Ok(response)) =
        timeout(Duration::from_secs(5), https_query(settings, query, false)).await
    {
        return Ok(response);
    }
    if settings.fallback == Fallback::Direct
        && let Ok(Ok(response)) =
            timeout(Duration::from_secs(5), https_query(settings, query, true)).await
    {
        return Ok(response);
    }
    short_reply(
        query,
        0x8082 | (u16::from_be_bytes([query[2], query[3]]) & 0x7900),
    )
}
async fn udp(socket: UdpSocket, settings: Arc<Settings>, permits: Arc<Semaphore>) -> Result<()> {
    let socket = Arc::new(socket);
    let mut buffer = vec![0u8; 65535];
    loop {
        let (size, peer) = socket.recv_from(&mut buffer).await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let query = buffer[..size].to_vec();
        let socket = socket.clone();
        let settings = settings.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Ok(mut answer) = resolve(&settings, &query).await {
                if answer.len() > 512 {
                    let flags = u16::from_be_bytes([answer[2], answer[3]]) | 0x0200;
                    let Ok(short) = short_reply(&query, flags) else {
                        return;
                    };
                    answer = short;
                }
                let _ = socket.send_to(&answer, peer).await;
            }
        });
    }
}
async fn tcp_query(mut stream: TcpStream, settings: Arc<Settings>) -> Result<()> {
    for _ in 0..32 {
        let size = timeout(Duration::from_secs(15), stream.read_u16()).await??;
        ensure!(size >= 12, "Invalid DNS message length");
        let mut query = vec![0u8; usize::from(size)];
        timeout(Duration::from_secs(5), stream.read_exact(&mut query)).await??;
        let answer = resolve(&settings, &query).await?;
        timeout(Duration::from_secs(5), async {
            stream.write_u16(answer.len() as u16).await?;
            stream.write_all(&answer).await
        })
        .await??;
    }
    Ok(())
}
async fn tcp(
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
            let _ = tcp_query(stream, settings).await;
        });
    }
}
pub struct Listeners {
    tcp4: TcpListener,
    tcp6: Option<TcpListener>,
    udp4: UdpSocket,
    udp6: Option<UdpSocket>,
}
impl Listeners {
    pub async fn bind() -> Result<Self> {
        let tcp4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = tcp4.local_addr()?.port();
        let ipv6 = linux::ipv6_loopback()?;
        Ok(Self {
            tcp4,
            tcp6: if ipv6 {
                Some(TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await?)
            } else {
                None
            },
            udp4: UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).await?,
            udp6: if ipv6 {
                Some(UdpSocket::bind((Ipv6Addr::LOCALHOST, port)).await?)
            } else {
                None
            },
        })
    }
    pub fn port(&self) -> Result<u16> {
        Ok(self.tcp4.local_addr()?.port())
    }
    pub async fn serve(self, settings: Arc<Settings>) -> Result<()> {
        let permits = Arc::new(Semaphore::new(64));
        tokio::try_join!(
            tcp(self.tcp4, settings.clone(), permits.clone()),
            async {
                match self.tcp6 {
                    Some(listener) => tcp(listener, settings.clone(), permits.clone()).await,
                    None => std::future::pending::<Result<()>>().await,
                }
            },
            udp(self.udp4, settings.clone(), permits.clone()),
            async {
                match self.udp6 {
                    Some(socket) => udp(socket, settings.clone(), permits.clone()).await,
                    None => std::future::pending::<Result<()>>().await,
                }
            }
        )?;
        Ok(())
    }
}
