//! Port scanner (v1.7.0): plain TCP connect scans, from THIS PC or THROUGH a
//! saved host. Through a host, every probe is an SSH `direct-tcpip` channel —
//! the server makes the connection, exactly like a -L tunnel does — so internal
//! networks only the server can see are scannable with nothing installed on it.
//!
//! Deliberately not here: SYN/UDP scans (raw sockets = admin on Windows, UDP
//! answers are unreliable) and OS fingerprinting. That is nmap's job.
//!
//! Outcomes per probe:
//!   open    — connected (optionally a banner is read)
//!   closed  — actively refused; the host is alive, nothing listens
//!   silent  — no answer within the timeout: firewalled, or unreachable from
//!             where the scan runs. All-silent is the hint to scan from a server.

use crate::ssh::{dedicated, Client};
use russh::client::Handle;
use serde_json::json;
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// running scans: id -> stop flag
#[derive(Default)]
pub struct Scans(pub Mutex<HashMap<u32, Arc<AtomicBool>>>);

const MAX_HOSTS: usize = 65_536;
const MAX_PROBES: u64 = 3_000_000;
/// ports used to decide whether a host is up before scanning it
const DISCOVERY_PORTS: [u16; 7] = [22, 80, 443, 3389, 445, 8080, 135];

/* ---------- parsing ---------- */

/// One target: what the user typed (`label`) and what to connect to (`addr`).
#[derive(Clone)]
pub struct Target {
    pub label: String,
    pub addr: String,
}

fn is_hostname(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        && !s.starts_with('-')
}

/// `10.0.0.5`, `10.0.0.0/24`, `10.0.0.1-50`, `10.0.0.1-10.0.1.20`, `db.lan` —
/// separated by commas, spaces or newlines.
pub fn parse_targets(s: &str) -> Result<Vec<Target>, String> {
    let mut out: Vec<Target> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut push = |out: &mut Vec<Target>, t: Target| -> Result<(), String> {
        if seen.insert(t.addr.clone()) {
            out.push(t);
        }
        if out.len() > MAX_HOSTS {
            return Err(format!("more than {MAX_HOSTS} targets — use a smaller range (a /16 is the largest)"));
        }
        Ok(())
    };
    for item in s.split(|c: char| c == ',' || c.is_whitespace()).filter(|x| !x.is_empty()) {
        if let Some((ip, bits)) = item.split_once('/') {
            let ip: Ipv4Addr = ip.parse().map_err(|_| format!("'{item}': not an IPv4 subnet"))?;
            let bits: u32 = bits.parse().map_err(|_| format!("'{item}': bad prefix length"))?;
            if !(16..=32).contains(&bits) {
                return Err(format!("'{item}': prefix must be /16 … /32"));
            }
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            let net = u32::from(ip) & mask;
            let last = net | !mask;
            // skip network + broadcast addresses for normal subnets
            let (a, b) = if bits <= 30 { (net + 1, last - 1) } else { (net, last) };
            for n in a..=b {
                let t = Ipv4Addr::from(n).to_string();
                push(&mut out, Target { label: t.clone(), addr: t })?;
            }
        } else if let Some((from, to)) = item.split_once('-').filter(|(f, _)| f.parse::<Ipv4Addr>().is_ok()) {
            let a: Ipv4Addr = from.parse().unwrap();
            let b: Ipv4Addr = if let Ok(full) = to.parse::<Ipv4Addr>() {
                full
            } else {
                let last: u8 = to.parse().map_err(|_| format!("'{item}': range end must be an IP or 0-255"))?;
                let o = a.octets();
                Ipv4Addr::new(o[0], o[1], o[2], last)
            };
            let (a, b) = (u32::from(a), u32::from(b));
            if b < a {
                return Err(format!("'{item}': range runs backwards"));
            }
            if (b - a) as usize >= MAX_HOSTS {
                return Err(format!("'{item}': range too large"));
            }
            for n in a..=b {
                let t = Ipv4Addr::from(n).to_string();
                push(&mut out, Target { label: t.clone(), addr: t })?;
            }
        } else if item.parse::<IpAddr>().is_ok() || is_hostname(item) {
            push(&mut out, Target { label: item.to_string(), addr: item.to_string() })?;
        } else {
            return Err(format!("'{item}': not an IP, subnet, range or hostname"));
        }
    }
    if out.is_empty() {
        return Err("no targets given".into());
    }
    Ok(out)
}

/// `22,80,443,8000-8100` → sorted unique ports.
pub fn parse_ports(s: &str) -> Result<Vec<u16>, String> {
    let mut set = BTreeSet::new();
    let num = |x: &str| -> Result<u16, String> {
        let v: u32 = x.trim().parse().map_err(|_| format!("'{x}': not a port number"))?;
        if (1..=65535).contains(&v) { Ok(v as u16) } else { Err(format!("{v}: ports are 1-65535")) }
    };
    for item in s.split(|c: char| c == ',' || c.is_whitespace()).filter(|x| !x.is_empty()) {
        if let Some((a, b)) = item.split_once('-') {
            let (a, b) = (num(a)?, num(b)?);
            if b < a {
                return Err(format!("'{item}': range runs backwards"));
            }
            set.extend(a..=b);
        } else {
            set.insert(num(item)?);
        }
    }
    if set.is_empty() {
        return Err("no ports given".into());
    }
    Ok(set.into_iter().collect())
}

/* ---------- services + banners ---------- */

pub fn service(port: u16) -> &'static str {
    match port {
        20 | 21 => "ftp", 22 => "ssh", 23 => "telnet", 25 => "smtp", 53 => "dns",
        80 => "http", 88 => "kerberos", 110 => "pop3", 111 => "rpcbind", 135 => "msrpc",
        139 => "netbios", 143 => "imap", 389 => "ldap", 443 => "https", 445 => "smb",
        465 => "smtps", 514 => "syslog", 587 => "submission", 636 => "ldaps", 873 => "rsync",
        993 => "imaps", 995 => "pop3s", 1433 => "mssql", 1521 => "oracle", 2049 => "nfs",
        2375 => "docker", 2376 => "docker-tls", 2379 | 2380 => "etcd", 3000 => "grafana/dev",
        3128 => "squid", 3306 => "mysql", 3389 => "rdp", 4369 => "epmd", 5000 => "registry/dev",
        5044 => "logstash", 5432 => "postgres", 5601 => "kibana", 5672 => "amqp",
        5900 => "vnc", 5985 | 5986 => "winrm", 6379 => "redis", 6443 => "k8s-api",
        8000 | 8008 | 8080 | 8081 | 8888 => "http-alt", 8006 => "proxmox", 8086 => "influxdb",
        8123 => "clickhouse-http", 8200 => "vault", 8443 => "https-alt", 8500 => "consul",
        9000 => "minio/pinot/clickhouse", 9042 => "cassandra", 9090 => "prometheus",
        9092 => "kafka", 9093 => "alertmanager", 9100 => "node-exporter", 9200 => "elasticsearch",
        9300 => "es-transport", 9418 => "git", 10250 => "kubelet", 11211 => "memcached",
        15672 => "rabbitmq-ui", 25565 => "minecraft", 27017 => "mongodb", 30000..=32767 => "k8s-nodeport",
        _ => "",
    }
}

const HTTPISH: [u16; 18] = [80, 3000, 5000, 5601, 8000, 8006, 8008, 8080, 8081, 8086, 8123, 8200, 8500, 8888, 9000, 9090, 9200, 15672];

/// What a quiet service gets poked with to make it say something.
fn active_probe(port: u16) -> &'static [u8] {
    match port {
        6379 => b"PING\r\n",
        11211 => b"version\r\n",
        _ => b"HEAD / HTTP/1.0\r\nHost: scan\r\nUser-Agent: SSHDeck\r\n\r\n",
    }
}

/// Turn the first bytes a service sent into one short readable line.
fn describe(b: &[u8]) -> Option<String> {
    if b.is_empty() {
        return None;
    }
    if b[0] == 0x15 || b[0] == 0x16 {
        return Some("TLS".into());
    }
    let text = String::from_utf8_lossy(b);
    if text.starts_with("HTTP/") {
        let status = text.lines().next().unwrap_or("").trim().to_string();
        let server = text.lines()
            .find(|l| l.to_ascii_lowercase().starts_with("server:"))
            .map(|l| l[7..].trim().to_string());
        return Some(match server { Some(s) if !s.is_empty() => format!("{status} · {s}"), _ => status });
    }
    if text.starts_with("+PONG") { return Some("redis (no auth)".into()); }
    if text.starts_with("-NOAUTH") { return Some("redis (auth required)".into()); }
    let line: String = text.lines().next().unwrap_or("")
        .chars().filter(|c| !c.is_control()).collect::<String>().trim().to_string();
    let printable = line.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').count();
    if line.len() < 3 || printable * 10 < line.chars().count() * 8 {
        return None;
    }
    Some(line.chars().take(120).collect())
}

/// Read what the service volunteers; if it waits for us, poke it once.
async fn grab<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, port: u16) -> Option<String> {
    let mut buf = [0u8; 1024];
    if !HTTPISH.contains(&port) && port != 6379 && port != 11211 {
        match timeout(Duration::from_millis(900), s.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => return describe(&buf[..n]),
            Ok(_) => return None,            // closed on us without a word
            Err(_) => {}                     // quiet — try asking
        }
    }
    s.write_all(active_probe(port)).await.ok()?;
    let n = timeout(Duration::from_millis(1500), s.read(&mut buf)).await.ok()?.ok()?;
    describe(&buf[..n])
}

/* ---------- probing ---------- */

pub(crate) enum Via {
    Local,
    Ssh(Arc<Handle<Client>>),
}

#[derive(PartialEq, Debug)]
pub(crate) enum Outcome {
    Open(Option<String>),
    Closed,
    Silent,
    /// the server refuses to make connections for us at all
    Forbidden,
    /// the SSH connection itself is gone — every later probe would "fail" too,
    /// so this must stop the scan instead of being counted as closed ports
    Lost,
}

pub(crate) async fn probe(via: &Via, addr: &str, port: u16, to: Duration, banner: bool) -> Outcome {
    match via {
        Via::Local => match timeout(to, TcpStream::connect((addr, port))).await {
            Ok(Ok(mut s)) => {
                let b = if banner { grab(&mut s, port).await } else { None };
                let _ = s.shutdown().await;
                Outcome::Open(b)
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Outcome::Closed,
            _ => Outcome::Silent,
        },
        Via::Ssh(h) => match timeout(to, h.channel_open_direct_tcpip(addr, port as u32, "127.0.0.1", 0)).await {
            Ok(Ok(ch)) => {
                let mut st = ch.into_stream();
                let b = if banner { grab(&mut st, port).await } else { None };
                let _ = st.shutdown().await;
                Outcome::Open(b)
            }
            Ok(Err(russh::Error::ChannelOpenFailure(russh::ChannelOpenFailure::AdministrativelyProhibited))) => Outcome::Forbidden,
            // sshd answers ConnectFailed quickly for a refused port (host alive);
            // an unreachable host takes longer than our timeout and lands below
            Ok(Err(russh::Error::ChannelOpenFailure(_))) => Outcome::Closed,
            Ok(Err(_)) => Outcome::Lost,
            Err(_) => Outcome::Silent,
        },
    }
}

#[derive(Default)]
struct Counts {
    done: AtomicU64,
    open: AtomicU64,
    closed: AtomicU64,
    silent: AtomicU64,
    up: AtomicU64,
}

/* ---------- commands ---------- */

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn scan_start(
    app: AppHandle,
    scans: State<'_, Scans>,
    id: u32,
    host_id: Option<i64>,
    targets: String,
    ports: String,
    timeout_ms: u64,
    concurrency: usize,
    discover: bool,
    banners: bool,
) -> Result<serde_json::Value, String> {
    let mut targets = parse_targets(&targets)?;
    let ports = parse_ports(&ports)?;
    let total = targets.len() as u64 * ports.len() as u64;
    if total > MAX_PROBES {
        return Err(format!(
            "{} targets × {} ports = {total} probes — too many. Narrow the range or the ports (limit {MAX_PROBES}).",
            targets.len(), ports.len()));
    }
    let via_ssh = host_id.is_some();
    let to = Duration::from_millis(timeout_ms.clamp(100, 10_000));
    let conc = concurrency.clamp(1, if via_ssh { 128 } else { 1000 });

    let (via, from) = match host_id {
        Some(hid) => {
            let spec = crate::build_spec(&app, hid)?;
            let label = spec.hostname.clone();
            // its own connection: hundreds of short channels must not crowd the
            // pooled one that SFTP and tunnels share
            let h = dedicated(&spec).await?;
            (Via::Ssh(Arc::new(h)), label)
        }
        None => {
            // resolve names once here, not once per probe
            for t in targets.iter_mut() {
                if t.addr.parse::<IpAddr>().is_err() {
                    let found = tokio::net::lookup_host((t.addr.as_str(), 0)).await
                        .map_err(|e| format!("cannot resolve {}: {e}", t.label))?
                        .map(|a| a.ip())
                        .min_by_key(|ip| !ip.is_ipv4());
                    let ip = found.ok_or(format!("cannot resolve {}", t.label))?;
                    t.addr = ip.to_string();
                }
            }
            (Via::Local, "this PC".to_string())
        }
    };

    let stop = Arc::new(AtomicBool::new(false));
    scans.0.lock().unwrap().insert(id, stop.clone());
    crate::log::info(&app, "scan", format!(
        "scan from {from}: {} target(s) × {} port(s), timeout {} ms, {} at once",
        targets.len(), ports.len(), to.as_millis(), conc));

    let n_targets = targets.len();
    let n_ports = ports.len();
    let ev = format!("scan-{id}");
    let app2 = app.clone();
    let emit: Emit = Arc::new(move |v| { let _ = app2.emit(&ev, v); });
    tauri::async_runtime::spawn(async move {
        let fin = run(emit, via, targets, ports, to, conc, discover, banners, stop).await;
        crate::log::info(&app, "scan", format!(
            "scan finished in {:.1}s: {} open, {} closed, {} no answer{}{}",
            fin["secs"].as_f64().unwrap_or(0.0), fin["open"], fin["closed"], fin["silent"],
            if fin["stopped"] == true { " (stopped)" } else { "" },
            if fin["forbidden"] == true { " — server refused port forwarding (AllowTcpForwarding off?)" }
            else if fin["lost"] == true { " — connection to the server was lost" } else { "" }));
        app.state::<Scans>().0.lock().unwrap().remove(&id);
    });
    Ok(json!({ "targets": n_targets, "ports": n_ports }))
}

#[tauri::command]
pub fn scan_stop(scans: State<Scans>, id: u32) {
    if let Some(f) = scans.0.lock().unwrap().get(&id) {
        f.store(true, Relaxed);
    }
}

pub(crate) type Emit = Arc<dyn Fn(serde_json::Value) + Send + Sync>;

/// The scan itself. Emits `progress` (throttled), `host`, `open` and finally
/// `done` through `emit`, and returns the `done` payload.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run(
    emit: Emit,
    via: Via,
    targets: Vec<Target>,
    ports: Vec<u16>,
    to: Duration,
    conc: usize,
    discover: bool,
    banners: bool,
    stop: Arc<AtomicBool>,
) -> serde_json::Value {
    let via = Arc::new(via);
    let counts = Arc::new(Counts::default());
    let started = Instant::now();
    let finished = Arc::new(AtomicBool::new(false));
    let forbidden = Arc::new(AtomicBool::new(false));
    let lost = Arc::new(AtomicBool::new(false));
    let phase = Arc::new(Mutex::new("scan"));
    let total = Arc::new(AtomicU64::new(targets.len() as u64 * ports.len() as u64));

    // one ticker turns counters into progress events (never one per probe)
    {
        let (emit, counts, finished, phase, total) =
            (emit.clone(), counts.clone(), finished.clone(), phase.clone(), total.clone());
        tokio::spawn(async move {
            while !finished.load(Relaxed) {
                emit(json!({
                    "kind": "progress", "phase": *phase.lock().unwrap(),
                    "done": counts.done.load(Relaxed), "total": total.load(Relaxed),
                    "open": counts.open.load(Relaxed), "closed": counts.closed.load(Relaxed),
                    "silent": counts.silent.load(Relaxed), "up": counts.up.load(Relaxed),
                }));
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        });
    }

    let sem = Arc::new(Semaphore::new(conc));

    // ---- phase 1: which hosts are up (only for more than one target)
    let mut live: Vec<Target> = targets.clone();
    if discover && targets.len() > 1 {
        *phase.lock().unwrap() = "discover";
        total.store(targets.len() as u64, Relaxed);
        // Windows takes ~2 s to report a refused port, so discovery waits longer
        let dto = if matches!(*via, Via::Local) { to.max(Duration::from_millis(2500)) } else { to };
        let up_list = Arc::new(Mutex::new(Vec::new()));
        let per_host = (DISCOVERY_PORTS.len() as u32).min(conc as u32);
        for (idx, t) in targets.iter().enumerate() {
            if stop.load(Relaxed) || forbidden.load(Relaxed) || lost.load(Relaxed) { break; }
            // a host costs one connection per discovery port, all at once
            let permit = sem.clone().acquire_many_owned(per_host).await.unwrap();
            let (via, t, counts, up_list, emit, forbidden, lost) =
                (via.clone(), t.clone(), counts.clone(), up_list.clone(), emit.clone(), forbidden.clone(), lost.clone());
            tokio::spawn(async move {
                let mut set = tokio::task::JoinSet::new();
                for p in DISCOVERY_PORTS {
                    let (via, addr) = (via.clone(), t.addr.clone());
                    set.spawn(async move { probe(&via, &addr, p, dto, false).await });
                }
                let mut alive = false;
                while let Some(r) = set.join_next().await {
                    match r {
                        Ok(Outcome::Open(_)) | Ok(Outcome::Closed) => { alive = true; break; }
                        Ok(Outcome::Forbidden) => { forbidden.store(true, Relaxed); break; }
                        Ok(Outcome::Lost) => { lost.store(true, Relaxed); break; }
                        _ => {}
                    }
                }
                set.abort_all();
                if alive {
                    counts.up.fetch_add(1, Relaxed);
                    up_list.lock().unwrap().push((idx, t.clone()));
                    emit(json!({ "kind": "host", "target": t.label, "addr": t.addr }));
                }
                counts.done.fetch_add(1, Relaxed);
                drop(permit);
            });
        }
        let _ = sem.acquire_many(conc as u32).await.map(|p| p.forget());
        sem.add_permits(conc);
        let mut l = up_list.lock().unwrap().clone();
        l.sort_by_key(|(i, _)| *i);
        live = l.into_iter().map(|(_, t)| t).collect();
        counts.done.store(0, Relaxed);
    } else {
        counts.up.store(targets.len() as u64, Relaxed);
    }

    // ---- phase 2: ports on every live host
    *phase.lock().unwrap() = "scan";
    total.store(live.len() as u64 * ports.len() as u64, Relaxed);
    'outer: for t in &live {
        for &port in &ports {
            if stop.load(Relaxed) || forbidden.load(Relaxed) || lost.load(Relaxed) { break 'outer; }
            let permit = sem.clone().acquire_owned().await.unwrap();
            let (via, t, counts, emit, forbidden, lost) =
                (via.clone(), t.clone(), counts.clone(), emit.clone(), forbidden.clone(), lost.clone());
            tokio::spawn(async move {
                let t0 = Instant::now();
                match probe(&via, &t.addr, port, to, banners).await {
                    Outcome::Open(b) => {
                        counts.open.fetch_add(1, Relaxed);
                        emit(json!({
                            "kind": "open", "target": t.label, "addr": t.addr, "port": port,
                            "service": service(port), "banner": b, "ms": t0.elapsed().as_millis() as u64,
                        }));
                    }
                    Outcome::Closed => { counts.closed.fetch_add(1, Relaxed); }
                    Outcome::Silent => { counts.silent.fetch_add(1, Relaxed); }
                    Outcome::Forbidden => { forbidden.store(true, Relaxed); }
                    Outcome::Lost => { lost.store(true, Relaxed); }
                }
                counts.done.fetch_add(1, Relaxed);
                drop(permit);
            });
        }
    }
    let _ = sem.acquire_many(conc as u32).await.map(|p| p.forget());

    finished.store(true, Relaxed);
    if let Via::Ssh(h) = &*via {
        let _ = h.disconnect(russh::Disconnect::ByApplication, "scan finished", "en").await;
    }
    let secs = started.elapsed().as_secs_f64();
    let stopped = stop.load(Relaxed);
    let forbid = forbidden.load(Relaxed);
    let (open, closed, silent, done) = (counts.open.load(Relaxed), counts.closed.load(Relaxed),
        counts.silent.load(Relaxed), counts.done.load(Relaxed));
    let fin = json!({
        "kind": "done", "done": done, "total": total.load(Relaxed), "open": open, "closed": closed,
        "silent": silent, "up": counts.up.load(Relaxed), "targets": targets.len(), "secs": secs,
        "stopped": stopped, "forbidden": forbid, "lost": lost.load(Relaxed),
    });
    emit(fin.clone());
    fin
}

/// Open http(s)://ip:port in the default browser. Only URLs the scanner builds
/// are accepted, and no shell is involved.
#[tauri::command]
pub fn open_url(url: String) -> Result<(), String> {
    let ok = (url.starts_with("http://") || url.starts_with("https://"))
        && url.len() < 300
        && url.chars().all(|c| c.is_ascii_alphanumeric() || ".:/-_[]".contains(c));
    if !ok {
        return Err("refusing to open that URL".into());
    }
    #[cfg(windows)]
    let r = std::process::Command::new("rundll32").args(["url.dll,FileProtocolHandler", &url]).spawn();
    #[cfg(not(windows))]
    let r = std::process::Command::new("xdg-open").arg(&url).spawn();
    r.map(|_| ()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn targets() {
        assert_eq!(parse_targets("10.0.0.0/30").unwrap().len(), 2);
        assert_eq!(parse_targets("10.0.0.0/24").unwrap().len(), 254);
        assert_eq!(parse_targets("10.0.0.7/32").unwrap()[0].addr, "10.0.0.7");
        assert_eq!(parse_targets("10.0.0.1-50").unwrap().len(), 50);
        assert_eq!(parse_targets("10.0.0.250-10.0.1.5").unwrap().len(), 12);
        assert_eq!(parse_targets("a.lan, 10.0.0.1\n10.0.0.1 b-c.osl.team").unwrap().len(), 3);
        assert!(parse_targets("10.0.0.0/8").is_err());
        assert!(parse_targets("10.0.0.9-3").is_err());
        assert!(parse_targets("rm -rf").is_err());
        assert!(parse_targets("$(x)").is_err());
        assert!(parse_targets("").is_err());
    }
    #[test]
    fn ports() {
        assert_eq!(parse_ports("22, 80,443").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("8000-8002,22,8001").unwrap(), vec![22, 8000, 8001, 8002]);
        assert_eq!(parse_ports("1-65535").unwrap().len(), 65535);
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("70000").is_err());
        assert!(parse_ports("90-80").is_err());
    }
    #[test]
    fn banners() {
        assert_eq!(describe(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n").unwrap(), "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13");
        assert_eq!(describe(b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n").unwrap(), "HTTP/1.1 200 OK · nginx/1.24.0");
        assert_eq!(describe(b"-NOAUTH Authentication required.\r\n").unwrap(), "redis (auth required)");
        assert_eq!(describe(&[0x15, 0x03, 0x03, 0, 2]).unwrap(), "TLS");
        assert!(describe(&[0, 1, 2, 3, 4, 5, 200, 201]).is_none());
    }
    #[test]
    fn urls() {
        assert!(open_url("http://10.0.0.1:8080/ && calc".into()).is_err());
        assert!(open_url("file:///c:/windows".into()).is_err());
    }
}
