// deep-probe — DEEP NETWORK's Rust latency prober.
//
// Reads targets from stdin (one per line):
//     <ip> <port> [sni] [rounds]
// Writes one result line per target to stdout:
//     <ip> <ok:1|0> <tcp_ms> <tls_ms> <stat:hello|reset|alert|timeout|none>
//
// Pure std: multi-threaded TCP connect timing + a hand-crafted TLS ClientHello
// (with SNI) to classify how each edge reacts — ServerHello vs RST vs timeout.
// Static single binary, no DNS, no external crates.

use std::env;
use std::io::{BufRead, BufWriter, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
struct Target {
    ip: String,
    port: u16,
    sni: String,
    rounds: u32,
}

#[derive(Clone)]
struct Outcome {
    ok: bool,
    tcp_ms: f64,
    tls_ms: f64,
    stat: &'static str,
}

fn client_hello(sni: &[u8]) -> Vec<u8> {
    // server_name extension
    let mut sni_body: Vec<u8> = Vec::with_capacity(sni.len() + 7);
    // server_name_list: 2-byte list length, then entry = type(1) + length(2) + hostname
    let list_len: u16 = 3 + sni.len() as u16;
    sni_body.extend_from_slice(&list_len.to_be_bytes());
    sni_body.push(0x00); // type host_name
    sni_body.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    sni_body.extend_from_slice(sni);
    let mut ext: Vec<u8> = Vec::new();
    ext.extend_from_slice(&[0x00, 0x00]); // extension type: server_name
    ext.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni_body);
    // supported_groups: x25519 + secp256r1 + secp384r1
    ext.extend_from_slice(&[0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]);
    // ec_point_formats: uncompressed
    ext.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
    // signature_algorithms: rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256, rsa_pkcs1_sha256
    let sigalgs: [u8; 6] = [0x08, 0x04, 0x04, 0x03, 0x04, 0x01];
    let mut sa: Vec<u8> = Vec::new();
    sa.extend_from_slice(&(sigalgs.len() as u16).to_be_bytes());
    sa.extend_from_slice(&sigalgs);
    ext.extend_from_slice(&[0x00, 0x0d]);
    let sa_ext_len = 2 + sigalgs.len(); // inner length field + payload
    ext.extend_from_slice(&(sa_ext_len as u16).to_be_bytes());
    ext.extend_from_slice(&sa);
    // (no supported_versions: a pure TLS 1.2 hello needs no key_share)
    // session_ticket (empty)
    ext.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]);
    // renegotiation_info (empty) — required by many servers
    ext.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);

    let mut body: Vec<u8> = Vec::with_capacity(80 + ext.len());
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    // 32 random bytes
    let r = nanos().to_le_bytes();
    for i in 0..32 {
        body.push(r[i % 8].wrapping_add(i as u8).wrapping_mul(31).wrapping_add(0x41));
    }
    body.push(0x00); // session_id length 0
    // cipher suites: TLS1.3 + TLS1.2 ECDHE set (16 suites = 32 bytes)
    let suites: [u8; 26] = [
        0xc0, 0x2f, 0xc0, 0x2b, 0xc0, 0x30, 0xc0, 0x2c, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0xaf, 0xc0, 0xad,
        0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x9c,
    ];
    body.extend_from_slice(&(suites.len() as u16).to_be_bytes());
    body.extend_from_slice(&suites);
    body.extend_from_slice(&[0x01, 0x00]); // compression methods
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut hs: Vec<u8> = Vec::with_capacity(body.len() + 4);
    hs.push(0x01); // handshake type: ClientHello
    let l = body.len();
    hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    hs.extend_from_slice(&body);

    let mut rec: Vec<u8> = Vec::with_capacity(hs.len() + 5);
    rec.push(0x16); // record type: handshake
    rec.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn probe_one(t: &Target, timeout: Duration, hello_cache: &[u8]) -> Outcome {
    let addr: SocketAddr = match (t.ip.as_str(), t.port).to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => {
                return Outcome { ok: false, tcp_ms: 0.0, tls_ms: 0.0, stat: "none" };
            }
        },
        Err(_) => {
            return Outcome { ok: false, tcp_ms: 0.0, tls_ms: 0.0, stat: "none" };
        }
    };

    let rounds = t.rounds.max(1).min(3);
    let mut best_tcp = f64::MAX;
    for _ in 0..rounds {
        let t0 = Instant::now();
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(_) => {
                let ms = t0.elapsed().as_secs_f64() * 1000.0;
                if ms < best_tcp {
                    best_tcp = ms;
                }
            }
            Err(_) => return Outcome { ok: false, tcp_ms: 0.0, tls_ms: 0.0, stat: "none" },
        }
    }

    // TLS ClientHello classification (one shot on a fresh connection)
    let mut tls_ms = 0.0;
    let stat: &'static str;
    let t0 = Instant::now();
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(mut sock) => {
            let _ = sock.set_nodelay(true);
            let _ = sock.set_read_timeout(Some(timeout));
            let _ = sock.set_write_timeout(Some(timeout));
            if sock.write_all(hello_cache).is_err() {
                stat = "reset";
            } else {
                let mut head = [0u8; 5];
                match sock.read(&mut head) {
                    Ok(n) if n > 0 => {
                        tls_ms = t0.elapsed().as_secs_f64() * 1000.0;
                        if head[0] == 0x16 {
                            stat = "hello";
                        } else if head[0] == 0x15 {
                            stat = "alert";
                        } else {
                            stat = "reset";
                        }
                    }
                    Ok(_) => {
                        tls_ms = t0.elapsed().as_secs_f64() * 1000.0;
                        stat = "timeout";
                    }
                    Err(_) => {
                        tls_ms = t0.elapsed().as_secs_f64() * 1000.0;
                        stat = "reset";
                    }
                }
            }
        }
        Err(_) => {
            stat = "none";
        }
    }

    Outcome { ok: true, tcp_ms: best_tcp, tls_ms, stat }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut timeout_ms: u64 = 2000;
    if let Some(a) = args.get(1) {
        if let Ok(v) = a.parse::<u64>() {
            timeout_ms = v.clamp(200, 10_000);
        }
    }
    let timeout = Duration::from_millis(timeout_ms);

    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    let mut targets: Vec<Target> = Vec::new();
    while let Some(Ok(line)) = lines.next() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let ip = parts[0].to_string();
        let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);
        let sni = parts.get(2).unwrap_or(&"").to_string();
        let rounds: u32 = parts.get(3).and_then(|p| p.parse().ok()).unwrap_or(1);
        targets.push(Target { ip, port, sni, rounds });
    }
    if targets.is_empty() {
        return;
    }

    let targets = Arc::new(targets);
    let workers = usize::min(64, targets.len());
    let queue = Arc::new(Mutex::new(0usize));
    let results = Arc::new(Mutex::new(vec![Outcome { ok: false, tcp_ms: 0.0, tls_ms: 0.0, stat: "none" }; targets.len()]));

    let hello = client_hello(b"probe.invalid"); // default; per-target below
    let _ = hello;

    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let targets = Arc::clone(&targets);
        let queue = Arc::clone(&queue);
        let results = Arc::clone(&results);
        handles.push(std::thread::spawn(move || {
            loop {
                let i = {
                    let mut q = queue.lock().unwrap();
                    let i = *q;
                    *q += 1;
                    i
                };
                if i >= targets.len() {
                    break;
                }
                let t = &targets[i];
                let hello = if t.sni.is_empty() {
                    Vec::new()
                } else {
                    client_hello(t.sni.as_bytes())
                };
                let out = if hello.is_empty() {
                    probe_tcp_only(t, timeout)
                } else {
                    probe_one(t, timeout, &hello)
                };
                results.lock().unwrap()[i] = out;
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }

    let stdout = std::io::stdout();
    let mut w = BufWriter::new(stdout.lock());
    let results = results.lock().unwrap();
    for (i, r) in results.iter().enumerate() {
        let _ = writeln!(
            w,
            "{} {} {:.1} {:.1} {}",
            targets[i].ip,
            if r.ok { 1 } else { 0 },
            r.tcp_ms,
            r.tls_ms,
            r.stat
        );
    }
}

fn probe_tcp_only(t: &Target, timeout: Duration) -> Outcome {
    let addr: SocketAddr = match (t.ip.as_str(), t.port).to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => return Outcome { ok: false, tcp_ms: 0.0, tls_ms: 0.0, stat: "none" },
        },
        Err(_) => return Outcome { ok: false, tcp_ms: 0.0, tls_ms: 0.0, stat: "none" },
    };
    let rounds = t.rounds.max(1).min(3);
    let mut best = f64::MAX;
    for _ in 0..rounds {
        let t0 = Instant::now();
        if TcpStream::connect_timeout(&addr, timeout).is_err() {
            return Outcome { ok: false, tcp_ms: 0.0, tls_ms: 0.0, stat: "none" };
        }
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        if ms < best {
            best = ms;
        }
    }
    Outcome { ok: true, tcp_ms: best, tls_ms: 0.0, stat: "none" }
}
