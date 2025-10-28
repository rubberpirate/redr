use anyhow::Result;
use notify::{Config, Event, EventKind, RecursiveMode};
use reqwest::Client;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::path::PathBuf;
use notify::Watcher;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{sleep, Duration};
use chrono::Utc;
use hostname;

#[derive(Serialize)]
struct TelemetryEvent {
    host: String,
    event_type: String,
    data: serde_json::Value,
}

async fn send_event(client: &Client, url: &str, token: &str, ev: &TelemetryEvent) -> Result<()> {
    let full = format!("{}/telemetry", url.trim_end_matches('/'));
    let res = client
        .post(&full)
        .header("x-edr-token", token)
        .json(ev)
        .send()
        .await?;
    if !res.status().is_success() {
        eprintln!("server returned {}", res.status());
    }
    Ok(())
}

fn sha256_of_path(path: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    let data = fs::read(path)?;
    hasher.update(&data);
    Ok(hex::encode(hasher.finalize()))
}

fn quarantine_file(path: &Path) -> Result<()> {
    let qdir = Path::new("/var/lib/edr/quarantine");
    fs::create_dir_all(qdir)?;
    let filename = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".into());
    let dest = qdir.join(format!("{}-{}", Utc::now().timestamp(), filename));
    fs::rename(path, dest)?;
    Ok(())
}

fn kill_pid(pid: i32) -> Result<()> {
    // Use the system `kill` command for portability in this prototype
    let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status();
    Ok(())
}

fn block_ip(ip: &str) -> Result<()> {
    // best-effort using nftables; requires nft installed and privileges
    let rule = format!("add rule inet filter input ip saddr {} drop", ip);
    let _ = Command::new("nft").arg("-f").arg("-").stdin(std::process::Stdio::piped()).spawn().and_then(|mut child| {
        use std::io::Write;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(rule.as_bytes())?;
        }
        child.wait()?;
        Ok(())
    });
    Ok(())
}

fn block_port(port: u16) -> Result<()> {
    let rule = format!("add rule inet filter input tcp dport {} drop", port);
    let _ = Command::new("nft").arg("-f").arg("-").stdin(std::process::Stdio::piped()).spawn().and_then(|mut child| {
        use std::io::Write;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(rule.as_bytes())?;
        }
        child.wait()?;
        Ok(())
    });
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Config from environment
    let server = env::var("EDR_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
    let token = env::var("EDR_AGENT_TOKEN").unwrap_or_else(|_| "local-dev-token".into());
    let watch_paths = env::var("EDR_WATCH_PATHS").unwrap_or_else(|_| "/home,/tmp".into());

    let client = Client::builder().danger_accept_invalid_certs(true).build()?;
    let host = hostname::get()?.to_string_lossy().into_owned();

    // Policy store (fetched from server)
    let policy: Arc<RwLock<serde_json::Value>> = Arc::new(RwLock::new(serde_json::json!({
        "whitelist_commands": [],
        "whitelist_paths": [],
        "blacklist_hashes": []
    })));
    let held_pids: Arc<Mutex<HashSet<i32>>> = Arc::new(Mutex::new(HashSet::new()));

    // Spawn process monitor: read /proc directly for a simple, portable snapshot
    let client_p = client.clone();
    let server_p = server.clone();
    let token_p = token.clone();
    let host_p = host.clone();
    let policy_p = policy.clone();
    let held_pids_p = held_pids.clone();
    let held_pids_c = held_pids.clone();
    tokio::spawn(async move {
        loop {
            let mut procs = Vec::new();
            // detect new pids
            static SUSPICIOUS: &[&str] = &["nc", "netcat", "ncat", "telnet", "wget", "curl", "sh", "bash", "python", "perl"];
            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    if let Ok(fname) = entry.file_name().into_string() {
                        if fname.chars().all(|c| c.is_ascii_digit()) {
                            let pid = fname;
                            let base = format!("/proc/{}", pid);
                            let cmdline = fs::read_to_string(format!("{}/cmdline", base)).unwrap_or_default();
                            let comm = fs::read_to_string(format!("{}/comm", base)).unwrap_or_default();
                            procs.push(serde_json::json!({
                                "pid": pid,
                                "name": comm.trim().to_string(),
                                "cmd": cmdline.replace('\0', " "),
                            }));
                            // detect and hold suspicious execs (best-effort)
                            // we only attempt to SIGSTOP if running as root or have permissions
                            // use a lightweight heuristic (name or cmd contains suspicious string)
                            let lower_name = comm.to_lowercase();
                            let lower_cmd = cmdline.to_lowercase();
                            let mut is_susp = false;
                            for s in SUSPICIOUS.iter() {
                                if lower_name.contains(s) || lower_cmd.contains(s) {
                                    is_susp = true; break;
                                }
                            }
                            if is_susp {
                                // consult policy whitelist
                                let p = policy_p.read().await;
                                let whitelist = p.get("whitelist_commands").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                                let mut is_whitelisted = false;
                                for w in whitelist.iter() {
                                    if let Some(s) = w.as_str() {
                                        if lower_name.contains(&s.to_lowercase()) || lower_cmd.contains(&s.to_lowercase()) {
                                            is_whitelisted = true; break;
                                        }
                                    }
                                }
                                if !is_whitelisted {
                                    // best-effort: stop the process to hold it for approval
                                    if let Ok(status) = Command::new("kill").arg("-STOP").arg(pid.clone()).status() {
                                        if status.success() {
                                            let mut h = held_pids_p.lock().await;
                                            if let Ok(pid_i) = pid.parse::<i32>() { h.insert(pid_i); }
                                        }
                                    }
                                    // notify server about suspicious exec
                                    let ev = TelemetryEvent {
                                        host: host_p.clone(),
                                        event_type: "suspicious_exec".into(),
                                        data: serde_json::json!({"pid": pid, "name": comm.trim().to_string(), "cmd": cmdline.replace('\0', " ")}),
                                    };
                                    let _ = send_event(&client_p, &server_p, &token_p, &ev).await;
                                }
                            }
                        }
                    }
                }
            }
            let ev = TelemetryEvent {
                host: host_p.clone(),
                event_type: "process_snapshot".into(),
                data: serde_json::json!({"processes": procs}),
            };
            let _ = send_event(&client_p, &server_p, &token_p, &ev).await;
            sleep(Duration::from_secs(5)).await;
        }
    });

    // File watcher
    let client_f = client.clone();
    let server_f = server.clone();
    let token_f = token.clone();
    let host_f = host.clone();
    let policy_f = policy.clone();
    let paths: Vec<String> = watch_paths.split(',').map(|s| s.trim().to_string()).collect();

    tokio::spawn(async move {
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        // notify watcher runs in a blocking thread
        let mut watcher = match notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.try_send(event);
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("notify watcher init error: {:?}", e);
                return;
            }
        };
        watcher.configure(Config::default()).ok();
        for p in &paths {
            if Path::new(p).exists() {
                let _ = watcher.watch(Path::new(p), RecursiveMode::Recursive);
            }
        }

        while let Some(event) = rx.recv().await {
            // we keep it simple: when a Create or Modify shows up, hash and send
            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    for path in event.paths {
                        if path.is_file() {
                            match sha256_of_path(&path) {
                                Ok(hash) => {
                                    // check policy blacklist or suspicious paths and quarantine if found
                                    let mut quarantined = false;
                                    if let Some(p) = policy_f.read().await.clone().as_object().cloned() {
                                        if let Some(black) = p.get("blacklist_hashes").and_then(|v| v.as_array()) {
                                            for h in black {
                                                if let Some(s) = h.as_str() {
                                                    if s == hash {
                                                        // quarantine immediately
                                                        if let Err(e) = quarantine_file(&path) {
                                                            eprintln!("quarantine failed: {:?}", e);
                                                        } else {
                                                            quarantined = true;
                                                        }
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        if !quarantined {
                                            if let Some(wpaths) = p.get("whitelist_paths").and_then(|v| v.as_array()) {
                                                // if path is whitelisted, skip
                                                let mut wh = false;
                                                for wp in wpaths {
                                                    if let Some(s) = wp.as_str() {
                                                        if path.to_string_lossy().starts_with(s) { wh = true; break; }
                                                    }
                                                }
                                                if wh { /* do nothing */ }
                                            }
                                        }
                                    }

                                    let file_ev = TelemetryEvent {
                                        host: host_f.clone(),
                                        event_type: if quarantined { "file_quarantined" } else { "file_event" }.into(),
                                        data: serde_json::json!({
                                            "path": path.to_string_lossy(),
                                            "sha256": hash,
                                            "kind": format!("{:?}", event.kind),
                                        }),
                                    };
                                    let _ = send_event(&client_f, &server_f, &token_f, &file_ev).await;
                                }
                                Err(e) => eprintln!("hash error {:?}", e),
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    });

    // Policy poller: fetch updated whitelist/blacklist from server periodically
    let client_pol = client.clone();
    let server_pol = server.clone();
    let token_pol = token.clone();
    let host_pol = host.clone();
    let policy_pol = policy.clone();
    tokio::spawn(async move {
        loop {
            let url = format!("{}/policy?host={}", server_pol.trim_end_matches('/'), host_pol);
            match client_pol.get(&url).send().await {
                Ok(resp) => {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        let mut lock = policy_pol.write().await;
                        *lock = json;
                    }
                }
                Err(e) => eprintln!("policy poll error: {:?}", e),
            }
            sleep(Duration::from_secs(10)).await;
        }
    });

    // Network snapshot loop (simple parse /proc/net/tcp)
    let client_n = client.clone();
    let server_n = server.clone();
    let token_n = token.clone();
    let host_n = host.clone();
    tokio::spawn(async move {
        loop {
            if let Ok(tcp) = fs::read_to_string("/proc/net/tcp") {
                let lines: Vec<_> = tcp.lines().skip(1).map(|l| l.to_string()).collect();
                let ev = TelemetryEvent {
                    host: host_n.clone(),
                    event_type: "net_snapshot".into(),
                    data: serde_json::json!({"lines": lines}),
                };
                let _ = send_event(&client_n, &server_n, &token_n, &ev).await;
            }
            sleep(Duration::from_secs(5)).await;
        }
    });

    // Poll server for commands and execute them
    let client_c = client.clone();
    let server_c = server.clone();
    let token_c = token.clone();
    let host_c = host.clone();
    let held_pids_c2 = held_pids.clone();
    tokio::spawn(async move {
        loop {
            let url = format!("{}/commands?host={}", server_c.trim_end_matches('/'), host_c);
            match client_c.get(&url).send().await {
                Ok(resp) => {
                    if let Ok(cmds) = resp.json::<Vec<serde_json::Value>>().await {
                        for c in cmds {
                if let Some(action) = c.get("action").and_then(|v| v.as_str()) {
                    let id = c.get("id").and_then(|v| v.as_str()).unwrap_or("");
                                // Execute known actions
                                let mut result = serde_json::json!({"id": id, "status": "unknown"});
                                if action == "kill" {
                                    if let Some(pidv) = c.get("args").and_then(|a| a.get("pid")).and_then(|p| p.as_i64()) {
                                        let _ = kill_pid(pidv as i32);
                                        result = serde_json::json!({"id": id, "status": "killed", "pid": pidv});
                                    }
                                } else if action == "quarantine" {
                                    if let Some(path) = c.get("args").and_then(|a| a.get("path")).and_then(|p| p.as_str()) {
                                        let _ = quarantine_file(Path::new(path));
                                        result = serde_json::json!({"id": id, "status": "quarantined", "path": path});
                                    }
                                } else if action == "block_ip" {
                                    if let Some(ip) = c.get("args").and_then(|a| a.get("ip")).and_then(|p| p.as_str()) {
                                        let _ = block_ip(ip);
                                        result = serde_json::json!({"id": id, "status": "blocked", "ip": ip});
                                    }
                                } else if action == "block_port" {
                                    if let Some(portv) = c.get("args").and_then(|a| a.get("port")).and_then(|p| p.as_u64()) {
                                        let _ = block_port(portv as u16);
                                        result = serde_json::json!({"id": id, "status": "blocked_port", "port": portv});
                                    }
                                } else if action == "resume" {
                                    if let Some(pidv) = c.get("args").and_then(|a| a.get("pid")).and_then(|p| p.as_i64()) {
                                        // send SIGCONT and remove from held_pids
                                        if let Ok(status) = Command::new("kill").arg("-CONT").arg(pidv.to_string()).status() {
                                            if status.success() {
                                                let mut h = held_pids_c2.lock().await;
                                                h.remove(&(pidv as i32));
                                                result = serde_json::json!({"id": id, "status": "resumed", "pid": pidv});
                                            } else {
                                                result = serde_json::json!({"id": id, "status": "resume_failed", "pid": pidv});
                                            }
                                        }
                                    }
                                }
                                // send command result back as telemetry
                                let res_ev = TelemetryEvent { host: host_c.clone(), event_type: "command_result".into(), data: result };
                                let _ = send_event(&client_c, &server_c, &token_c, &res_ev).await;
                            }
                        }
                    }
                }
                Err(e) => eprintln!("command poll error: {:?}", e),
            }
            sleep(Duration::from_secs(5)).await;
        }
    });

    // Simple control loop to receive local commands (not implemented: would need server push)
    println!("edr-agent running; configured server={}", server);
    // keep the program alive
    loop {
        sleep(Duration::from_secs(60)).await;
    }
}
