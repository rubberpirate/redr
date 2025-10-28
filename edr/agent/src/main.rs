use anyhow::Result;
use notify::{Config, Event, EventKind, RecursiveMode};
use reqwest::Client;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::path::PathBuf;
use notify::Watcher;
use tokio::sync::Mutex;
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

#[tokio::main]
async fn main() -> Result<()> {
    // Config from environment
    let server = env::var("EDR_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
    let token = env::var("EDR_AGENT_TOKEN").unwrap_or_else(|_| "local-dev-token".into());
    let watch_paths = env::var("EDR_WATCH_PATHS").unwrap_or_else(|_| "/home,/tmp".into());

    let client = Client::builder().danger_accept_invalid_certs(true).build()?;
    let host = hostname::get()?.to_string_lossy().into_owned();

    // Spawn process monitor: read /proc directly for a simple, portable snapshot
    let client_p = client.clone();
    let server_p = server.clone();
    let token_p = token.clone();
    let host_p = host.clone();
    tokio::spawn(async move {
        loop {
            let mut procs = Vec::new();
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
                                    let file_ev = TelemetryEvent {
                                        host: host_f.clone(),
                                        event_type: "file_event".into(),
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
