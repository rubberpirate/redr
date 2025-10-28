use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, Mutex};
use warp::Filter;
use futures_util::{StreamExt, SinkExt};

#[derive(Deserialize, Serialize, Debug, Clone)]
struct TelemetryEvent {
    host: String,
    event_type: String,
    data: serde_json::Value,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Command {
    id: String,
    target: String,
    action: String,
    args: serde_json::Value,
}

type CmdMap = HashMap<String, Vec<Command>>;

async fn append_log(ev: &TelemetryEvent) {
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open("edr_server.log") {
        let line = format!("{}\n", serde_json::to_string(ev).unwrap_or_else(|_| "{serializing_error}".into()));
        let _ = f.write_all(line.as_bytes());
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let token = std::env::var("EDR_SERVER_TOKEN").ok();

    // In-memory storage for recent events and pending commands
    let events: Arc<Mutex<Vec<TelemetryEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let cmds: Arc<Mutex<CmdMap>> = Arc::new(Mutex::new(HashMap::new()));

    // broadcast channel to push telemetry to websocket clients
    let (tx, _) = broadcast::channel::<TelemetryEvent>(1024);

    // POST /telemetry -> accept events from agents
    let events_clone = events.clone();
    let tx_clone = tx.clone();
    let telemetry = warp::post()
        .and(warp::path("telemetry"))
        .and(warp::body::json())
        .and_then(move |ev: TelemetryEvent| {
            let events = events_clone.clone();
            let tx = tx_clone.clone();
            async move {
                append_log(&ev).await;
                println!("recv {} from {}", ev.event_type, ev.host);
                {
                    let mut e = events.lock().await;
                    e.push(ev.clone());
                    let excess = e.len().saturating_sub(10000);
                    if excess > 0 {
                        e.drain(0..excess);
                    }
                }
                let _ = tx.send(ev);
                Ok::<_, Infallible>(warp::reply::with_status("ok", warp::http::StatusCode::OK))
            }
        });

    // GET /commands?host=... -> agent polling to fetch pending commands for host
    let cmds_clone = cmds.clone();
    let get_cmds = warp::get()
        .and(warp::path("commands"))
        .and(warp::query::<HashMap<String, String>>())
        .and_then(move |q: HashMap<String, String>| {
            let cmds = cmds_clone.clone();
            async move {
                let host = q.get("host").cloned().unwrap_or_default();
                let mut cm = cmds.lock().await;
                let res = cm.remove(&host).unwrap_or_default();
                Ok::<_, Infallible>(warp::reply::json(&res))
            }
        });

    // POST /command -> admin UI posts a command to a target host
    let cmds_clone2 = cmds.clone();
    let post_cmd = warp::post()
        .and(warp::path("command"))
        .and(warp::body::json())
        .and_then(move |c: Command| {
            let cmds = cmds_clone2.clone();
            async move {
                let mut cm = cmds.lock().await;
                cm.entry(c.target.clone()).or_insert_with(Vec::new).push(c.clone());
                Ok::<_, Infallible>(warp::reply::with_status("ok", warp::http::StatusCode::CREATED))
            }
        });

    // Websocket endpoint for live telemetry (/ws)
    let tx_clone2 = tx.clone();
    let ws_route = warp::path("ws")
        .and(warp::ws())
        .map(move |ws: warp::ws::Ws| {
            let tx = tx_clone2.clone();
            ws.on_upgrade(move |socket| async move {
                let mut rx = tx.subscribe();
                let (mut ws_tx, mut ws_rx) = socket.split();
                // spawn a task to forward broadcasts to websocket
                let send_task = tokio::spawn(async move {
                    while let Ok(ev) = rx.recv().await {
                        if let Ok(txt) = serde_json::to_string(&ev) {
                            if ws_tx.send(warp::ws::Message::text(txt)).await.is_err() {
                                break;
                            }
                        }
                    }
                });
                // drain client messages (keep connection alive)
                let recv_task = tokio::spawn(async move {
                    while let Some(Ok(_msg)) = ws_rx.next().await {
                        // ignore client messages for now
                    }
                });
                let _ = tokio::join!(send_task, recv_task);
            })
        });

    // Serve static UI - use path relative to server source or embedded fallback
    let ui_path = std::env::var("EDR_UI_PATH").unwrap_or_else(|_| "edr/server/ui/index.html".to_string());
    let ui = warp::get().and(warp::path::end()).and(warp::fs::file(ui_path));

    let routes = telemetry.or(get_cmds).or(post_cmd).or(ws_route).or(ui);

    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    println!("edr-server listening on {}", addr);
    warp::serve(routes).run(addr).await;

    Ok(())
}
