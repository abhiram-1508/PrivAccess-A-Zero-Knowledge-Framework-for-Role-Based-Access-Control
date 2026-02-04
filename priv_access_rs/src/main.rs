use std::process::Command;
use std::fs;
use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Query, Json},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Router,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tera::{Tera, Context};
use tower_http::services::ServeDir;
use once_cell::sync::Lazy;
use qrcode::QrCode;
use base64::{Engine as _, engine::general_purpose};
use tokio::sync::broadcast;

#[derive(Deserialize)]
struct ZkProofPayload {
    proof: Option<serde_json::Value>,
    publicSignals: Option<serde_json::Value>,
    demo: Option<bool>,
    userHash: Option<String>,
    allowedPrefix: Option<String>,
}

async fn verify_zkp(Json(payload): Json<ZkProofPayload>) -> impl IntoResponse {
    // === DEMO MODE BYPASS ===
    // If ZKP artifacts are missing, we still want the demo to show the "Privacy-Preserving Geofence" logic.
    if let Some(true) = payload.demo {
        println!("DEBUG: Verifying in DEMO MODE (Simulation)...");
        let user_hash = payload.userHash.unwrap_or_default();
        let allowed_prefix = payload.allowedPrefix.unwrap_or_default();
        
        // Ensure at least 6 characters match (same as the ZK circuit)
        if user_hash.starts_with(&allowed_prefix) && allowed_prefix.len() >= 6 {
            println!("SUCCESS: Geofence check PASSED in Demo Mode.");
            return (StatusCode::OK, "Access granted (Demo Mode)").into_response();
        } else {
            return (StatusCode::FORBIDDEN, "Access denied: User is outside the geofence").into_response();
        }
    }

    // === REAL ZKP VERIFICATION ===
    let proof = match payload.proof {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, "Missing proof").into_response(),
    };
    let public_signals = match payload.publicSignals {
        Some(s) => s,
        None => return (StatusCode::BAD_REQUEST, "Missing public signals").into_response(),
    };

    let proof_path = "zkp_circom/tmp_proof.json";
    let public_path = "zkp_circom/tmp_public.json";
    let vkey_path = "zkp_circom/verification_key.json";

    if let Err(e) = fs::write(proof_path, proof.to_string()) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to write proof: {}", e)).into_response();
    }
    if let Err(e) = fs::write(public_path, public_signals.to_string()) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to write public signals: {}", e)).into_response();
    }

    // 2. Call Node.js verifier
    let status = Command::new("node")
        .arg("zkp_circom/verify_proof.js")
        .arg(proof_path)
        .arg(public_path)
        .arg(vkey_path)
        .status();

    let status = match status {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to execute Node.js verifier: {}", e)).into_response(),
    };

    let is_valid_signal = public_signals.as_array()
        .and_then(|arr| arr.get(0))
        .and_then(|val| val.as_str())
        .unwrap_or("0");

    if status.success() && is_valid_signal == "1" {
        (StatusCode::OK, "Access granted").into_response()
    } else {
        println!("Verification failed: status={:?}, isValid={}", status, is_valid_signal);
        (StatusCode::FORBIDDEN, "Access denied: Invalid Proof or Location").into_response()
    }
}

mod crypto;
mod rbac;
mod zkp;

use crate::crypto::{P, G, power_mod, get_random_secret};
use crate::rbac::{ROLES, get_role_secret};
use crate::zkp::{SchnorrVerifier, Proof};

// --- App State ---

struct AppState {
    tera: Tera,
}

// --- Constants & Data ---

#[derive(Clone, Serialize)]
struct Door {
    name: String,
    #[allow(dead_code)]
    secret_qr: String,
    geohash_prefix: String,
}

static DOORS: Lazy<HashMap<String, Door>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("101".to_string(), Door {
        name: "Computer Lab A".to_string(),
        secret_qr: "3f334a1714eb61d5ab08730948518608".to_string(),
        geohash_prefix: "t1q7hk".to_string(),
    });
    m
});

// Real-time door status signaling
static DOOR_STATUS_TX: Lazy<broadcast::Sender<(String, String)>> = Lazy::new(|| {
    let (tx, _) = broadcast::channel(100);
    tx
});

// --- Routes ---

#[tokio::main]
async fn main() {
    // Initialize Tera
    let tera = match Tera::new("templates/**/*.html") {
        Ok(t) => t,
        Err(e) => {
            println!("Parsing error(s): {}", e);
            ::std::process::exit(1);
        }
    };

    let state = Arc::new(AppState { tera });

    // Build Router
    let app = Router::new()
        .route("/", get(index))
        .route("/door/:door_id", get(door_display))
        .route("/door/:door_id/status", get(door_status_stream))
        .route("/s/:door_id", get(short_scan))
        .route("/api/notify_status", post(api_notify_status)) // New: Notify door of mobile status
        .route("/mobile/scan", get(mobile_scan))
        .route("/mobile/setup", get(mobile_setup))
        .route("/api/verify", post(api_verify))
        .route("/verify", post(verify_zkp))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    
    let lan_ip = get_local_ip();
    println!("\n{}", "=".repeat(50));
    println!("🚀 PRIVACCESS SYSTEM STARTED");
    println!("{}", "=".repeat(50));
    println!("🖥️  DOOR DISPLAY (Open this in your browser):");
    println!("   http://localhost:3000/door/101");
    println!("   http://{}:3000/door/101 (LAN)", lan_ip);
    println!("{}", "-".repeat(50));
    println!("📱 MOBILE SCAN SIMULATION (Optional):");
    println!("   http://localhost:3000/s/101");
    println!("{}\n", "=".repeat(50));

    axum::serve(listener, app).await.unwrap();
}

async fn index() -> Redirect {
    Redirect::to("/door/101")
}

fn get_local_ip() -> String {
    use std::net::UdpSocket;
    let fallback = "127.0.0.1".to_string();
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return fallback,
    };
    if socket.connect("8.8.8.8:80").is_err() {
        return fallback;
    }
    let ip = socket.local_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or(fallback);
    println!("DEBUG: Detected LAN IP for QR Code: {}", ip);
    ip
}

// === 1. Door Display ===

async fn door_display(
    axum::extract::Path(door_id): axum::extract::Path<String>,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    let door = match DOORS.get(&door_id) {
        Some(d) => d,
        None => return (StatusCode::NOT_FOUND, "Door Not Found").into_response(),
    };

    let host = req.headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:3000");

    let mobile_url = if host.starts_with("localhost") || host.starts_with("127.0.0.1") {
        let lan_ip = get_local_ip();
        format!("http://{}:3000/s/{}", lan_ip, door_id)
    } else {
        format!("http://{}/s/{}", host, door_id)
    };

    // GENERATE QR CODE SERVER-SIDE (Manual draw to avoid trait mismatches)
    let code = QrCode::new(mobile_url.as_bytes()).unwrap();
    let width = code.width();
    let mut img = image::GrayImage::new(width as u32, width as u32);
    
    for (i, color) in code.to_colors().into_iter().enumerate() {
        let x = (i % width) as u32;
        let y = (i / width) as u32;
        let pixel = if color == qrcode::Color::Dark {
            image::Luma([0u8])
        } else {
            image::Luma([255u8])
        };
        img.put_pixel(x, y, pixel);
    }

    // Upscale for better quality
    let upscaled = image::imageops::resize(&img, 400, 400, image::imageops::FilterType::Nearest);
    
    let mut buffer = std::io::Cursor::new(Vec::new());
    let dynamic_image = image::DynamicImage::ImageLuma8(upscaled);
    dynamic_image.write_to(&mut buffer, image::ImageFormat::Png).unwrap();
    let b64 = general_purpose::STANDARD.encode(buffer.into_inner());
    let qr_data_url = format!("data:image/png;base64,{}", b64);

    let mut context = Context::new();
    context.insert("door", door);
    context.insert("door_id", &door_id);
    context.insert("mobile_url", &mobile_url);
    context.insert("qr_data_url", &qr_data_url);

    println!("TERMINAL: [DOOR {}] Initialized. Waiting for connection...", door_id);

    match state.tera.render("door_display.html", &context) {
        Ok(html) => Html(html).into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Template Error: {}", err)).into_response(),
    }
}

// SSE handler for door display updates
async fn door_status_stream(
    ax_path: axum::extract::Path<String>,
) -> impl IntoResponse {
    use axum::response::sse::{Event, Sse};
    use futures::stream::StreamExt;
    use tokio_stream::wrappers::BroadcastStream;

    let door_id = ax_path.0;
    let rx = DOOR_STATUS_TX.subscribe();
    let stream = BroadcastStream::new(rx)
        .filter_map(move |msg| {
            let door_id = door_id.clone();
            async move {
                match msg {
                    Ok((target_id, status)) if target_id == door_id => {
                        Some(Ok::<Event, std::convert::Infallible>(Event::default().data(status)))
                    },
                    _ => None,
                }
            }
        });

    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

// === 2. Mobile App ===
async fn short_scan(
    axum::extract::Path(door_id): axum::extract::Path<String>
) -> Redirect {
    println!("TERMINAL: [DOOR {}] QR Scanned! Mobile connecting...", door_id);
    let _ = DOOR_STATUS_TX.send((door_id.clone(), "connected".to_string()));
    Redirect::to(&format!("/mobile/scan?door={}", door_id))
}

#[derive(Deserialize)]
struct StatusNotifyPayload {
    door_id: String,
    status: String,
}

async fn api_notify_status(Json(payload): Json<StatusNotifyPayload>) -> impl IntoResponse {
    println!("TERMINAL: [DOOR {}] Status Update: {}", payload.door_id, payload.status.to_uppercase());
    let _ = DOOR_STATUS_TX.send((payload.door_id, payload.status));
    StatusCode::OK
}

#[derive(Deserialize)]
struct ScanParams {
    door: Option<String>,
}

async fn mobile_scan(
    Query(params): Query<ScanParams>,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> impl IntoResponse {
    let mut context = Context::new();
    if let Some(d) = params.door {
        context.insert("door_id", &d);
    }

    match state.tera.render("mobile_app.html", &context) {
        Ok(html) => Html(html).into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Template Error: {}", err)).into_response(),
    }
}

#[derive(Deserialize)]
struct SetupParams {
    role: Option<String>,
}

async fn mobile_setup(Query(params): Query<SetupParams>) -> impl IntoResponse {
    let requested_role = params.role.unwrap_or_else(|| "STUDENT".to_string()).to_uppercase();
    
    let (secret, role_name) = match get_role_secret(&requested_role) {
        Some(s) => (s, requested_role),
        None => (get_random_secret(), "UNKNOWN".to_string()),
    };

    let public_key = power_mod(&G, &secret, &P);

    Json(json!({
        "secret": secret.to_string(),
        "public_key": public_key.to_string(),
        "role": role_name
    }))
}

// === 3. Verification ===
#[derive(Deserialize, Debug)]
struct VerifyPayload {
    #[allow(dead_code)]
    door_id: String,
    proof: Proof,
    geohash: String,
}

async fn api_verify(Json(payload): Json<VerifyPayload>) -> impl IntoResponse {
    println!("TERMINAL: [DOOR {}] RECEIVED ACCESS REQUEST", payload.door_id);
    println!("DEBUG: Received Payload: {:?}", payload);

    // 1. Check Door Existence
    let door = match DOORS.get(payload.door_id.trim()) {
        Some(d) => d,
        None => {
            println!("TERMINAL: [DOOR {}] ACCESS DENIED: Door Not Found", payload.door_id);
            return (StatusCode::NOT_FOUND, Json(json!({
                "status": "failed",
                "message": "Access Denied: Door Not Found"
            }))).into_response()
        },
    };

    // 2. Verify Geohash (Proximity Check)
    println!("TERMINAL: [DOOR {}] Verifying Proximity: Local={} | Required={}", 
        payload.door_id, payload.geohash, door.geohash_prefix);
        
    if !payload.geohash.starts_with(&door.geohash_prefix) {
        println!("TERMINAL: [DOOR {}] ACCESS DENIED: Outside Proximity", payload.door_id);
        return (StatusCode::FORBIDDEN, Json(json!({
            "status": "failed",
            "message": "Access Denied: User is outside the door proximity"
        }))).into_response();
    }

    // Extra check: Ensure the geohash inside the proof matches
    if payload.proof.geohash != payload.geohash {
        println!("TERMINAL: [DOOR {}] ACCESS DENIED: Geohash Mismatch/Tampering", payload.door_id);
        return (StatusCode::FORBIDDEN, Json(json!({
             "status": "failed",
             "message": "Access Denied: Geohash tampering detected"
         }))).into_response();
    }

    // 3. Verify Schnorr Proof (Identity + Location Binding)
    println!("TERMINAL: [DOOR {}] Initiating ZKP Identity Verification...", payload.door_id);
    if !SchnorrVerifier::verify_proof(&payload.proof) {
         println!("TERMINAL: [DOOR {}] ACCESS DENIED: Invalid ZKP", payload.door_id);
         return (StatusCode::FORBIDDEN, Json(json!({
             "status": "failed",
             "message": "Access Denied: Invalid Zero-Knowledge Proof"
         }))).into_response();
    }

    // 4. RBAC Logic
    let prover_pub_key = payload.proof.public_key.clone();
    let mut role_found = None;
    
    // Check against known roles
    for (role_name, secret) in ROLES.iter() {
        let pk = power_mod(&G, secret, &P).to_string();
        if pk == prover_pub_key {
            role_found = Some(role_name.clone());
            break;
        }
    }

    match role_found {
        Some(role) => {
            println!("TERMINAL: [DOOR {}] SUCCESS: Access Granted to {}", payload.door_id, role);
            let _ = DOOR_STATUS_TX.send((payload.door_id.clone(), "unlocked".to_string()));
            
            Json(json!({
                "status": "success",
                "message": format!("Access Granted to {}", role),
                "role": role
            })).into_response()
        },
        None => {
            println!("TERMINAL: [DOOR {}] ACCESS DENIED: Authenticated but Unauthorized Role", payload.door_id);
            (StatusCode::FORBIDDEN, Json(json!({
                "status": "failed",
                "message": "Access Denied: Unauthorized Identity"
            }))).into_response()
        }
    }
}
