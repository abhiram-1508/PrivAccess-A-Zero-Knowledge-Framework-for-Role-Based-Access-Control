use std::process::Command;
use std::fs;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

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

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct ZkProofPayload {
    proof: Option<serde_json::Value>,
    public_signals: Option<serde_json::Value>,
    demo: Option<bool>,
    user_hash: Option<String>,
    allowed_prefix: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct AccessHistory {
    role: String,
    door_name: String,
    section: String,
    timestamp: String,
    status: String,
    faculty_name: Option<String>,
    faculty_id: Option<String>,
}

static ACCESS_LOGS: Lazy<std::sync::Mutex<Vec<AccessHistory>>> = Lazy::new(|| {
    let logs = load_history();
    std::sync::Mutex::new(logs)
});

fn load_history() -> Vec<AccessHistory> {
    if let Ok(content) = fs::read_to_string("access_history.json") {
        if let Ok(logs) = serde_json::from_str(&content) {
            return logs;
        }
    }
    Vec::new()
}

fn save_history(logs: &Vec<AccessHistory>) {
    if let Ok(content) = serde_json::to_string_pretty(logs) {
        let _ = fs::write("access_history.json", content);
    }
}

// Section to Room mapping: stores which section is assigned to which room and by which faculty
// Map: Section -> (RoomID, FacultyName)
static SECTION_ROOM_MAP: Lazy<std::sync::Mutex<HashMap<String, (String, String)>>> = Lazy::new(|| {
    std::sync::Mutex::new(HashMap::new())
});


async fn verify_zkp(Json(payload): Json<ZkProofPayload>) -> impl IntoResponse {
    // === DEMO MODE BYPASS ===
    // If ZKP artifacts are missing, we still want the demo to show the "Privacy-Preserving Geofence" logic.
    if let Some(true) = payload.demo {
        println!("DEBUG: Verifying in DEMO MODE (Simulation)...");
        let user_hash = payload.user_hash.unwrap_or_default();
        let allowed_prefix = payload.allowed_prefix.unwrap_or_default();
        
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
    let public_signals = match payload.public_signals {
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
use crate::rbac::get_role_secret;
use crate::zkp::{SchnorrVerifier, Proof};

// --- App State ---

struct AppState {
    tera: Tera,
}

static USED_NONCES: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| Mutex::new(HashSet::new()));

// --- Constants & Data ---

#[derive(Serialize, Clone, Debug)]
struct Door {
    name: String,
    #[allow(dead_code)]
    secret_qr: String,
    geohash_prefix: String,
    qr_url: Option<String>,
    floor: i32,
}

static DOORS: Lazy<HashMap<String, Door>> = Lazy::new(|| {
    let mut m = HashMap::new();
    let default_geo = "t1q7hk9vj".to_string(); // shared base location for demo
    
    // Floor 1
    m.insert("room101".to_string(), Door { name: "Room 101".to_string(), secret_qr: "s101".to_string(), geohash_prefix: default_geo.clone(), qr_url: None, floor: 1 });
    m.insert("tiered102".to_string(), Door { name: "Tiered 102".to_string(), secret_qr: "s102".to_string(), geohash_prefix: default_geo.clone(), qr_url: None, floor: 1 });
    m.insert("lab103".to_string(), Door { name: "Lab 103".to_string(), secret_qr: "s103".to_string(), geohash_prefix: default_geo.clone(), qr_url: None, floor: 1 });
    // Floor 2
    m.insert("room201".to_string(), Door { name: "Room 201".to_string(), secret_qr: "s201".to_string(), geohash_prefix: default_geo.clone(), qr_url: None, floor: 2 });
    m.insert("tiered202".to_string(), Door { name: "Tiered 202".to_string(), secret_qr: "s202".to_string(), geohash_prefix: default_geo.clone(), qr_url: None, floor: 2 });
    m.insert("lab203".to_string(), Door { name: "Lab 203".to_string(), secret_qr: "s203".to_string(), geohash_prefix: default_geo.clone(), qr_url: None, floor: 2 });
    // Floor 3
    m.insert("room301".to_string(), Door { name: "Room 301".to_string(), secret_qr: "s301".to_string(), geohash_prefix: default_geo.clone(), qr_url: None, floor: 3 });
    m.insert("tiered302".to_string(), Door { name: "Tiered 302".to_string(), secret_qr: "s302".to_string(), geohash_prefix: default_geo.clone(), qr_url: None, floor: 3 });
    m.insert("lab303".to_string(), Door { name: "Lab 303".to_string(), secret_qr: "s303".to_string(), geohash_prefix: default_geo.clone(), qr_url: None, floor: 3 });
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
        .route("/history", get(api_get_history))
        .route("/api/room_qrs", get(api_room_qrs))
        .route("/api/check_assignment", get(api_check_assignment))
        .route("/api/dynamic_qr/:door_id", get(api_dynamic_qr))
        .route("/api/dynamic_qrs_all", get(api_dynamic_qrs_all))
        .route("/door/:door_id", get(door_display))
        .route("/door/:door_id/status", get(door_status_stream))
        .route("/s/:door_id", get(short_scan))
        .route("/api/notify_status", post(api_notify_status)) 
        .route("/mobile/scan", get(mobile_scan))
        .route("/mobile/setup", get(mobile_setup))
        .route("/api/verify", post(api_verify))
        .route("/verify", post(verify_zkp))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state);


    let listener = match tokio::net::TcpListener::bind("0.0.0.0:3000").await {
        Ok(l) => l,
        Err(e) => {
            println!("\n❌ PORT CONFLICT ERROR: {}", e);
            println!("==================================================");
            println!("ERROR: Port 3000 is still being held by an old process.");
            println!("TO FIX THIS ON WINDOWS, RUN THESE COMMANDS:");
            println!("1. netstat -ano | findstr :3000");
            println!("2. taskkill /F /PID <THE_PID_FROM_STEP_1>");
            println!("==================================================\n");
            return;
        }
    };
    
    let lan_ip = get_local_ip();
    println!("\n{}", "=".repeat(50));
    println!("🚀 PRIVACCESS SYSTEM STARTED");
    println!("{}", "=".repeat(50));
    println!("🖥️  MAIN GATEWAY (Select Role):");
    println!("   http://localhost:3000/");
    println!("   http://{}:3000/ (LAN)", lan_ip);
    println!("{}", "-".repeat(50));
    println!("{}\n", "=".repeat(50));

    axum::serve(listener, app).await.unwrap();
}

async fn index(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> impl IntoResponse {
    let context = Context::new();
    match state.tera.render("index.html", &context) {
        Ok(html) => Html(html).into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Template Error: {}", err)).into_response(),
    }
}

async fn api_get_history() -> impl IntoResponse {
    let logs = ACCESS_LOGS.lock().unwrap();
    Json(json!(logs.clone()))
}

#[derive(Deserialize)]
struct CheckAssignmentParams {
    section: String,
}

async fn api_check_assignment(Query(params): Query<CheckAssignmentParams>) -> impl IntoResponse {
    let map = SECTION_ROOM_MAP.lock().unwrap();
    
    if let Some((room_id, faculty_name)) = map.get(&params.section) {
        if let Some(door) = DOORS.get(room_id) {
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            let history = AccessHistory {
                role: "STUDENT".to_string(),
                door_name: door.name.clone(),
                section: params.section.clone(),
                timestamp,
                status: "ASSIGNMENT FETCHED".to_string(),
                faculty_name: Some(faculty_name.clone()),
                faculty_id: None,
            };
            {
                let mut logs = ACCESS_LOGS.lock().unwrap();
                logs.push(history);
                save_history(&logs);
            }

            return Json(json!({
                "assigned": true,
                "room_name": door.name,
                "room_id": room_id,
                "faculty_name": faculty_name
            }));
        }
    }
    
    // Log "No Room Allotted" check
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let history = AccessHistory {
        role: "STUDENT".to_string(),
        door_name: "Room lookup".to_string(),
        section: params.section.clone(),
        timestamp,
        status: "DENIED: No room allotted".to_string(),
        faculty_name: None,
        faculty_id: None,
    };
    {
        let mut logs = ACCESS_LOGS.lock().unwrap();
        logs.push(history);
        save_history(&logs);
    }

    Json(json!({
        "assigned": false,
        "message": "No room is being alloted for ur section"
    }))
}


#[derive(Deserialize)]
struct QrParams {
    role: Option<String>,
    section: Option<String>,
    faculty_name: Option<String>,
    faculty_id: Option<String>,
    pin: Option<String>,
}

async fn api_room_qrs(
    Query(q_params): Query<QrParams>,
    req: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    let host = req.headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:3000");

    let mut room_qrs = Vec::new();
    let is_student = q_params.role.as_deref() == Some("STUDENT");

    // If student, add a special LOOKUP QR first
    if is_student {
        room_qrs.push(json!({
            "id": "lookup",
            "name": "LOOKUP MY ROOM",
            "type": "lookup"
        }));

        // STOP HERE FOR STUDENTS - They shouldn't see classroom QRs unconditionally
        return Json(room_qrs);
    }

    for (id, door) in DOORS.iter() {
        room_qrs.push(json!({
            "id": id,
            "name": door.name,
            "type": "door"
        }));
    }
    Json(room_qrs)
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

// === Dynamic QR Code API ===
#[derive(Serialize)]
struct DynamicQrRes {
    door_id: String,
    floor: i32,
    timestamp: u64,
    nonce: String,
    url: String,
}

async fn api_dynamic_qr(
    axum::extract::Path(door_id): axum::extract::Path<String>,
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

    let is_local = host.starts_with("localhost") || host.starts_with("127.0.0.1");
    let base_host = if is_local {
        format!("{}:3000", get_local_ip())
    } else {
        host.to_string()
    };

    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    
    use rand::Rng;
    let nonce: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    // URL scheme: http://HOST/s/door_id?ts=XXX&nonce=YYY&floor=Z
    let url = format!("http://{}/s/{}?ts={}&nonce={}&floor={}", base_host, door_id, timestamp, nonce, door.floor);

    Json(DynamicQrRes {
        door_id,
        floor: door.floor,
        timestamp,
        nonce,
        url,
    }).into_response()
}

async fn api_dynamic_qrs_all(
    req: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    let host = req.headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:3000");

    let is_local = host.starts_with("localhost") || host.starts_with("127.0.0.1");
    let base_host = if is_local {
        format!("{}:3000", get_local_ip())
    } else {
        host.to_string()
    };

    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    
    use rand::Rng;
    let mut responses = HashMap::new();

    for (id, door) in DOORS.iter() {
        let nonce: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();
        let url = format!("http://{}/mobile/scan?door={}&ts={}&nonce={}&floor={}", base_host, id, timestamp, nonce, door.floor);
        responses.insert(id.clone(), DynamicQrRes {
            door_id: id.clone(),
            floor: door.floor,
            timestamp,
            nonce,
            url,
        });
    }

    Json(responses).into_response()
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

    context.insert("faculties", crate::rbac::FACULTIES);
    context.insert("sections", crate::rbac::SECTIONS);

    match state.tera.render("mobile_app.html", &context) {
        Ok(html) => Html(html).into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Template Error: {}", err)).into_response(),
    }
}

#[derive(Deserialize)]
struct SetupParams {
    role: Option<String>,
    faculty_id: Option<String>,
    pin: Option<String>,
    password: Option<String>,
}

async fn mobile_setup(Query(params): Query<SetupParams>) -> impl IntoResponse {
    let requested_role = params.role.unwrap_or_else(|| "STUDENT".to_string()).to_uppercase();
    
    if requested_role == "FACULTY" {
        let fac_id = params.faculty_id.as_deref().unwrap_or("").trim();
        let pin = params.pin.as_deref().unwrap_or("").trim();
        let faculty_match = crate::rbac::FACULTIES.iter().find(|f| {
            f.id.eq_ignore_ascii_case(fac_id) && f.pin == pin
        });
        if faculty_match.is_none() {
            return (StatusCode::UNAUTHORIZED, Json(json!({"status": "failed", "message": "Invalid Faculty ID or PIN"}))).into_response();
        }
    } else if requested_role == "ADMIN" {
        let pass = params.password.as_deref().unwrap_or("").trim();
        if pass != crate::rbac::ADMIN_PASSWORD {
            return (StatusCode::UNAUTHORIZED, Json(json!({"status": "failed", "message": "Incorrect Admin Password"}))).into_response();
        }
    }

    let (secret, role_name) = match get_role_secret(&requested_role) {
        Some(s) => (s, requested_role),
        None => (get_random_secret(), "UNKNOWN".to_string()),
    };

    let public_key = power_mod(&G, &secret, &P);

    Json(json!({
        "secret": secret.to_string(),
        "public_key": public_key.to_string(),
        "role": role_name
    })).into_response()
}

// === 3. Verification ===
#[derive(Deserialize, Debug)]
struct VerifyPayload {
    door_id: String,
    role: String,
    proof: Proof,
    geohash: String,
    password: Option<String>,
    pin: Option<String>,
    section: Option<String>,
    faculty_name: Option<String>,
    faculty_id: Option<String>,
    gps_valid: Option<bool>,
    ip_city: Option<String>,
    ip_region: Option<String>,
    ip_country: Option<String>,
    nonce: Option<String>,
    qr_timestamp: Option<u64>,
    floor: Option<i32>,
}

const EXPECTED_COUNTRY: &str = "India";
const EXPECTED_REGION: &str = "Andhra Pradesh";

async fn api_verify(Json(payload): Json<VerifyPayload>) -> impl IntoResponse {
    let door_id = payload.door_id.trim();
    println!("TERMINAL: [DOOR {}] RECEIVED ACCESS REQUEST FROM {}", door_id, payload.role);

    // 1. Check Door Existence
    let door = match DOORS.get(door_id) {
        Some(d) => d,
        None => {
            return (StatusCode::NOT_FOUND, Json(json!({"status": "failed", "message": "Door Not Found"}))).into_response()
        },
    };

    // 1.5 Dynamic QR Check (Anti-Replay / Location enforcement)
    if payload.role != "ADMIN" {
        let ts = payload.qr_timestamp.unwrap_or(0);
        let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        if current_time > ts + 5 {
            log_denied(&payload, door, "QR Expired");
            return (StatusCode::FORBIDDEN, Json(json!({"status": "failed", "message": "Location Check Failed: QR Code Expired (Took more than 5s)."}))).into_response();
        }
        
        let nonce = payload.nonce.clone().unwrap_or_default();
        if nonce.is_empty() {
            log_denied(&payload, door, "Missing QR Nonce");
            return (StatusCode::FORBIDDEN, Json(json!({"status": "failed", "message": "Location Check Failed: Invalid QR format"}))).into_response();
        }
        
        {
            let mut nonces = USED_NONCES.lock().unwrap();
            if nonces.contains(&nonce) {
                log_denied(&payload, door, "QR Reused");
                return (StatusCode::FORBIDDEN, Json(json!({"status": "failed", "message": "Location Check Failed: QR Code already used"}))).into_response();
            }
            nonces.insert(nonce);
        }

        let sent_floor = payload.floor.unwrap_or(-1);
        if sent_floor != door.floor {
            log_denied(&payload, door, "Floor Mismatch");
            return (StatusCode::FORBIDDEN, Json(json!({"status": "failed", "message": "Location Check Failed: Wrong Floor"}))).into_response();
        }
    }

    // 2. Authentication Logic
    match payload.role.as_str() {
        "ADMIN" => {
            if payload.password.as_deref() != Some(crate::rbac::ADMIN_PASSWORD) {
                log_denied(&payload, door, "Incorrect Admin Password");
                return (StatusCode::UNAUTHORIZED, Json(json!({"status": "failed", "message": "Incorrect Admin Password"}))).into_response();
            }
            // Admin has remote access - Skip Proximity check
            println!("TERMINAL: [DOOR {}] ADMIN REMOTE ACCESS GRANTED", door_id);
        },
        "FACULTY" => {
            let pin = payload.pin.as_deref().unwrap_or("").trim();
            let fac_id = payload.faculty_id.as_deref().unwrap_or("").trim();
            let section = payload.section.as_deref().unwrap_or("");

            let faculty_match = crate::rbac::FACULTIES.iter().find(|f| {
                f.id.eq_ignore_ascii_case(fac_id) && f.pin == pin
            });

            if faculty_match.is_none() {
                println!("TERMINAL: [DOOR {}] FACULTY LOGIN FAILED: ID='{}', PIN='{}'", door_id, fac_id, pin);
                log_denied(&payload, door, "Invalid Faculty Credentials");
                return (StatusCode::UNAUTHORIZED, Json(json!({"status": "failed", "message": "Invalid ID or PIN for Faculty"}))).into_response();
            }
            // Location checks are satisfied via Dynamic QR proximity logically above
            // We only optionally check GPS for backup logging
            let is_gps_valid = payload.gps_valid.unwrap_or(false);
            if !is_gps_valid {
                println!("TERMINAL: [DOOR {}] Optional warning: Faculty skipped GPS lock, but dynamic QR passed.", door_id);
            }
            
            // Store section-to-room mapping
            if !section.is_empty() {
                let faculty_name = payload.faculty_name.clone().unwrap_or_else(|| fac_id.to_string());
                let mut map = SECTION_ROOM_MAP.lock().unwrap();
                map.insert(section.to_string(), (door_id.to_string(), faculty_name.clone()));
                println!("TERMINAL: [MAPPING] Section {} assigned to room {} by {}", section, door.name, faculty_name);
            }
        },
        "STUDENT" => {
            let section = payload.section.as_deref().unwrap_or("");
            if !crate::rbac::SECTIONS.contains(&section) {
                log_denied(&payload, door, "Invalid Section");
                return (StatusCode::BAD_REQUEST, Json(json!({"status": "failed", "message": "Invalid Section Selected"}))).into_response();
            }

            // SECTION RESTRICTION CHECK
            {
                let map = SECTION_ROOM_MAP.lock().unwrap();
                match map.get(section) {
                    Some((assigned_room, _)) if assigned_room == door_id => {
                        // Correct room - continue to proximity check
                    },
                    Some((assigned_room, faculty)) => {
                        let msg = format!("Access Denied: Your section is assigned to {} by {}", assigned_room, faculty);
                        log_denied(&payload, door, &msg);
                        return (StatusCode::FORBIDDEN, Json(json!({"status": "failed", "message": msg}))).into_response();
                    },
                    None => {
                        let msg = "No room is being alloted for ur section";
                        log_denied(&payload, door, msg);
                        return (StatusCode::FORBIDDEN, Json(json!({"status": "failed", "message": msg}))).into_response();
                    }
                }
            }

            // Location checks are satisfied via Dynamic QR proximity logically above
            let is_gps_valid = payload.gps_valid.unwrap_or(false);
            if !is_gps_valid {
                println!("TERMINAL: [DOOR {}] Optional warning: Student skipped GPS lock, but dynamic QR passed.", door_id);
            }
        },
        _ => return (StatusCode::BAD_REQUEST, Json(json!({"status": "failed", "message": "Invalid Role"}))).into_response(),
    }

    // 3. Verify Schnorr Proof (Identity Binding) - SKIP FOR ADMIN
    if payload.role != "ADMIN" {
        if !SchnorrVerifier::verify_proof(&payload.proof) {
             log_denied(&payload, door, "Invalid Zero-Knowledge Proof");
             return (StatusCode::FORBIDDEN, Json(json!({"status": "failed", "message": "Invalid Zero-Knowledge Proof"}))).into_response();
        }
    }

    // 4. Log Success
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let history = AccessHistory {
        role: payload.role.clone(),
        door_name: door.name.clone(),
        section: payload.section.unwrap_or_else(|| "N/A".to_string()),
        timestamp,
        status: "GRANTED".to_string(),
        faculty_name: payload.faculty_name.clone(),
        faculty_id: payload.faculty_id.clone(),
    };
    
    {
        let mut logs = ACCESS_LOGS.lock().unwrap();
        logs.push(history);
        save_history(&logs);
    }

    let _ = DOOR_STATUS_TX.send((door_id.to_string(), "unlocked".to_string()));
    
    Json(json!({
        "status": "success",
        "message": format!("Access Granted to {}", payload.role),
        "role": payload.role
    })).into_response()
}

fn log_denied(payload: &VerifyPayload, door: &Door, reason: &str) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let history = AccessHistory {
        role: payload.role.clone(),
        door_name: door.name.clone(),
        section: payload.section.clone().unwrap_or_else(|| "N/A".to_string()),
        timestamp,
        status: format!("DENIED: {}", reason),
        faculty_name: payload.faculty_name.clone(),
        faculty_id: payload.faculty_id.clone(),
    };
    let mut logs = ACCESS_LOGS.lock().unwrap();
    logs.push(history);
    save_history(&logs);
}
 