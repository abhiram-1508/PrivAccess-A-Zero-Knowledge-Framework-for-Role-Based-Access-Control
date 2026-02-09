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

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct ZkProofPayload {
    proof: Option<serde_json::Value>,
    public_signals: Option<serde_json::Value>,
    demo: Option<bool>,
    user_hash: Option<String>,
    allowed_prefix: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
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
    std::sync::Mutex::new(Vec::new())
});

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

// --- Constants & Data ---

#[derive(Serialize, Clone, Debug)]
struct Door {
    name: String,
    #[allow(dead_code)]
    secret_qr: String,
    geohash_prefix: String,
    qr_url: Option<String>,
}

static DOORS: Lazy<HashMap<String, Door>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("tiered".to_string(), Door {
        name: "Tiered Classroom".to_string(),
        secret_qr: "tiered_secret".to_string(),
        geohash_prefix: "t1q7hk9vj".to_string(), // 9 chars ~= 5m
        qr_url: None,
    });
    m.insert("normal".to_string(), Door {
        name: "Normal Classroom".to_string(),
        secret_qr: "normal_secret".to_string(),
        geohash_prefix: "t1q7hk9uh".to_string(), 
        qr_url: None,
    });
    m.insert("lab".to_string(), Door {
        name: "Lab".to_string(),
        secret_qr: "lab_secret".to_string(),
        geohash_prefix: "t1q7hk9tk".to_string(),
        qr_url: None,
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
        .route("/history", get(api_get_history))
        .route("/api/room_qrs", get(api_room_qrs))
        .route("/api/check_assignment", get(api_check_assignment))
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
            return Json(json!({
                "assigned": true,
                "room_name": door.name,
                "room_id": room_id,
                "faculty_name": faculty_name
            }));
        }
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

    let final_host = if host.starts_with("localhost") || host.starts_with("127.0.0.1") {
        let ip = get_local_ip();
        format!("{}:3000", ip)
    } else {
        host.to_string()
    };

    let mut room_qrs = Vec::new();
    let is_student = q_params.role.as_deref() == Some("STUDENT");

    // If student, add a special LOOKUP QR first
    if is_student {
        let lookup_url = format!("http://{}/mobile/scan?role=STUDENT&action=lookup", final_host);
        if let Some(ref _s) = q_params.section { 
            // We don't append section here to keep it generic, or we could if we want automatic lookup
        }

        let code = QrCode::new(lookup_url.as_bytes()).unwrap();
        let width = code.width();
        let mut img = image::GrayImage::new(width as u32, width as u32);
        for (i, color) in code.to_colors().into_iter().enumerate() {
            let x = (i % width) as u32; let y = (i / width) as u32;
            let pixel = if color == qrcode::Color::Dark { image::Luma([0u8]) } else { image::Luma([255u8]) };
            img.put_pixel(x, y, pixel);
        }
        let upscaled = image::imageops::resize(&img, 300, 300, image::imageops::FilterType::Nearest);
        let mut buffer = std::io::Cursor::new(Vec::new());
        let dynamic_image = image::DynamicImage::ImageLuma8(upscaled);
        dynamic_image.write_to(&mut buffer, image::ImageFormat::Png).unwrap();
        let b64 = general_purpose::STANDARD.encode(buffer.into_inner());

        room_qrs.push(json!({
            "id": "lookup",
            "name": "LOOKUP MY ROOM",
            "qr_data": format!("data:image/png;base64,{}", b64)
        }));

        // STOP HERE FOR STUDENTS - They shouldn't see classroom QRs on the laptop
        return Json(room_qrs);
    }

    for (id, door) in DOORS.iter() {
        let mut mobile_url = format!("http://{}/mobile/scan?door={}", final_host, id);
        
        // Append identity if present
        if let Some(ref r) = q_params.role { mobile_url.push_str(&format!("&role={}", r)); }
        if let Some(ref s) = q_params.section { mobile_url.push_str(&format!("&section={}", s)); }
        if let Some(ref n) = q_params.faculty_name { mobile_url.push_str(&format!("&faculty_name={}", urlencoding::encode(n))); }
        if let Some(ref i) = q_params.faculty_id { mobile_url.push_str(&format!("&faculty_id={}", urlencoding::encode(i))); }
        if let Some(ref p) = q_params.pin { mobile_url.push_str(&format!("&pin={}", p)); }

        let code = QrCode::new(mobile_url.as_bytes()).unwrap();
        let width = code.width();
        let mut img = image::GrayImage::new(width as u32, width as u32);
        for (i, color) in code.to_colors().into_iter().enumerate() {
            let x = (i % width) as u32;
            let y = (i / width) as u32;
            let pixel = if color == qrcode::Color::Dark { image::Luma([0u8]) } else { image::Luma([255u8]) };
            img.put_pixel(x, y, pixel);
        }
        let upscaled = image::imageops::resize(&img, 300, 300, image::imageops::FilterType::Nearest);
        let mut buffer = std::io::Cursor::new(Vec::new());
        let dynamic_image = image::DynamicImage::ImageLuma8(upscaled);
        dynamic_image.write_to(&mut buffer, image::ImageFormat::Png).unwrap();
        let b64 = general_purpose::STANDARD.encode(buffer.into_inner());
        
        room_qrs.push(json!({
            "id": id,
            "name": door.name,
            "qr_data": format!("data:image/png;base64,{}", b64)
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
    door_id: String,
    role: String,
    proof: Proof,
    geohash: String,
    password: Option<String>,
    pin: Option<String>,
    section: Option<String>,
    faculty_name: Option<String>,
    faculty_id: Option<String>,
}

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
            let pin = payload.pin.as_deref().unwrap_or("");
            let fac_id = payload.faculty_id.as_deref().unwrap_or("");
            let section = payload.section.as_deref().unwrap_or("");

            let faculty_match = crate::rbac::FACULTIES.iter().find(|f| {
                f.id == fac_id && f.pin == pin
            });

            if faculty_match.is_none() {
                println!("TERMINAL: [DOOR {}] FACULTY LOGIN FAILED: ID='{}', PIN='{}'", door_id, fac_id, pin);
                log_denied(&payload, door, "Invalid Faculty Credentials");
                return (StatusCode::UNAUTHORIZED, Json(json!({"status": "failed", "message": "Invalid ID or PIN for Faculty"}))).into_response();
            }
            // Proximity Check (Relaxed to 6 chars for Demo - approx 1.2km)
            let req_prefix = if door.geohash_prefix.len() >= 6 { &door.geohash_prefix[0..6] } else { &door.geohash_prefix };
            if !payload.geohash.starts_with(req_prefix) {
                 log_denied(&payload, door, "Access Denied: Location Mismatch");
                 println!("TERMINAL: [DOOR {}] FACULTY DENIED DUE TO LOCATION. Expected prefix: {}, Got: {}", door_id, req_prefix, payload.geohash);
                 return (StatusCode::FORBIDDEN, Json(json!({"status": "failed", "message": "Access Denied: You must be near the room to unlock."}))).into_response();
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

            // Proximity Check (Relaxed to 6 chars for Demo)
            let req_prefix = if door.geohash_prefix.len() >= 6 { &door.geohash_prefix[0..6] } else { &door.geohash_prefix };
            if !payload.geohash.starts_with(req_prefix) {
                 log_denied(&payload, door, "Access Denied: Location Mismatch");
                 return (StatusCode::FORBIDDEN, Json(json!({"status": "failed", "message": "Access Denied: You must be near the room to unlock."}))).into_response();
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
}
