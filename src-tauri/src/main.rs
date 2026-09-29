#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct DispatchManifest {
    dispatch_id: String,
    sender_id: String,
    receiver_id: String,
    kem_algorithm: String,
    symmetric_algorithm: String,
    watermark_proof: String,
    payload_sha256: String,
    status: String,
}

#[derive(Serialize, Deserialize)]
struct ForensicScanResult {
    detected: bool,
    leaker_id: String,
    dispatch_id: String,
    confidence_percent: f64,
    valid_tiles_voted: u32,
    total_tiles_scanned: u32,
}

// Command: Create offline dispatch
#[tauri::command]
fn create_offline_dispatch(dispatch_id: String, recipient: String, payload_sha: String) -> Result<String, String> {
    let manifest = DispatchManifest {
        dispatch_id: dispatch_id.clone(),
        sender_id: "agent-alice-sender".into(),
        receiver_id: recipient,
        kem_algorithm: "ML-KEM-768".into(),
        symmetric_algorithm: "AES-256-GCM".into(),
        watermark_proof: "PROVE-WM-TILED-64X64".into(),
        payload_sha256: payload_sha,
        status: "OFFLINE_READY_FOR_USB_TRANSFER".into(),
    };

    let json_str = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?;
    let path = format!("dispatches/{}.json", dispatch_id);
    let _ = fs::create_dir_all("dispatches");
    fs::write(&path, &json_str).map_err(|e| e.to_string())?;

    Ok(format!("Dispatch saved successfully to {}", path))
}

// Command: Query ledger integrity
#[tauri::command]
fn verify_ledger_integrity() -> Result<bool, String> {
    let ledger_path = Path::new("ledger_data/ledger_blocks.dat");
    if !ledger_path.exists() {
        return Ok(true);
    }
    let data = fs::read_to_string(ledger_path).map_err(|e| e.to_string())?;
    let lines: Vec<&str> = data.lines().filter(|l| !l.is_empty()).collect();
    
    // Check hash chaining
    let mut prev_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    for (idx, line) in lines.iter().enumerate() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 9 {
            return Err(format!("Malformed block at line {}", idx));
        }
        if parts[1] != prev_hash {
            return Err(format!("Hash chain broken at block #{}", idx));
        }
        prev_hash = parts[8];
    }

    Ok(true)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            create_offline_dispatch,
            verify_ledger_integrity
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
