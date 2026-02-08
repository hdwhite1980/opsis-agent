use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Locate the data directory.
/// Checks: 1) next to exe  2) parent of exe  3) CWD
fn get_data_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        // Next to exe: <exe_dir>/data/
        let beside_exe = exe.parent().unwrap_or(exe.as_ref()).join("data");
        if beside_exe.exists() {
            return beside_exe;
        }
        // Parent of exe dir (for dev: src-tauri/target/release -> project root)
        if let Some(parent) = exe.parent().and_then(|p| p.parent()).and_then(|p| p.parent()).and_then(|p| p.parent()) {
            let project_data = parent.join("data");
            if project_data.exists() {
                return project_data;
            }
        }
    }
    // CWD fallback
    PathBuf::from("data")
}

fn read_json_file(filename: &str) -> Option<serde_json::Value> {
    let path = get_data_dir().join(filename);
    let content = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

// ---------- Stats ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    issues_detected: i64,
    active_tickets: i64,
    issues_escalated: i64,
    success_rate: i64,
}

#[tauri::command]
pub fn get_stats() -> Stats {
    let default = Stats {
        issues_detected: 0,
        active_tickets: 0,
        issues_escalated: 0,
        success_rate: 0,
    };

    let Some(data) = read_json_file("tickets.json") else {
        return default;
    };

    let tickets = match data.get("tickets").and_then(|t| t.as_array()) {
        Some(t) => t,
        None => return default,
    };

    let total = tickets.len() as i64;
    let active = tickets
        .iter()
        .filter(|t| {
            let status = t.get("status").and_then(|s| s.as_str()).unwrap_or("");
            let result = t.get("result").and_then(|s| s.as_str()).unwrap_or("");
            status != "resolved" && result != "success"
        })
        .count() as i64;
    let escalated = tickets
        .iter()
        .filter(|t| {
            t.get("escalated")
                .map(|v| v.as_i64().unwrap_or(0) == 1 || v.as_bool().unwrap_or(false))
                .unwrap_or(false)
        })
        .count() as i64;
    let success_count = tickets
        .iter()
        .filter(|t| t.get("result").and_then(|s| s.as_str()) == Some("success"))
        .count() as i64;
    let with_result = tickets
        .iter()
        .filter(|t| t.get("result").and_then(|s| s.as_str()).is_some())
        .count() as i64;

    let success_rate = if with_result > 0 {
        (success_count * 100) / with_result
    } else {
        0
    };

    Stats {
        issues_detected: total,
        active_tickets: active,
        issues_escalated: escalated,
        success_rate,
    }
}

// ---------- Tickets ----------

#[tauri::command]
pub fn get_tickets() -> Vec<serde_json::Value> {
    let Some(data) = read_json_file("tickets.json") else {
        return vec![];
    };

    match data.get("tickets").and_then(|t| t.as_array()) {
        Some(tickets) => {
            // Return latest 100
            let mut result: Vec<serde_json::Value> = tickets.clone();
            result.truncate(100);
            result
        }
        None => vec![],
    }
}

// ---------- Clear old tickets ----------

#[tauri::command]
pub fn clear_old_tickets() -> i64 {
    let path = get_data_dir().join("tickets.json");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return 0,
    };

    let mut data: serde_json::Value = match serde_json::from_str(&content) {
        Ok(d) => d,
        Err(_) => return 0,
    };

    let one_day_ago = chrono::Utc::now() - chrono::Duration::hours(24);
    let cutoff = one_day_ago.to_rfc3339();

    let original_count;
    let new_count;

    if let Some(tickets) = data.get_mut("tickets").and_then(|t| t.as_array_mut()) {
        original_count = tickets.len();
        tickets.retain(|t| {
            let ts = t
                .get("timestamp")
                .or_else(|| t.get("created_at"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            ts >= cutoff.as_str()
        });
        new_count = tickets.len();
    } else {
        return 0;
    }

    // Write back
    if let Ok(json) = serde_json::to_string_pretty(&data) {
        let _ = std::fs::write(&path, json);
    }

    (original_count - new_count) as i64
}

// ---------- Submit manual ticket ----------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualTicket {
    server_name: String,
    category: String,
    description: String,
    priority: String,
    submitted_at: String,
}

#[tauri::command]
pub fn submit_manual_ticket(ticket: ManualTicket) -> bool {
    let path = get_data_dir().join("tickets.json");
    let content = std::fs::read_to_string(&path).unwrap_or_else(|_| r#"{"tickets":[]}"#.to_string());

    let mut data: serde_json::Value =
        serde_json::from_str(&content).unwrap_or(serde_json::json!({"tickets": []}));

    let new_ticket = serde_json::json!({
        "ticket_id": format!("manual-{}", chrono::Utc::now().timestamp_millis()),
        "timestamp": ticket.submitted_at,
        "type": "manual-review",
        "issue_type": ticket.category,
        "description": ticket.description,
        "priority": ticket.priority,
        "status": "open",
        "source": "manual",
        "computer_name": ticket.server_name,
    });

    if let Some(tickets) = data.get_mut("tickets").and_then(|t| t.as_array_mut()) {
        tickets.insert(0, new_ticket);
    }

    match serde_json::to_string_pretty(&data) {
        Ok(json) => std::fs::write(&path, json).is_ok(),
        Err(_) => false,
    }
}

// ---------- Update settings ----------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsUpdate {
    server_url: Option<String>,
    monitor_interval: Option<i64>,
    alert_email: Option<String>,
    log_retention: Option<i64>,
    confidence_threshold: Option<i64>,
}

#[tauri::command]
pub fn update_settings(settings: SettingsUpdate) -> bool {
    let path = get_data_dir().join("agent.config.json");

    let mut config: serde_json::Value = if path.exists() {
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        serde_json::from_str(&content).unwrap_or(serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    let obj = config.as_object_mut().unwrap();
    if let Some(v) = settings.server_url {
        obj.insert("serverUrl".into(), serde_json::json!(v));
    }
    if let Some(v) = settings.monitor_interval {
        obj.insert("monitorInterval".into(), serde_json::json!(v));
    }
    if let Some(v) = settings.alert_email {
        obj.insert("alertEmail".into(), serde_json::json!(v));
    }
    if let Some(v) = settings.log_retention {
        obj.insert("logRetention".into(), serde_json::json!(v));
    }
    if let Some(v) = settings.confidence_threshold {
        obj.insert("confidenceThreshold".into(), serde_json::json!(v));
    }

    match serde_json::to_string_pretty(&config) {
        Ok(json) => std::fs::write(&path, json).is_ok(),
        Err(_) => false,
    }
}

// ---------- Load settings (for frontend) ----------

#[tauri::command]
pub fn get_settings() -> serde_json::Value {
    read_json_file("agent.config.json").unwrap_or(serde_json::json!({}))
}

// ---------- Health data ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthData {
    health_scores: serde_json::Value,
    correlations: serde_json::Value,
    patterns: Vec<serde_json::Value>,
    proactive_actions: Vec<serde_json::Value>,
}

#[tauri::command]
pub fn get_health_data() -> HealthData {
    // Build health scores from state-tracker.json
    let health_scores = build_health_scores();
    let patterns = build_patterns();
    let proactive_actions = build_proactive_actions();

    HealthData {
        health_scores,
        correlations: serde_json::json!({}),
        patterns,
        proactive_actions,
    }
}

fn build_health_scores() -> serde_json::Value {
    let Some(data) = read_json_file("state-tracker.json") else {
        return serde_json::json!({});
    };

    let Some(resources) = data.get("resources").and_then(|r| r.as_object()) else {
        return serde_json::json!({});
    };

    let mut scores = serde_json::Map::new();

    // Group resources by type and compute scores
    for (key, resource) in resources {
        let severity = resource
            .get("severityLevel")
            .and_then(|s| s.as_str())
            .unwrap_or("info");
        let state = resource
            .get("currentState")
            .and_then(|s| s.as_str())
            .unwrap_or("ok");

        let score = match severity {
            "critical" => 20,
            "error" => 40,
            "warning" => 65,
            _ => 100,
        };

        let trend = match state {
            "critical" | "error" => "degrading",
            "warning" => "stable",
            _ => "improving",
        };

        let name = key
            .split(':')
            .nth(1)
            .unwrap_or(key)
            .to_string();

        scores.insert(
            name,
            serde_json::json!({
                "score": score,
                "trend": trend,
            }),
        );
    }

    serde_json::Value::Object(scores)
}

fn build_patterns() -> Vec<serde_json::Value> {
    let Some(data) = read_json_file("pattern-detector.json") else {
        return vec![];
    };

    let Some(patterns) = data.get("patterns").and_then(|p| p.as_object()) else {
        return vec![];
    };

    patterns
        .iter()
        .take(20)
        .map(|(key, val)| {
            serde_json::json!({
                "patternId": key,
                "signalId": key,
                "occurrenceCount": val.get("occurrenceCount").and_then(|v| v.as_i64()).unwrap_or(0),
                "trend": val.get("trend").and_then(|v| v.as_str()).unwrap_or("stable"),
                "frequency": val.get("frequency").and_then(|v| v.as_f64()).unwrap_or(0.0),
                "urgency": val.get("urgency").and_then(|v| v.as_str()).unwrap_or("low"),
                "recommendation": val.get("recommendation").and_then(|v| v.as_str()).unwrap_or(""),
            })
        })
        .collect()
}

fn build_proactive_actions() -> Vec<serde_json::Value> {
    let Some(data) = read_json_file("pending-actions.json") else {
        return vec![];
    };

    let Some(actions) = data.get("pending_actions").and_then(|a| a.as_array()) else {
        return vec![];
    };

    actions
        .iter()
        .take(10)
        .map(|a| {
            let severity = a
                .get("signature")
                .and_then(|s| s.get("severity"))
                .and_then(|s| s.as_str())
                .unwrap_or("low");
            serde_json::json!({
                "title": a.get("signature_id").and_then(|v| v.as_str()).unwrap_or("Action"),
                "urgency": severity,
                "reasoning": a.get("server_message").and_then(|v| v.as_str()).unwrap_or(""),
            })
        })
        .collect()
}
