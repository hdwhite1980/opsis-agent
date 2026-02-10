// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ipc;

use tauri::{
    menu::{MenuBuilder, MenuItemBuilder},
    tray::TrayIconBuilder,
    Manager,
};

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .on_window_event(|window, event| {
            // Hide window on close instead of quitting (minimize to tray)
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(|app| {
            // Build tray menu
            let show_item = MenuItemBuilder::with_id("show", "Show Control Panel").build(app)?;
            let view_logs_item =
                MenuItemBuilder::with_id("view_logs", "View Logs").build(app)?;
            let restart_item =
                MenuItemBuilder::with_id("restart_service", "Restart Service").build(app)?;
            let quit_item = MenuItemBuilder::with_id("quit", "Quit").build(app)?;

            let get_help_item =
                MenuItemBuilder::with_id("get_help", "Get Help").build(app)?;

            let tray_menu = MenuBuilder::new(app)
                .item(&show_item)
                .item(&get_help_item)
                .item(&view_logs_item)
                .separator()
                .item(&restart_item)
                .separator()
                .item(&quit_item)
                .build()?;

            let _tray = TrayIconBuilder::new()
                .menu(&tray_menu)
                .tooltip("OPSIS Agent - Autonomous IT Management")
                .on_menu_event(move |app_handle, event| {
                    let id = event.id().as_ref();
                    match id {
                        "show" => {
                            if let Some(window) = app_handle.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                        "get_help" => {
                            // Open self-service portal in default browser
                            let _ = open::that("http://localhost:19850");
                        }
                        "view_logs" => {
                            // Open the log file in the default text editor
                            if let Ok(exe) = std::env::current_exe() {
                                let log_path = exe
                                    .parent()
                                    .unwrap_or(exe.as_ref())
                                    .join("logs")
                                    .join("agent.log");
                                if log_path.exists() {
                                    let _ = open::that(&log_path);
                                }
                            }
                        }
                        "restart_service" => {
                            std::thread::spawn(|| {
                                let _ = std::process::Command::new("cmd")
                                    .args([
                                        "/c",
                                        "net stop \"OPSIS Agent Service\" && net start \"OPSIS Agent Service\"",
                                    ])
                                    .output();
                            });
                        }
                        "quit" => {
                            std::process::exit(0);
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::DoubleClick { .. } = event {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ipc::get_stats,
            ipc::get_tickets,
            ipc::clear_old_tickets,
            ipc::clear_all_tickets,
            ipc::submit_manual_ticket,
            ipc::update_settings,
            ipc::get_settings,
            ipc::get_health_data,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
