mod commands;
mod config;
mod crypto;
mod error;
mod wireguard;
mod wg_nt;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::import_config,
            commands::connect,
            commands::disconnect,
            commands::delete_config,
            commands::tunnel_stats,
            commands::force_reconnect,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
