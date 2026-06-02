//! ESTATES desktop shell — wraps the Vite/React/SVG client in a native window.
//! The game logic runs in the web layer (the pure engine in-browser); this is a
//! thin WebView host. Keys never leave the client.

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running the ESTATES desktop application");
}
