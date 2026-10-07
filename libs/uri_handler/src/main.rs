//! Sparse MSIX identity launcher for RustDesk on Windows.
//!
//! This executable is the `Application Executable` of the
//! `RustDesk.WebIdentity` sparse package and is what Windows activates for the
//! `windows.appUriHandler` extension. It carries the package identity in its
//! embedded manifest so that `RustDesk.exe` does not have to: an executable
//! with a package identity cannot be started by the Service Control Manager as
//! a classic LocalSystem service ("Access is denied").
//!
//! Behaviour is intentionally identical to what `RustDesk.exe` did when it was
//! the handler itself: forward the activation arguments verbatim to
//! `RustDesk.exe` in the same directory and exit. RustDesk already understands
//! `rustdesk://` links and simply shows its main window for anything else.
#![cfg_attr(windows, windows_subsystem = "windows")]

use std::path::PathBuf;
use std::process::Command;

const APP_CANDIDATES: &[&str] = &["RustDesk.exe", "rustdesk.exe"];

fn app_path() -> Option<PathBuf> {
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    APP_CANDIDATES
        .iter()
        .map(|name| dir.join(name))
        .find(|p| p.is_file())
}

fn main() {
    let Some(app) = app_path() else {
        std::process::exit(2);
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let status = Command::new(&app)
        .args(&args)
        .current_dir(app.parent().unwrap_or_else(|| std::path::Path::new(".")))
        .spawn();
    if status.is_err() {
        std::process::exit(1);
    }
}
