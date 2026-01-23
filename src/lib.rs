#![allow(unexpected_cfgs)]
pub mod bridge;
pub mod crypto;
pub mod database;
pub mod models;
pub mod network;
pub mod state;

use flutter_rust_bridge::frb;

#[frb(init)]
pub fn init_app() {
    // Default utilities - e.g. logging
    flutter_rust_bridge::setup_default_user_utils();
}
