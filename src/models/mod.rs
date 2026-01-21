use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct UserProfile {
    pub id: String,
    pub username: String,
    pub display_name: String,
}
