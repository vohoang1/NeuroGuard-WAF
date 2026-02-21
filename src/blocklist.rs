use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct BlocklistResponse {
    pub blocked_ips: Vec<String>,
}
