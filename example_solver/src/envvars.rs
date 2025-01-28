use anyhow::Result;
use std::env;
use tracing::instrument;

static SOLVER_ADDRESSES: &[&str] = &[
    "0x0362110922F923B57b7EfF68eE7A51827b2dF4b4", // ethereum
    "6zYgJTTuHZZ3G7qNje7RbCSnNtVtGKsxN5YKopPP6cqL", // solana
];

pub(crate) struct Envvars {
    pub(crate) solver_id: String,
    pub(crate) solver_addresses: &'static [&'static str],
    pub(crate) auctioneer_ws: String,
    pub(crate) comission: u32,
    pub(crate) ethereum_key: String,
    pub(crate) ethereum_rpc: String,
    pub(crate) solana_key: String,
    pub(crate) solana_rpc: String,
    pub(crate) mantis_rpc: String,
    // Reference: https://quote-api.jup.ag/v4/docs/static/index.html
    pub(crate) quote_api_url: String,
    // Reference: https://quote-api.jup.ag/docs/static/index.html
    pub(crate) price_api_url: String,
    pub(crate) is_jito_enabled: bool,
}

#[instrument(skip_all)]
pub fn get() -> Result<Envvars> {
    let solver_id = env::var("SOLVER_ID")?;
    let auctioneer_ws = env::var("COMPOSABLE_ENDPOINT")?;
    let comission = env::var("COMISSION")?.parse::<u32>()?;
    let ethereum_key = env::var("ETHEREUM_PKEY")?;
    let ethereum_rpc = env::var("ETHEREUM_RPC")?;
    let solana_key = env::var("SOLANA_KEYPAIR")?;
    let solana_rpc = env::var("SOLANA_RPC")?;
    let mantis_rpc = env::var("MANTIS_RPC")?;
    let quote_api_url = env::var("QUOTE_API_URL")?;
    let price_api_url = env::var("PRICE_API_URL")?;
    let is_jito_enabled = env::var("JITO")?.parse::<bool>().unwrap_or_default();

    Ok(Envvars {
        solver_id,
        solver_addresses: SOLVER_ADDRESSES,
        auctioneer_ws,
        comission,
        ethereum_key,
        ethereum_rpc,
        solana_key,
        solana_rpc,
        mantis_rpc,
        quote_api_url,
        price_api_url,
        is_jito_enabled,
    })
}
