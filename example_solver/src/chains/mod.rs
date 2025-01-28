pub mod ethereum;
pub mod mantis;
pub mod solana;

use std::{
    collections::HashMap,
    error::Error,
    str::FromStr,
    sync::{Arc, LazyLock},
};

use ethers::{
    prelude::*,
    signers::LocalWallet,
    utils::{hash_message, keccak256},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum_macros::EnumString;
use tokio::sync::RwLock;
use tracing::instrument;

pub static INTENTS: LazyLock<Arc<RwLock<HashMap<String, PostIntentInfo>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(HashMap::new())));

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SwapTransferInput {
    pub token_in: String,
    pub amount_in: String,
    pub src_chain_user: String,
    pub timeout: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SwapTransferOutput {
    pub token_out: String,
    pub amount_out: String,
    pub dst_chain_user: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LendInput {
    // TO DO
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LendOutput {
    // TO DO
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BorrowInput {
    // TO DO
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BorrowOutput {
    // TO DO
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum OperationInput {
    SwapTransfer(SwapTransferInput),
    Lend(LendInput),
    Borrow(BorrowInput),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum OperationOutput {
    SwapTransfer(SwapTransferOutput),
    Lend(LendOutput),
    Borrow(BorrowOutput),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PostIntentInfo {
    pub function_name: String,
    pub src_chain: String,
    pub dst_chain: String,
    pub inputs: OperationInput,
    pub outputs: OperationOutput,
}

#[derive(Debug, PartialEq, Eq, Hash, EnumString, Serialize, Deserialize)]
#[strum(serialize_all = "lowercase")]
enum Blockchain {
    Ethereum,
    Solana,
}

#[derive(Debug, PartialEq, Eq, Hash, EnumString, Serialize, Deserialize)]
#[strum(serialize_all = "UPPERCASE")]
enum Token {
    USDT,
}

#[derive(Debug)]
struct TokenInfo {
    address: HashMap<Blockchain, &'static str>,
    decimals: u32,
}

static TOKEN_INFO: LazyLock<HashMap<Token, TokenInfo>> = LazyLock::new(|| {
    [(
        Token::USDT,
        TokenInfo {
            address: [
                (
                    Blockchain::Ethereum,
                    "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                ),
                (
                    Blockchain::Solana,
                    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
                ),
            ]
            .into_iter()
            .collect::<HashMap<Blockchain, &str>>(),
            decimals: 6,
        },
    )]
    .into_iter()
    .collect::<HashMap<Token, TokenInfo>>()
});

#[instrument(skip_all)]
pub fn get_token_info(token: &str, blockchain: &str) -> Option<(&'static str, u32)> {
    let token_enum = Token::from_str(token).ok()?;
    let blockchain_enum = Blockchain::from_str(blockchain).ok()?;
    let info = TOKEN_INFO.get(&token_enum)?;
    let address = info.address.get(&blockchain_enum)?;
    Some((address, info.decimals))
}

#[instrument(skip_all)]
pub async fn create_keccak256_signature(
    json_data: &mut Value,
    private_key: &str,
) -> Result<(), Box<dyn Error>> {
    let json_str = json_data.to_string();
    let json_bytes = json_str.as_bytes();

    let hash = keccak256(json_bytes);
    let hash_hex = hex::encode(hash);

    let wallet: LocalWallet = private_key.parse().unwrap();
    let eth_message_hash = hash_message(hash);

    let signature: Signature = wallet.sign_hash(H256::from(eth_message_hash)).unwrap();
    let signature_hex = signature.to_string();

    if let Some(msg) = json_data.get_mut("msg") {
        msg["hash"] = Value::String(hash_hex);
        msg["signature"] = Value::String(signature_hex);
    }

    Ok(())
}
