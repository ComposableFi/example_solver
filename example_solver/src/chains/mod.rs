pub mod ethereum;
pub mod mantis;
pub mod solana;

use lazy_static::lazy_static;
use std::collections::HashMap;

use crate::{env, SignedPayload};
use ethers::prelude::*;
use ethers::signers::LocalWallet;
use ethers::utils::hash_message;
use ethers::utils::keccak256;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;
use std::str::FromStr;
use std::sync::Arc;
use strum_macros::EnumString;
use tokio::sync::RwLock;

lazy_static! {
    // <intent_id, PostIntentInfo>
    pub static ref INTENTS: Arc<RwLock<HashMap<String, PostIntentInfo>>> = {
        let m = HashMap::new();
        Arc::new(RwLock::new(m))
    };
}

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

pub static SOLVER_ADDRESSES: &[&str] = &[
    "0x0362110922F923B57b7EfF68eE7A51827b2dF4b4", // ethereum
    "6zYgJTTuHZZ3G7qNje7RbCSnNtVtGKsxN5YKopPP6cqL", // solana
];

lazy_static! {
    static ref TOKEN_INFO: HashMap<Token, TokenInfo> = {
        let mut m = HashMap::new();

        let mut usdt_addresses = HashMap::new();
        usdt_addresses.insert(
            Blockchain::Ethereum,
            "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        );
        usdt_addresses.insert(
            Blockchain::Solana,
            "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
        );
        m.insert(
            Token::USDT,
            TokenInfo {
                address: usdt_addresses,
                decimals: 6,
            },
        );

        m
    };
    pub static ref SOLVER_ID: String = env::var("SOLVER_ID").unwrap_or_else(|_| String::from(""));
    pub static ref SOLVER_PRIVATE_KEY: String =
        env::var("ETHEREUM_PKEY").unwrap_or_else(|_| String::from(""));
}

pub fn get_token_info(token: &str, blockchain: &str) -> Option<(&'static str, u32)> {
    let token_enum = Token::from_str(token).ok()?;
    let blockchain_enum = Blockchain::from_str(blockchain).ok()?;
    let info = TOKEN_INFO.get(&token_enum)?;
    let address = info.address.get(&blockchain_enum)?;
    Some((address, info.decimals))
}

pub async fn create_keccak256_signature<T: Serialize>(
    json_data: T,
    private_key: String,
) -> Result<SignedPayload<T>, Box<dyn Error>> {
    let json_str = serde_json::to_string(&json_data)?;
    let json_bytes = json_str.as_bytes();

    let hash = H256(keccak256(json_bytes));

    let wallet: LocalWallet = private_key.parse().unwrap();
    let eth_message_hash = hash_message(hash);

    let signature: Signature = wallet.sign_hash(H256::from(eth_message_hash)).unwrap();

    Ok(SignedPayload {
        payload: json_data,
        hash,
        signature,
    })
}
