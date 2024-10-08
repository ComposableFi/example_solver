pub mod jupiter;
pub mod paraswap;

// use ethers::providers::Middleware;
// use serde_json::Value;
use crate::chains::*;
use crate::PostIntentInfo;
use ethereum::ethereum_chain::ethereum_quote;
use lazy_static::lazy_static;
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use num_traits::Zero;
use solana::solana_chain::solana_quote;
use std::collections::HashMap;
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use anchor_lang::prelude::Pubkey;
use ethers::abi::Address;
use tokio::sync::RwLock;

lazy_static! {
    // <(src_chain, dst_chain), (src_chain_cost, dst_chain_cost)> // cost in USDT
    pub static ref FLAT_FEES: Arc<RwLock<HashMap<(String, String), (u32, u32)>>> = {
        let mut m = HashMap::new();
        m.insert(("ethereum".to_string(), "ethereum".to_string()), (0, 0));       // 0$ 3$
        m.insert(("solana".to_string(), "solana".to_string()), (0, 0));            // 0$ 0.2$
        m.insert(("ethereum".to_string(), "solana".to_string()), (0, 0));    // 1$ 0.1$
        m.insert(("solana".to_string(), "ethereum".to_string()), (0, 0));    // 0.1$ 2$
        Arc::new(RwLock::new(m))
    };

    // <mantis_token, solana_token>
    pub static ref MANTIS_TOKENS: Arc<RwLock<HashMap<String, String>>> = {
        let mut m = HashMap::new();
        m.insert("CpHLZarS6tobQTDQSKtnXCQWd1YcfSDL7UMgmjcVNjTb".to_string(), "7BgBvyjrZX1YKz4oh9mjb8ZScatkkwb8DzFx7LoiVkM3".to_string()); // SLERF (test, not the IBC-SLERF)
        m.insert("9fJw9rQdMi8QEJnBsybVKU7XTXBUTXVKpinDaYMsVSUS".to_string(), "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB".to_string()); // USDT (test, not the IBC-USDT)
        Arc::new(RwLock::new(m))
    };
}

pub async fn get_simulate_swap_intent(
    intent_info: &PostIntentInfo,
    mut src_chain: &str,
    mut dst_chain: &str,
    bridge_token: &String,
) -> String {
    // Extracting values from OperationInput
    let (mut token_in, amount_in, src_chain_user) = match &intent_info.inputs {
        OperationInput::SwapTransfer(input) => (
            input.token_in.clone(),
            input.amount_in.clone(),
            input.src_chain_user.clone(),
        ),
        OperationInput::Lend(_) => todo!(),
        OperationInput::Borrow(_) => todo!(),
    };

    let (dst_chain_user, mut token_out, _) = match &intent_info.outputs {
        OperationOutput::SwapTransfer(output) => (
            output.dst_chain_user.clone(),
            output.token_out.clone(),
            output.amount_out.clone(),
        ),
        OperationOutput::Lend(_) => todo!(),
        OperationOutput::Borrow(_) => todo!(),
    };

    if src_chain == "mantis" {
        let tokens = MANTIS_TOKENS.read().await;

        if let Some(token_mantis) = tokens.get(&token_in) {
            token_in = token_mantis.clone();
        } else {
            println!("Token {token_in} not supported, please include it on MANTIS_TOKENS");
        }

        src_chain = "solana";
    }

    if dst_chain == "mantis" {
        let tokens = MANTIS_TOKENS.read().await;

        if let Some(token_mantis) = tokens.get(&token_out) {
            token_out = token_mantis.clone();
        } else {
            println!("Token {token_out} not supported, please include it on MANTIS_TOKENS");
        }

        dst_chain = "solana";
    }

    let (bridge_token_address_src, _) = get_token_info(bridge_token, src_chain).unwrap();
    let mut amount_out_src_chain = BigInt::from_str(&amount_in).unwrap();

    if !bridge_token_address_src.eq_ignore_ascii_case(&token_in) {
        // simulate token_in -> USDT
        if src_chain == "ethereum" {
            let token_in = Address::from_str(&token_in).unwrap();
            let bridge_token_address_src = Address::from_str(&bridge_token_address_src).unwrap();
            let amount_in = amount_in.parse::<BigInt>().unwrap();
            amount_out_src_chain =
                ethereum_quote(token_in, amount_in, bridge_token_address_src).await;
        } else if src_chain == "solana" || src_chain == "mantis" {
            if src_chain == "mantis" {
                let tokens = MANTIS_TOKENS.read().await;

                match tokens.get(&token_in) {
                    Some(_token_in) => {
                        token_in = _token_in.clone();
                    }
                    None => {
                        amount_out_src_chain = BigInt::zero();
                        eprintln!("Update MANTIS_TOKENS global variable <mantis_token ({token_in}), solana_token>");
                    }
                }
            }

            if !amount_out_src_chain.is_zero() {
                let src_chain_user = Pubkey::from_str(&src_chain_user).unwrap();
                let token_in = Pubkey::from_str(&token_in).unwrap();
                let bridge_token_address_src = Pubkey::from_str(&bridge_token_address_src).unwrap();
                amount_out_src_chain = BigInt::from(
                    solana_quote(
                        src_chain_user,
                        token_in,
                        bridge_token_address_src,
                        amount_in.parse::<u64>().unwrap(),
                    )
                    .await.unwrap().out_amount,
                )
            }
        }
    }

    let (bridge_token_address_dst, _) = get_token_info(bridge_token, dst_chain).unwrap();

    // get flat fees
    let flat_fees;
    {
        let fees = FLAT_FEES.read().await;
        flat_fees = fees
            .get(&(src_chain.to_string(), dst_chain.to_string()))
            .unwrap()
            .clone();
        drop(fees);
    }

    // get comission
    let comission = env::var("COMISSION")
        .expect("COMISSION must be set")
        .parse::<u32>()
        .unwrap();

    if amount_out_src_chain < BigInt::from(flat_fees.0 + flat_fees.1 + comission) {
        return String::from("0");
    }

    // we substract the flat fees and the solver comission in USD
    let amount_in_dst_chain = amount_out_src_chain.clone()
        - (BigInt::from(flat_fees.0)
            + BigInt::from(flat_fees.1)
            + (amount_out_src_chain * BigInt::from(comission) / BigInt::from(100_000)));

    let mut final_amount_out = amount_in_dst_chain.to_string();

    if !amount_in_dst_chain.is_zero() && !bridge_token_address_dst.eq_ignore_ascii_case(&token_out)
    {
        // simulate USDT -> token_out
        if dst_chain == "ethereum" {
            let token_in = Address::from_str(&token_in).unwrap();
            let bridge_token_address_src = Address::from_str(&bridge_token_address_src).unwrap();
            let amount_in = amount_in.parse::<BigInt>().unwrap();
            final_amount_out =
                ethereum_quote(token_in, amount_in, bridge_token_address_src).await.to_string();
        } else if dst_chain == "solana" || dst_chain == "mantis" {
            if src_chain == "mantis" {
                let tokens = MANTIS_TOKENS.read().await;

                match tokens.get(&token_out) {
                    Some(_token_out) => {
                        token_out = _token_out.clone();
                    }
                    None => {
                        final_amount_out = "0".to_string();
                        eprintln!("Update MANTIS_TOKENS global variable <mantis_token ({token_in}), solana_token>");
                    }
                }
            }

            if final_amount_out != "0" {
                let dst_chain_user = Pubkey::from_str(&dst_chain_user).unwrap();
                let token_out = Pubkey::from_str(&token_out).unwrap();
                let bridge_token_address_dst = Pubkey::from_str(&bridge_token_address_dst).unwrap();
                final_amount_out = solana_quote(
                    dst_chain_user,
                    bridge_token_address_dst,
                    token_out,
                    amount_in_dst_chain.to_u64().unwrap(),
                )
                .await.unwrap().out_amount.to_string();
            }
        }
    }

    final_amount_out
}

// Calculation ethereum gas fees
// let url = "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd";
// let response: Value = reqwest::get(url).await.unwrap().json().await.unwrap();
// let eth_price = response["ethereum"]["usd"].as_f64().unwrap().round();
// let gas_price = provider.get_gas_price().await.unwrap().as_u128() as f64;
// let gas =  295000f64;
// let flat_fees = (eth_price * ((gas * gas_price) / 1e18)) as f64;

// let profit = (amount_out_src_chain.to_f64().unwrap() / 10f64.powi(bridge_token_dec_src as i32))
//     - (amount_in_dst_chain.to_f64().unwrap() / 10f64.powi(bridge_token_dec_dst as i32));
