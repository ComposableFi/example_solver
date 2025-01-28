pub mod jupiter;
pub mod paraswap;

use crate::{chains::*, Context, PostIntentInfo};
use ethereum::ethereum_simulate_swap;
use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};
use solana::solana_simulate_swap;
use solana_sdk::system_program;
use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, LazyLock},
    thread::sleep,
};
use tokio::sync::RwLock;
use tracing::instrument;

pub static FLAT_FEES: LazyLock<Arc<RwLock<HashMap<(&str, &str), (u32, u32)>>>> =
    LazyLock::new(|| {
        Arc::new(RwLock::new(
            [
                (("ethereum", "ethereum"), (0, 0)),
                (("solana", "solana"), (0, 0)),
                (("ethereum", "solana"), (0, 0)),
                (("solana", "ethereum"), (0, 0)),
            ]
            .into_iter()
            .collect::<HashMap<(&str, &str), (u32, u32)>>(),
        ))
    });

pub static MANTIS_TOKENS: LazyLock<Arc<RwLock<HashMap<&str, &str>>>> = LazyLock::new(|| {
    Arc::new(RwLock::new(
        [
            (
                "CpHLZarS6tobQTDQSKtnXCQWd1YcfSDL7UMgmjcVNjTb",
                "7BgBvyjrZX1YKz4oh9mjb8ZScatkkwb8DzFx7LoiVkM3",
            ),
            (
                "9fJw9rQdMi8QEJnBsybVKU7XTXBUTXVKpinDaYMsVSUS",
                "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
            ),
        ]
        .into_iter()
        .collect::<HashMap<&str, &str>>(),
    ))
});

#[instrument(skip_all)]
pub async fn get_simulate_swap_intent(
    ctx: Context,
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

    if token_out == system_program::ID.to_string() {
        sleep(tokio::time::Duration::from_secs(2));
        return String::from("0");
    }

    if src_chain == "mantis" {
        let tokens = MANTIS_TOKENS.read().await;

        if let Some(token_mantis) = tokens.get(token_in.as_str()) {
            token_in = token_mantis.to_string();
        } else {
            tracing::warn!("Token {token_in} not supported, please include it on MANTIS_TOKENS");
        }

        src_chain = "solana";
    }

    if dst_chain == "mantis" {
        let tokens = MANTIS_TOKENS.read().await;

        if let Some(token_mantis) = tokens.get(token_out.as_str()) {
            token_out = token_mantis.to_string();
        } else {
            tracing::warn!("Token {token_out} not supported, please include it on MANTIS_TOKENS");
        }

        dst_chain = "solana";
    }

    let (bridge_token_address_src, _) = get_token_info(bridge_token, src_chain).unwrap();
    let mut amount_out_src_chain = BigInt::from_str(&amount_in).unwrap();

    if !bridge_token_address_src.eq_ignore_ascii_case(&token_in) {
        // simulate token_in -> USDT
        if src_chain == "ethereum" {
            amount_out_src_chain = ethereum_simulate_swap(
                ctx.clone(),
                &token_in,
                &amount_in,
                bridge_token_address_src,
            )
            .await;
        } else if src_chain == "solana" || src_chain == "mantis" {
            if src_chain == "mantis" {
                let tokens = MANTIS_TOKENS.read().await;

                match tokens.get(token_in.as_str()) {
                    Some(_token_in) => {
                        token_in = _token_in.to_string();
                    }
                    None => {
                        amount_out_src_chain = BigInt::zero();
                        tracing::error!("Update MANTIS_TOKENS global variable <mantis_token ({token_in}), solana_token>");
                    }
                }
            }

            if !amount_out_src_chain.is_zero() {
                amount_out_src_chain = BigInt::from_str(
                    &solana_simulate_swap(
                        &src_chain_user,
                        &token_in,
                        &bridge_token_address_src,
                        BigInt::from_str(&amount_in).unwrap().to_u64().unwrap(),
                    )
                    .await,
                )
                .unwrap();
            }
        }
    }

    let (bridge_token_address_dst, _) = get_token_info(bridge_token, dst_chain).unwrap();

    // get flat fees
    let flat_fees;
    {
        let fees = FLAT_FEES.read().await;
        flat_fees = fees.get(&(&src_chain, &dst_chain)).unwrap().clone();
    }

    let comission = ctx.envvars.comission;

    if amount_out_src_chain
        < BigInt::from(flat_fees.0 + flat_fees.1 + (&amount_out_src_chain * comission) / 100)
    {
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
            final_amount_out = ethereum_simulate_swap(
                ctx.clone(),
                bridge_token_address_dst,
                &final_amount_out,
                &token_out,
            )
            .await
            .to_string();
        } else if dst_chain == "solana" || dst_chain == "mantis" {
            if src_chain == "mantis" {
                let tokens = MANTIS_TOKENS.read().await;

                match tokens.get(token_out.as_str()) {
                    Some(_token_out) => {
                        token_out = _token_out.to_string();
                    }
                    None => {
                        final_amount_out = "0".to_string();
                        tracing::error!("Update MANTIS_TOKENS global variable <mantis_token ({token_in}), solana_token>");
                    }
                }
            }

            if final_amount_out != "0" {
                final_amount_out = solana_simulate_swap(
                    &dst_chain_user,
                    bridge_token_address_dst,
                    &token_out,
                    amount_in_dst_chain.to_u64().unwrap(),
                )
                .await;
            }
        }
    }

    final_amount_out
}
