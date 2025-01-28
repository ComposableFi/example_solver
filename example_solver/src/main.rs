mod chains;
mod envvars;
mod messages;
mod routers;

use crate::{
    chains::{
        ethereum::handle_ethereum_execution, mantis::handle_mantis_execution,
        solana::handle_solana_execution, OperationInput, OperationOutput, PostIntentInfo, INTENTS,
    },
    routers::get_simulate_swap_intent,
};
use anyhow::{bail, Error, Result};
use chains::create_keccak256_signature;
use envvars::Envvars;
use ethers::types::U256;
use futures::{stream::SplitSink, SinkExt, StreamExt};
use serde_json::{json, Value};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpStream, sync::RwLock};
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message, MaybeTlsStream, WebSocketStream,
};
use tracing::instrument;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

#[derive(Clone)]
pub(crate) struct Context {
    pub(crate) envvars: Arc<Envvars>,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();

    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .with_level(true)
        .with_ansi(true)
        .with_span_events(FmtSpan::NONE)
        .without_time()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new(
            "info,tower_http=debug,axum::rejection=trace",
        )))
        .try_init()
        .map_err(Error::from_boxed)?;

    let ctx = Context {
        envvars: Arc::new(envvars::get()?),
    };

    let (ws_stream, _) = connect_async(&ctx.envvars.auctioneer_ws).await?;
    let (ws_sender, mut ws_receiver) = ws_stream.split();
    let ws_sender = Arc::new(RwLock::new(ws_sender));

    // Initial authentication message
    let mut json_data = json!({
        "code": 1,
        "msg": {
            "solver_id": &ctx.envvars.solver_id,
            "solver_addresses": ctx.envvars.solver_addresses,
        }
    });

    create_keccak256_signature(&mut json_data, &ctx.envvars.ethereum_key)
        .await
        .map_err(|err| anyhow::anyhow!("{}", err))?;

    if json_data.get("code").is_some_and(|code| code == "0") {
        tracing::error!("Authentication failed: {:#?}", json_data);
        bail!("Authentication failed: {:#?}", json_data);
    }

    {
        ws_sender
            .write()
            .await
            .send(Message::Text(json_data.to_string()))
            .await?;
    }

    while let Some(msg) = ws_receiver.next().await {
        let ws_sender = ws_sender.clone();
        let ctx = ctx.clone();

        tokio::spawn(async move {
            match msg {
                Ok(Message::Text(text)) => {
                    let parsed = match serde_json::from_str::<Value>(&text) {
                        Ok(val) => val,
                        Err(err) => {
                            tracing::error!("Unable to parse WebSocket message: {}", err);
                            return;
                        }
                    };

                    let code = match parsed.get("code").and_then(|x| x.as_u64()) {
                        Some(val) => val,
                        None => {
                            tracing::error!("Unable to parse code value from WebSocket message");
                            return;
                        }
                    };

                    tracing::info!("{:#?}", parsed);

                    if code == 1 {
                        handle_auction_message(ctx, parsed, ws_sender).await;
                    } else if code == 4 {
                        handle_result_message(ctx, parsed).await;
                    }
                }
                Ok(Message::Close(_)) => {
                    tracing::warn!("WebSocket loop closed");
                }
                Err(err) => {
                    tracing::error!("WebSocket loop error: {}", err);
                }
                _ => {}
            }
        });
    }

    tracing::warn!("Auctioneer went down, please reconnect");

    Ok(())
}

/// Handle "participate auction" messages (code 1)
#[instrument(skip_all)]
async fn handle_auction_message(
    ctx: Context,
    parsed: Value,
    ws_sender: Arc<RwLock<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
) {
    let intent_id = parsed
        .get("msg")
        .unwrap()
        .get("intent_id")
        .and_then(Value::as_str)
        .unwrap();
    let intent_str = parsed
        .get("msg")
        .unwrap()
        .get("intent")
        .unwrap()
        .to_string();
    let intent_value: Value = serde_json::from_str(&intent_str).unwrap();
    let intent_info: PostIntentInfo = serde_json::from_value(intent_value).unwrap();

    if let OperationInput::SwapTransfer(swap_input) = &intent_info.inputs {
        let timeout = swap_input.timeout.parse::<u64>().unwrap();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let ok = if current_time >= timeout {
            tracing::info!("current_time >= intent.timestamp: impossible to solve {intent_id}");
            false
        } else if intent_info.src_chain == intent_info.dst_chain {
            if timeout - current_time < 30 {
                tracing::info!("timeout - current_time < 30: not willing to solve {intent_id}");
                false
            } else {
                true
            }
        } else {
            if timeout - current_time < 1800 {
                tracing::info!("timeout - current_time < 30mins on cross-chain: not willing to solve {intent_id}");
                false
            } else {
                true
            }
        };

        if ok {
            let final_amount = get_simulate_swap_intent(
                ctx.clone(),
                &intent_info,
                &intent_info.src_chain,
                &intent_info.dst_chain,
                &String::from("USDT"),
            )
            .await;

            let mut amount_out_min = U256::zero();
            if let OperationOutput::SwapTransfer(transfer_output) = &intent_info.outputs {
                amount_out_min = U256::from_dec_str(&transfer_output.amount_out).unwrap();
            }

            let final_amount = U256::from_dec_str(&final_amount).unwrap();

            tracing::info!(
                "User wants {amount_out_min} token_out, you can provide {final_amount} token_out (after FLAT_FEES + COMMISSION)"
            );

            if final_amount > amount_out_min {
                let mut json_data = json!({
                    "code": 2,
                    "msg": {
                        "intent_id": intent_id,
                        "solver_id": &ctx.envvars.solver_id,
                        "amount": &final_amount
                    }
                });

                create_keccak256_signature(&mut json_data, &ctx.envvars.ethereum_key)
                    .await
                    .unwrap();

                {
                    ws_sender
                        .write()
                        .await
                        .send(Message::text(json_data.to_string()))
                        .await
                        .expect("Failed to send message");
                }

                {
                    INTENTS
                        .write()
                        .await
                        .insert(intent_id.to_string(), intent_info);
                }
            }
        }
    }
}

#[instrument(skip_all)]
async fn handle_result_message(ctx: Context, parsed: Value) {
    let intent_id = parsed
        .get("msg")
        .and_then(|msg| msg.get("intent_id"))
        .and_then(Value::as_str)
        .map(|s| s.to_string())
        .expect("intent_id not found");
    let amount = parsed
        .get("msg")
        .and_then(|msg| msg.get("amount"))
        .and_then(Value::as_str)
        .map(|s| s.to_string());

    if let Some(amount) = amount {
        let msg = parsed
            .get("msg")
            .and_then(|msg| msg.get("msg"))
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .expect("msg not found");

        if msg.contains("won") {
            // Clone the necessary data for the closure
            let cloned_intent_id = intent_id.clone();
            let cloned_amount = amount.clone();

            let intent;
            {
                let intents = INTENTS.read().await;
                intent = intents.get(&intent_id).cloned().expect("Intent not found");
                drop(intents);
            }

            let result = if intent.dst_chain == "solana" {
                let res = tokio::task::spawn_blocking(move || {
                    tokio::runtime::Handle::current().block_on(handle_solana_execution(
                        ctx.clone(),
                        &intent,
                        &cloned_intent_id,
                        &cloned_amount,
                    ))
                })
                .await;

                res.map(|x| x.map_err(|x| x.to_string()))
            } else if intent.dst_chain == "ethereum" {
                tokio::task::spawn_blocking(move || {
                    tokio::runtime::Handle::current().block_on(handle_ethereum_execution(
                        ctx.clone(),
                        &intent,
                        &cloned_intent_id,
                        &cloned_amount,
                    ))
                })
                .await
            } else if intent.dst_chain == "mantis" {
                tokio::task::spawn_blocking(move || {
                    tokio::runtime::Handle::current().block_on(handle_mantis_execution(
                        ctx.clone(),
                        &intent,
                        &cloned_intent_id,
                        &cloned_amount,
                    ))
                })
                .await
            } else {
                Ok(Ok(()))
            };

            // Log errors if any
            match result {
                Err(e) => tracing::error!("Error spawning chain handler: {:?}", e),
                Ok(Err(e)) => tracing::error!("Error during chain handler execution: {}", e),
                _ => {}
            }

            // Update INTENTS after execution
            {
                let mut intents = INTENTS.write().await;
                intents.remove(&intent_id);
            }
        }
    }
}
