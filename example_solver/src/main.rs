mod chains;
mod routers;

use crate::chains::ethereum::ethereum_chain::handle_ethereum_execution;
use crate::chains::mantis::mantis_chain::handle_mantis_execution;
use crate::chains::solana::solana_chain::{handle_solana_execution, SUBMIT_THROUGH_JITO};
use crate::chains::OperationInput;
use crate::chains::OperationOutput;
use crate::chains::PostIntentInfo;
use crate::chains::INTENTS;
use crate::chains::SOLVER_ADDRESSES;
use crate::chains::SOLVER_ID;
use crate::chains::SOLVER_PRIVATE_KEY;
use crate::routers::get_simulate_swap_intent;
use chains::create_keccak256_signature;
use ethers::types::U256;
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use serde_json::json;
use serde_json::Value;
use spl_associated_token_account::get_associated_token_address;
use std::env;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::MaybeTlsStream;
use tokio_tungstenite::WebSocketStream;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let is_jito_enabled = env::var("JITO").map(|x| x == "true").unwrap_or(false);
    SUBMIT_THROUGH_JITO.store(is_jito_enabled, std::sync::atomic::Ordering::SeqCst);
    let server_addr = env::var("COMPOSABLE_ENDPOINT").unwrap_or_else(|_| String::from(""));

    // Connect to WebSocket
    let (ws_stream, _) = connect_async(server_addr).await.expect("Failed to connect");
    let (ws_sender, mut ws_receiver) = ws_stream.split();

    // Wrap the sender in an Arc<RwLock> for thread-safe sharing
    let ws_sender = Arc::new(RwLock::new(ws_sender));

    // Initial authentication message
    let mut json_data = json!({
        "code": 1,
        "msg": {
            "solver_id": SOLVER_ID.to_string(),
            "solver_addresses": SOLVER_ADDRESSES,
        }
    });

    create_keccak256_signature(&mut json_data, SOLVER_PRIVATE_KEY.to_string())
        .await
        .expect("Failed to sign message");

    if json_data.get("code").unwrap() == "0" {
        println!("Authentication failed: {:#?}", json_data);
        return;
    }

    // Send the initial message
    {
        let mut ws_sender_locked = ws_sender.write().await;
        ws_sender_locked
            .send(Message::Text(json_data.to_string()))
            .await
            .expect("Failed to send initial message");
    }

    // Handle incoming messages
    while let Some(msg) = ws_receiver.next().await {
        let ws_sender = Arc::clone(&ws_sender);
        tokio::spawn(async move {
            match msg {
                Ok(Message::Text(text)) => {
                    let parsed: Value = serde_json::from_str(&text).unwrap();
                    let code = parsed.get("code").unwrap().as_u64().unwrap();

                    println!("{:#?}", parsed);

                    if code == 1 {
                        handle_auction_message(parsed, ws_sender).await;
                    } else if code == 4 {
                        handle_result_message(parsed).await;
                    }
                }
                Ok(Message::Close(_)) | Err(_) => {
                    println!("WebSocket closed or error occurred.");
                }
                _ => {}
            }
        });
    }

    println!("Auctioneer went down, please reconnect");
}

/// Handle "participate auction" messages (code 1)
async fn handle_auction_message(
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
            println!("current_time >= intent.timestamp: impossible to solve {intent_id}");
            false
        } else if intent_info.src_chain == intent_info.dst_chain {
            if timeout - current_time < 30 {
                println!("timeout - current_time < 30: not willing to solve {intent_id}");
                false
            } else {
                true
            }
        } else {
            if timeout - current_time < 1800 {
                println!("timeout - current_time < 30mins on cross-chain: not willing to solve {intent_id}");
                false
            } else {
                true
            }
        };

        if ok {
            let final_amount = get_simulate_swap_intent(
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

            println!(
                "User wants {amount_out_min} token_out, you can provide {final_amount} token_out (after FLAT_FEES + COMMISSION)"
            );

            if final_amount > amount_out_min {
                let mut json_data = json!({
                    "code": 2,
                    "msg": {
                        "intent_id": intent_id,
                        "solver_id": SOLVER_ID.to_string(),
                        "amount": final_amount.to_string()
                    }
                });

                create_keccak256_signature(&mut json_data, SOLVER_PRIVATE_KEY.to_string())
                    .await
                    .unwrap();

                {
                    let mut ws_sender_locked = ws_sender.write().await;
                    ws_sender_locked
                        .send(Message::text(json_data.to_string()))
                        .await
                        .expect("Failed to send message");
                    drop(ws_sender_locked);
                }

                {
                    let mut intents = INTENTS.write().await;
                    intents.insert(intent_id.to_string(), intent_info);
                    drop(intents);
                }
            }
        }
    }
}

async fn handle_result_message(parsed: Value) {
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
                tokio::task::spawn_blocking(move || {
                    tokio::runtime::Handle::current()
                        .block_on(handle_solana_execution(
                            &intent,
                            &cloned_intent_id,
                            &cloned_amount,
                        ))
                        .map_err(|e| e.to_string())
                })
                .await
            } else if intent.dst_chain == "ethereum" {
                tokio::task::spawn_blocking(move || {
                    tokio::runtime::Handle::current().block_on(handle_ethereum_execution(
                        &intent,
                        &cloned_intent_id,
                        &cloned_amount,
                    ))
                })
                .await
            } else if intent.dst_chain == "mantis" {
                tokio::task::spawn_blocking(move || {
                    tokio::runtime::Handle::current().block_on(handle_mantis_execution(
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
                Err(e) => eprintln!("Error spawning chain handler: {:?}", e),
                Ok(Err(e)) => eprintln!("Error during chain handler execution: {}", e),
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
