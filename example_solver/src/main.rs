mod chains;
mod routers;

use crate::chains::ethereum::ethereum_chain::handle_ethereum_execution;
use crate::chains::solana::solana_chain::handle_solana_execution;
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
use futures::{SinkExt, StreamExt};
use serde_json::json;
use serde_json::Value;
use spl_associated_token_account::get_associated_token_address;
use std::env;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::protocol::Message;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let server_addr = env::var("COMPOSABLE_ENDPOINT").unwrap_or_else(|_| String::from(""));

    let (ws_stream, _) = connect_async(server_addr).await.expect("Failed to connect");
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    let mut json_data = json!({
        "code": 1,
        "msg": {
            "solver_id": SOLVER_ID.to_string(),
            "solver_addresses": SOLVER_ADDRESSES,
        }
    });

    create_keccak256_signature(&mut json_data, SOLVER_PRIVATE_KEY.to_string())
        .await
        .unwrap();

    if json_data.get("code").unwrap() == "0" {
        println!("{:#?}", json_data);
        return;
    }

    ws_sender
        .send(Message::Text(json_data.to_string()))
        .await
        .expect("Failed to send initial message");

    while let Some(msg) = ws_receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                let parsed: Value = serde_json::from_str(&text).unwrap();
                let code = parsed.get("code").unwrap().as_u64().unwrap();

                println!("{:#?}", parsed);

                if code == 0 {
                    // error
                } else if code == 1 {
                    // participate auction
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

                    // calculate best quote
                    let final_amount = get_simulate_swap_intent(
                        &intent_info,
                        &intent_info.src_chain,
                        &intent_info.dst_chain,
                        &String::from("USDT"),
                    )
                    .await;

                    // decide if participate or not
                    let mut amount_out_min = U256::zero();
                    if let OperationOutput::SwapTransfer(transfer_output) = &intent_info.outputs {
                        amount_out_min = U256::from_dec_str(&transfer_output.amount_out).unwrap();
                    }

                    let final_amount = U256::from_dec_str(&final_amount).unwrap();

                    println!("User wants {amount_out_min} token_out, you can provide {final_amount} token_out (after FLAT_FEES + COMISSION)");

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

                        ws_sender
                            .send(Message::text(json_data.to_string()))
                            .await
                            .expect("Failed to send message");

                        let mut intents = INTENTS.write().await;
                        intents.insert(intent_id.to_string(), intent_info);
                        drop(intents);
                    }
                } else if code == 3 {
                    // solver registered
                } else if code == 4 {
                    let intent_id = parsed
                        .get("msg")
                        .unwrap()
                        .get("intent_id")
                        .and_then(Value::as_str)
                        .unwrap();
                    let amount = parsed
                        .get("msg")
                        .unwrap()
                        .get("amount")
                        .and_then(Value::as_str);

                    if let Some(amount) = amount {
                        let msg = parsed
                            .get("msg")
                            .unwrap()
                            .get("msg")
                            .and_then(Value::as_str)
                            .unwrap()
                            .to_string();

                        if msg.contains("won") {
                            let intent;
                            {
                                let intents = INTENTS.read().await;
                                intent = intents.get(intent_id).unwrap().clone();
                                drop(intents);
                            }

                            if intent.dst_chain == "solana" {
                                handle_solana_execution(&intent, intent_id, amount)
                                    .await
                                    .unwrap();
                            } else if intent.dst_chain == "ethereum" {
                                handle_ethereum_execution(&intent, intent_id, amount)
                                    .await
                                    .unwrap();
                            } 

                            // ws_sender.send(Message::text(msg)).await.expect("Failed to send message");
                        }

                        {
                            let mut intents = INTENTS.write().await;
                            intents.remove(&intent_id.to_string());
                            drop(intents);
                        }
                    }
                }
            }
            Ok(Message::Close(_)) | Err(_) => break,
            _ => {}
        }
    }

    println!("Auctioner went down, please reconnect");
}
