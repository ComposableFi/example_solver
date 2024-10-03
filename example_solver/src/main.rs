mod chains;
mod routers;

use crate::chains::ethereum::ethereum_chain::handle_ethereum_execution;
use crate::chains::mantis::mantis_chain::handle_mantis_execution;
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
use ethers::prelude::{Signature, H256};
use futures::stream::SplitSink;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tokio_tungstenite::tungstenite::Error;
use tokio_tungstenite::tungstenite::protocol::Message;

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    SolverRegister(SignedPayload<SolverRegisterRequest>),
    AuctionBid(SignedPayload<AuctionBidRequest>),
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage {
    SolverRegisterResponse(SolverRegisterResponse),
    NewIntent(NewIntentMessage),
    AuctionResult(AuctionResultMessage),
    ErrorResponse(ErrorResponse),
}

#[derive(Serialize)]
struct SolverRegisterRequest {
    solver_id: String,
    solver_addresses: Vec<String>,
}

#[derive(Deserialize)]
struct SolverRegisterResponse {
    message: String,
}

#[derive(Serialize)]
struct AuctionBidRequest {
    intent_id: String,
    solver_id: String,
    amount: String,
}

#[derive(Serialize)]
struct SignedPayload<T: Serialize> {
    payload: T,
    hash: H256,
    signature: Signature,
}

#[derive(Deserialize)]
struct NewIntentMessage {
    intent_id: String,
    intent: PostIntentInfo,
}

#[derive(Deserialize)]
struct AuctionResultMessage {
    intent_id: String,
    amount: Option<String>,
    message: String,
}

#[derive(Deserialize)]
struct ErrorResponse {
    message: String,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let server_addr = env::var("COMPOSABLE_ENDPOINT")
        .unwrap_or_else(|_| String::from("ws://34.78.217.187:8080"));

    let (ws_stream, _) = connect_async(format!("{}/ws", server_addr))
        .await
        .expect("Failed to connect");
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    let register_request = SolverRegisterRequest {
        solver_id: SOLVER_ID.to_string(),
        solver_addresses: SOLVER_ADDRESSES.into_iter().map(ToString::to_string).collect(),
    };

    let register_request = create_keccak256_signature(register_request, SOLVER_PRIVATE_KEY.to_string())
        .await
        .unwrap();

    // Serialize the message
    let message = ClientMessage::SolverRegister(register_request);
    let message_text = serde_json::to_string(&message).unwrap();

    ws_sender
        .send(Message::Text(message_text))
        .await
        .expect("Failed to send initial message");

    while let Some(msg) = ws_receiver.next().await {
        handle_message(&mut ws_sender, msg).await;
    }

    println!("Auctioneer went down, please reconnect");
}

async fn handle_message(ws_sender: &mut SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>, msg: Result<Message, Error>) -> Result<Option<()>, ()> {
    match msg {
        Ok(Message::Text(text)) => {
            let server_message: ServerMessage = match serde_json::from_str(&text) {
                Ok(msg) => msg,
                Err(err) => {
                    eprintln!("Failed to parse server message: {:?}", err);
                    return Ok(Some(()));
                }
            };

            match server_message {
                ServerMessage::SolverRegisterResponse(response) => {
                    println!("Solver registered: {}", response.message);
                }
                ServerMessage::NewIntent(new_intent) => {
                    // Participate in auction
                    let intent_id = new_intent.intent_id;
                    let intent_info = new_intent.intent;

                    // Calculate best quote
                    let final_amount = get_simulate_swap_intent(
                        &intent_info,
                        &intent_info.src_chain,
                        &intent_info.dst_chain,
                        &"USDT".to_string(),
                    )
                        .await;

                    // Decide whether to participate
                    let amount_out_min = if let OperationOutput::SwapTransfer(transfer_output) = &intent_info.outputs {
                        U256::from_dec_str(&transfer_output.amount_out).unwrap_or(U256::zero())
                    } else {
                        U256::zero()
                    };

                    let final_amount_u256 = U256::from_dec_str(&final_amount).unwrap_or(U256::zero());

                    println!(
                        "User wants {} token_out, you can provide {} token_out (after fees and commission)",
                        amount_out_min, final_amount_u256
                    );

                    if final_amount_u256 > amount_out_min {
                        // Create AuctionBidRequest
                        let auction_bid_request = AuctionBidRequest {
                            intent_id: intent_id.clone(),
                            solver_id: SOLVER_ID.to_string(),
                            amount: final_amount.clone(),
                        };

                        // Create signature
                        let auction_bid_request = create_keccak256_signature(auction_bid_request, SOLVER_PRIVATE_KEY.to_string())
                            .await
                            .unwrap();

                        // Serialize the message
                        let message = ClientMessage::AuctionBid(auction_bid_request);
                        let message_text = serde_json::to_string(&message).unwrap();

                        ws_sender
                            .send(Message::Text(message_text))
                            .await
                            .expect("Failed to send auction bid message");

                        // Store the intent
                        {
                            let mut intents = INTENTS.write().await;
                            intents.insert(intent_id.clone(), intent_info);
                        }
                    }
                }
                ServerMessage::AuctionResult(auction_result) => {
                    let intent_id = auction_result.intent_id;
                    let amount = auction_result.amount;

                    if let Some(amount) = amount {
                        println!("Auction result for {}: {}", intent_id, auction_result.message);

                        // Retrieve the intent
                        let intent = {
                            let intents = INTENTS.read().await;
                            intents.get(&intent_id).cloned()
                        };

                        if let Some(intent) = intent {
                            if auction_result.message.contains("won") {
                                // Handle execution
                                let handle_result = match intent.dst_chain.as_str() {
                                    "solana" => handle_solana_execution(&intent, &intent_id, &amount).await,
                                    "ethereum" => handle_ethereum_execution(&intent, &intent_id, &amount, intent.src_chain == intent.dst_chain).await,
                                    "mantis" => handle_mantis_execution(&intent, &intent_id, &amount).await,
                                    _ => Err("Unsupported destination chain".to_string()),
                                };

                                if let Err(err) = handle_result {
                                    eprintln!("Failed to handle execution: {}", err);
                                }
                            }

                            // Remove the intent
                            {
                                let mut intents = INTENTS.write().await;
                                intents.remove(&intent_id);
                            }
                        } else {
                            eprintln!("Intent not found for intent_id: {}", intent_id);
                        }
                    }
                }
                ServerMessage::ErrorResponse(error_response) => {
                    eprintln!("Error from server: {}", error_response.message);
                }
            }
            Ok(Some(()))
        }
        Ok(Message::Close(_)) | Err(_) => Ok(None),
        _ => {
            Ok(Some(()))
        }
    }
}