mod chains;
mod routers;

use crate::chains::ethereum::ethereum_chain::{ethereum_quote, handle_ethereum_execution};
use crate::chains::mantis::mantis_chain::handle_mantis_execution;
use crate::chains::solana::solana_chain::{handle_solana_execution, solana_quote};
use crate::chains::OperationInput;
use crate::chains::OperationOutput;
use crate::chains::PostIntentInfo;
use crate::chains::INTENTS;
use crate::chains::SOLVER_ADDRESSES;
use crate::chains::SOLVER_ID;
use crate::chains::SOLVER_PRIVATE_KEY;
use crate::routers::get_simulate_swap_intent;
use chains::create_keccak256_signature;
use derive_more::{Deref, DerefMut};
use ethers::core::rand;
use ethers::prelude::{Signature, H256};
use ethers::types::U256;
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use solana_sdk::pubkey::Pubkey;
use spl_associated_token_account::get_associated_token_address;
use std::env;
use std::str::FromStr;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use ethers::abi::Address;
use num_bigint::BigInt;
use num_traits::Num;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::Error;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

type RequestId = u32;
type SolverId = String;

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    SolverRegister(SignedPayload<SolverRegisterRequest>),
    AuctionBid(SignedPayload<AuctionBidRequest>),
    QuoteResponse(QuoteResponse),
    ErrorResponse(ErrorResponse),
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage {
    SolverRegisterResponse(SolverRegisterResponse),
    NewIntent(NewIntentMessage),
    AuctionResult(AuctionResultMessage),
    ErrorResponse(ErrorResponse),
    QuoteRequest(QuoteRequest),
}

#[derive(Serialize, Deserialize)]
struct QuoteRequest {
    pub token_in: String,
    pub amount_in: U256,
    pub token_out: String,
    pub network: Network
}

#[derive(Deserialize, Serialize)]
struct QuoteResponse {
    pub token_out: String,
    pub amount_out: U256,
}

#[derive(Deserialize, Serialize)]
struct SolverQuoteResponse {
    solver_id: SolverId,
    #[serde(flatten)]
    response: QuoteResponse,
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

#[derive(Serialize, Deserialize, Deref, DerefMut)]
pub struct Identified<T> {
    #[deref]
    #[deref_mut]
    payload: T,
    pub(crate) id: RequestId,
}

impl<T> Identified<T> {
    pub fn new(payload: T, id: RequestId) -> Self {
        Identified { payload, id }
    }
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

#[derive(Deserialize, Serialize)]
struct ErrorResponse {
    message: String,
}

struct Solver {
    solver_id: SolverId,
    request_id: Arc<AtomicU32>,
    ws_sender: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
}

#[derive(Copy, Clone)]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Network {
    Solana,
    Ethereum,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    env_logger::init();
    let server_addr =
        env::var("COMPOSABLE_ENDPOINT").unwrap_or_else(|_| String::from("ws://34.78.217.187:8080"));

    let (ws_stream, _) = connect_async(format!("{}/ws", server_addr))
        .await
        .expect("Failed to connect");
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    let mut solver = Solver {
        solver_id: SOLVER_ID.to_string(),
        request_id: Arc::new(AtomicU32::new(0)),
        ws_sender,
    };

    let register_request = SolverRegisterRequest {
        solver_id: solver.solver_id.clone(),
        solver_addresses: SOLVER_ADDRESSES
            .into_iter()
            .map(ToString::to_string)
            .collect(),
    };

    let register_request =
        create_keccak256_signature(register_request, SOLVER_PRIVATE_KEY.to_string())
            .await
            .unwrap();

    // Serialize the message
    let message = ClientMessage::SolverRegister(register_request);
    solver.identify_and_send(&message).await.unwrap();

    while let Some(msg) = ws_receiver.next().await {
        if let Err(e) = solver
            .handle_message(msg)
            .await {
            error!("Error handling message: {}", e);

        }
    }

    // TODO: auto-reconnect
    println!("Auctioneer went down, please reconnect");
}

impl Solver {
    pub async fn send_raw<T: Serialize>(&mut self, val: &T) -> anyhow::Result<()> {
        let val = serde_json::to_string(val)?;
        let message = Message::Text(val);
        self.ws_sender.send(message).await?;
        Ok(())
    }

    pub async fn identify_and_send<T: Serialize>(&mut self, val: &T) -> anyhow::Result<()> {
        let req_id = self
            .request_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let ident_val = Identified::new(val, req_id);
        self.send_raw(&ident_val).await
    }

    pub async fn reply<T: Serialize>(
        &mut self,
        val: &T,
        request_id: RequestId,
    ) -> anyhow::Result<()> {
        let ident_val = Identified::new(val, request_id);
        self.send_raw(&ident_val).await
    }

    async fn handle_message(&mut self, msg: Result<Message, Error>) -> anyhow::Result<Option<()>> {
        match msg {
            Ok(Message::Text(text)) => {
                debug!("Received message: {}", text);
                let ident_server_message: Identified<ServerMessage> =
                    match serde_json::from_str(&text) {
                        Ok(msg) => msg,
                        Err(err) => {
                            eprintln!("Failed to parse server message: {:?}", err);
                            return Ok(Some(()));
                        }
                    };

                let id = ident_server_message.id;
                if let Err(e) = self.process_server_message(ident_server_message).await {
                    error!("Error processing server message: {}", e);
                    self.reply(
                        &ClientMessage::ErrorResponse(ErrorResponse {
                            message: format!("Error processing message: {}", e),
                        }),
                        id,
                    ).await?;
                }
                Ok(Some(()))
            }
            Ok(Message::Close(_)) | Err(_) => Ok(None),
            _ => Ok(Some(())),
        }
    }

    async fn process_server_message(&mut self, ident_server_message: Identified<ServerMessage>) -> anyhow::Result<()> {
        let server_message = ident_server_message.payload;
        let req_id = ident_server_message.id;
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
                let amount_out_min = if let OperationOutput::SwapTransfer(transfer_output) =
                    &intent_info.outputs
                {
                    U256::from_dec_str(&transfer_output.amount_out).unwrap_or(U256::zero())
                } else {
                    U256::zero()
                };

                let final_amount_u256 =
                    U256::from_dec_str(&final_amount).unwrap_or(U256::zero());

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
                    let auction_bid_request = create_keccak256_signature(
                        auction_bid_request,
                        SOLVER_PRIVATE_KEY.to_string(),
                    )
                        .await
                        .unwrap();

                    // Serialize the message
                    let message = ClientMessage::AuctionBid(auction_bid_request);
                    self.reply(&message, req_id).await.unwrap();

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
                    println!(
                        "Auction result for {}: {}",
                        intent_id, auction_result.message
                    );

                    // Retrieve the intent
                    let intent = {
                        let intents = INTENTS.read().await;
                        intents.get(&intent_id).cloned()
                    };

                    if let Some(intent) = intent {
                        if auction_result.message.contains("won") {
                            // Handle execution
                            let handle_result = match intent.dst_chain.as_str() {
                                "solana" => {
                                    handle_solana_execution(&intent, &intent_id, &amount)
                                        .await
                                }
                                "ethereum" => {
                                    handle_ethereum_execution(
                                        &intent,
                                        &intent_id,
                                        &amount,
                                        intent.src_chain == intent.dst_chain,
                                    )
                                        .await
                                }
                                "mantis" => {
                                    handle_mantis_execution(&intent, &intent_id, &amount)
                                        .await
                                }
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
            ServerMessage::QuoteRequest(req) => {
                let quote_market = self.quote_market(req.network, &req).await?;
                let message = ClientMessage::QuoteResponse(QuoteResponse {
                    token_out: req.token_out,
                    amount_out: quote_market,
                });
                self.reply(&message, req_id).await.unwrap();
            }
        }
        Ok(())
    }

    async fn quote_market(
        &self,
        network: Network,
        quote_request: &QuoteRequest,
    ) -> anyhow::Result<U256> {
        match network {
            Network::Solana => {
                let dest_user = Pubkey::default();
                let token_in = Pubkey::from_str(&quote_request.token_in)?;
                let amount_in = quote_request.amount_in.as_u64();
                let token_out = Pubkey::from_str(&quote_request.token_out)?;
                let quote = solana_quote(dest_user, token_in, token_out, amount_in).await?;
                Ok(quote.out_amount.into())
            }
            Network::Ethereum => {
                let token_in = Address::from_str(&quote_request.token_in)?;
                let token_out = Address::from_str(&quote_request.token_out)?;
                let amount_in = BigInt::from_str_radix(&quote_request.amount_in.to_string(), 16)?;
                let amount_out = ethereum_quote(token_in,  amount_in, token_out).await;
                Ok(U256::from_dec_str(&amount_out.to_string()).unwrap())
            }
        }
    }
}
