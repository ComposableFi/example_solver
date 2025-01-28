use crate::{
    chains::*,
    routers::jupiter::{jupiter_swap, quote, Memo as Jup_Memo, QuoteConfig, SwapMode},
    Context, PostIntentInfo,
};
use anchor_client::Cluster;
use jito_protos::searcher::SubscribeBundleResultsRequest;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    compute_budget::ComputeBudgetInstruction,
    instruction::Instruction,
    message::{v0, VersionedMessage},
    pubkey,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction, system_program,
    transaction::{Transaction, VersionedTransaction},
};
use spl_associated_token_account::{get_associated_token_address, instruction};
use spl_token::instruction::transfer;
use std::{
    env,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use strum_macros::{Display, IntoStaticStr};
use tracing::instrument;

pub const JITO_ADDRESS: Pubkey = pubkey!("96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5");
pub const AUCTIONEER_ADDRESS: Pubkey = pubkey!("5zCZ3jk8EZnJyG7fhDqD6tmqiYTLZjik5HUpGMnHrZfC");
pub const JITO_TIP_AMOUNT: u64 = 100_000;
pub const JITO_BLOCK_ENGINE_URL: &str = "https://mainnet.block-engine.jito.wtf";
pub const MAX_RETRIES: u8 = 1;
pub const WSOL_ADDRESS: &str = "So11111111111111111111111111111111111111112";
pub const USDT_ADDRESS: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
pub static SUBMIT_THROUGH_JITO: AtomicBool = AtomicBool::new(option_env!("JITO").is_some());
const AUCTIONEER_URL: &str = "http://34.78.217.187:8080";

/// The Errors that may occur while using this module
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Soalana client error: {0}")]
    SolanaClient(#[from] solana_client::client_error::ClientError),

    #[error("Reqwest HTTP error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("Jito client error: {0}")]
    JitoClient(#[from] jito_searcher_client::BlockEngineConnectionError),

    #[error("Message compile error: {0}")]
    MessageCompile(#[from] solana_sdk::message::CompileError),

    #[error("Signer error: {0}")]
    Signer(#[from] solana_sdk::signature::SignerError),

    #[error("Program error: {0}")]
    Program(#[from] solana_program::program_error::ProgramError),

    #[error("Failed to parse {name}: {source}")]
    ParseInt {
        name: String,
        #[source]
        source: std::num::ParseIntError,
    },

    #[error("Failed to parse {name}: {source}")]
    ParsePubkey {
        name: String,
        #[source]
        source: solana_program::pubkey::ParsePubkeyError,
    },

    #[error("Env var must be set: {name} {source}")]
    EnvVar {
        name: String,
        #[source]
        source: std::env::VarError,
    },

    #[error("{0}")]
    Message(String),

    #[error("{context}: {source}")]
    WithContext {
        context: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl Error {
    #[instrument(skip_all)]
    pub fn with_context<E>(context: &str, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Error::WithContext {
            context: context.to_string(),
            source: Box::new(source),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, Default, EnumString, Display, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum TxSendMethod {
    #[default]
    JITO,
    RPC,
}

// DUMMY MANTIS = 78grvu3nEsQsx3tdMB8BqedJF2hyJx1GPgjGQZWDrDTS

#[derive(Debug, Serialize, Deserialize)]
struct SwapData {
    pub user_account: String,
    pub token_in: String,
    pub token_out: String,
    pub amount: u64,
    pub slippage_bps: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Memo {
    tx_hash: String,
    intent_id: String,
    params: Vec<String>,
}

#[instrument(skip_all)]
pub async fn handle_solana_execution(
    ctx: Context,
    intent: &PostIntentInfo,
    intent_id: &str,
    amount: &str,
) -> Result<()> {
    let solver_keypair = Arc::new(Keypair::from_base58_string(&ctx.envvars.solana_key));
    let rpc_url = &ctx.envvars.solana_rpc;
    let client = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());

    let mut user_account = String::default();
    let mut token_in = String::default();
    let mut amount_in = String::default();
    let mut token_out = String::default();

    if let OperationOutput::SwapTransfer(transfer_output) = &intent.outputs {
        user_account = transfer_output.dst_chain_user.clone();
        token_out = transfer_output.token_out.clone();

        if token_out == system_program::ID.to_string() {
            token_out = WSOL_ADDRESS.to_string();
        }
    }
    if let OperationInput::SwapTransfer(transfer_input) = &intent.inputs {
        token_in = transfer_input.token_in.clone();
        amount_in = transfer_input.amount_in.clone();
    }

    // swap USDT -> token_out
    let solver_token_out_account = get_associated_token_address(
        &solver_keypair.pubkey(),
        &Pubkey::from_str(&token_out).map_err(|e| Error::ParsePubkey {
            name: "token_out".into(),
            source: e,
        })?,
    );

    let solver_token_out_balance = client
        .get_token_account_balance(&solver_token_out_account)
        .await
        .map(|result| result.amount)
        .unwrap_or_else(|_| "0".to_string())
        .parse::<u64>()
        .map_err(|e| Error::ParseInt {
            name: "balance".into(),
            source: e,
        })?;

    let token_out_amount = amount.parse::<u64>().map_err(|e| Error::ParseInt {
        name: "amount".into(),
        source: e,
    })?;

    let mut setup_instructions: Vec<Instruction> = vec![];
    let mut bundle_instructions: Vec<Vec<Instruction>> = vec![];

    if solver_token_out_balance < token_out_amount && !token_out.eq_ignore_ascii_case(USDT_ADDRESS)
    {
        let ts_instructions = solana_transfer_swap(ctx.clone(), intent.clone(), amount)
            .await
            .map_err(|e| {
                Error::with_context(
                    "Error occurred during swap from USDT to token_out (manual swap required)",
                    e,
                )
            })?;
        setup_instructions.extend(ts_instructions.setup_instructions);
        if !ts_instructions.swap_instructions.is_empty() {
            bundle_instructions.push(ts_instructions.swap_instructions);
        } else if !ts_instructions.transfer_instructions.is_empty() {
            bundle_instructions.push(ts_instructions.transfer_instructions);
        }
    }

    let solver_out = if intent.src_chain == "ethereum" {
        ctx.envvars.solver_addresses.get(0).unwrap()
    } else if intent.src_chain == "solana" {
        ctx.envvars.solver_addresses.get(1).unwrap()
    } else {
        panic!("Chain not supported, this should't happen");
    };

    // solver -> token_out -> user | user -> token_in -> solver
    let sftu_instructions = solana_send_funds_to_user(
        ctx.clone(),
        intent_id,
        &token_in,
        &token_out,
        &user_account,
        solver_out.to_string(),
        intent.src_chain == intent.dst_chain,
        rpc_url,
        bridge_escrow::ID,
        token_out_amount,
    )
    .await
    .map_err(|e| Error::with_context("Error occurred during solana_send_funds_to_user", e))?;

    let mut sftu_tx_index: Option<usize> = None;
    setup_instructions.extend(sftu_instructions.setup_instructions);
    if !sftu_instructions.send_funds_to_user_instructions.is_empty() {
        bundle_instructions.push(sftu_instructions.send_funds_to_user_instructions);
        // We record the SendFundsToUser transaction index to later find the correct signature.
        sftu_tx_index = Some(bundle_instructions.len());
    }

    // swap token_in -> USDT
    if intent.src_chain == intent.dst_chain && !token_in.eq_ignore_ascii_case(USDT_ADDRESS) {
        let mut amount_in = amount_in.parse::<u64>().map_err(|e| Error::ParseInt {
            name: "amount_in".into(),
            source: e,
        })?;
        // The bridge escrow contract takes a 0.1% fee.
        amount_in -= amount_in / 1000;

        let memo = format!(
            r#"{{"user_account": "{}","token_in": "{}","token_out": "{}","amount": {},"slippage_bps": {}}}"#,
            ctx.envvars.solver_addresses.get(1).unwrap(),
            token_in,
            USDT_ADDRESS,
            amount_in,
            1000
        );

        let js_instructions = jupiter_swap(
            &memo,
            &client,
            solver_keypair.clone(),
            SwapMode::ExactIn,
            true,
        )
        .await
        .map_err(|e| Error::Message(format!("Failed to swap token_in to USDT: {e}")))?;

        setup_instructions.extend(js_instructions.setup_instructions);
        if !js_instructions.swap_instructions.is_empty() {
            bundle_instructions.push(js_instructions.swap_instructions);
        }
    }

    match submit_through_jito(
        &client,
        solver_keypair,
        setup_instructions,
        bundle_instructions,
        JITO_TIP_AMOUNT,
    )
    .await
    {
        Ok(bundle_signatures) => {
            if let Some(index) = sftu_tx_index {
                let sftu_tx_hash = bundle_signatures[index];
                tracing::info!(
                    "Sending SendFundsToUser transaction hash to auctioneer: {}",
                    sftu_tx_hash
                );
                send_tx_hash_to_auctioneer(AUCTIONEER_URL, sftu_tx_hash)
                    .await
                    .map_err(|e| {
                        Error::with_context("Failed to send transaction hash to auctioneer", e)
                    })?;
            } else {
                return Err(Error::Message(
                    "SendFundsToUser signature index missing".into(),
                ));
            }
            tracing::info!("Intent {intent_id} solved successfully");
            Ok(())
        }
        Err(error) => Err(Error::with_context(
            "Failed to submit intent transactions",
            error,
        )),
    }
}

#[derive(Debug, Default)]
pub struct TransferSwapInstructions {
    pub setup_instructions: Vec<Instruction>,
    pub transfer_instructions: Vec<Instruction>,
    pub swap_instructions: Vec<Instruction>,
}

#[instrument(skip_all)]
pub async fn solana_transfer_swap(
    ctx: Context,
    intent: PostIntentInfo,
    amount: &str,
) -> Result<TransferSwapInstructions> {
    let rpc_url = env::var("SOLANA_RPC").map_err(|e| Error::EnvVar {
        name: "SOLANA_RPC".into(),
        source: e,
    })?;

    let solver_keypair = Arc::new(Keypair::from_base58_string(
        env::var("SOLANA_KEYPAIR")
            .map_err(|e| Error::EnvVar {
                name: "SOLANA_KEYPAIR".into(),
                source: e,
            })?
            .as_str(),
    ));

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let mut ts_instructions = TransferSwapInstructions::default();

    match intent.function_name.as_str() {
        "transfer" => {
            let mut user_account = String::default();
            let mut token_out = String::default();
            let mut parsed_amount = 0u64;

            if let OperationOutput::SwapTransfer(transfer_output) = &intent.outputs {
                user_account = transfer_output.dst_chain_user.clone();
                token_out = transfer_output.token_out.clone();
                parsed_amount =
                    transfer_output
                        .amount_out
                        .parse::<u64>()
                        .map_err(|e| Error::ParseInt {
                            name: "amount_out".into(),
                            source: e,
                        })?;
            }

            let instructions = transfer_spl20(
                &client,
                solver_keypair.clone(),
                &Pubkey::from_str(&user_account).map_err(|e| Error::ParsePubkey {
                    name: "user_account".into(),
                    source: e,
                })?,
                &Pubkey::from_str(&token_out).map_err(|e| Error::ParsePubkey {
                    name: "token_out".into(),
                    source: e,
                })?,
                parsed_amount,
            )
            .await
            .map_err(|e| Error::with_context("Token transfer failed", e))?;

            ts_instructions.setup_instructions = instructions.setup_instructions;
            ts_instructions.transfer_instructions = instructions.transfer_instructions;
        }
        "swap" => {
            let mut token_out = String::default();

            if let OperationOutput::SwapTransfer(transfer_output) = &intent.outputs {
                token_out = transfer_output.token_out.clone();
            }

            let memo = format!(
                r#"{{"user_account": "{}","token_in": "{}","token_out": "{}","amount": {},"slippage_bps": {}}}"#,
                ctx.envvars.solver_addresses.get(1).unwrap(),
                USDT_ADDRESS,
                token_out,
                amount,
                200
            );

            let js_instructions = jupiter_swap(
                &memo,
                &client,
                solver_keypair.clone(),
                SwapMode::ExactOut,
                true,
            )
            .await
            .map_err(|e| Error::Message(format!("Jupiter swap failed: {e}")))?;

            ts_instructions.setup_instructions = js_instructions.setup_instructions;
            ts_instructions.swap_instructions = js_instructions.swap_instructions;
        }
        _ => {
            return Err(Error::Message("Function not supported".into()));
        }
    };

    Ok(ts_instructions)
}

#[derive(Debug, Default)]
struct TransferSPL20Instructions {
    setup_instructions: Vec<Instruction>,
    transfer_instructions: Vec<Instruction>,
}

#[instrument(skip_all)]
async fn transfer_spl20(
    client: &RpcClient,
    sender_keypair: Arc<Keypair>,
    recipient_wallet: &Pubkey,
    token_mint: &Pubkey,
    amount: u64,
) -> Result<TransferSPL20Instructions> {
    let sender_wallet = &sender_keypair.pubkey();
    let sender_token_account = get_associated_token_address(sender_wallet, token_mint);
    let recipient_token_account = get_associated_token_address(recipient_wallet, token_mint);

    if client.get_account(&sender_token_account).await.is_err() {
        tracing::error!("Sender's associated token account does not exist");
        return Err(Error::Message(
            "Sender's associated token account does not exist".into(),
        ));
    }

    let mut setup_instructions: Vec<Instruction> = vec![];
    if client.get_account(&recipient_token_account).await.is_err() {
        let token_program_id = get_token_program_id(client, token_mint).await?;
        setup_instructions.push(instruction::create_associated_token_account_idempotent(
            &sender_keypair.pubkey(),
            recipient_wallet,
            token_mint,
            &token_program_id,
        ));
    }

    let mut transfer_instructions: Vec<Instruction> = vec![];
    let recent_blockhash = client.get_latest_blockhash().await?;
    let transfer_instruction = transfer(
        &spl_token::id(),
        &sender_token_account,
        &recipient_token_account,
        &sender_keypair.pubkey(),
        &[],
        amount,
    )?;
    transfer_instructions.push(transfer_instruction.clone());

    let transaction = Transaction::new_signed_with_payer(
        &[transfer_instruction],
        Some(&sender_keypair.pubkey()),
        &[&*sender_keypair],
        recent_blockhash,
    );

    let simulation_result = client.simulate_transaction(&transaction).await?;
    if simulation_result.value.err.is_some() {
        tracing::error!(
            "Transaction simulation failed: {:?}",
            simulation_result.value.err
        );
        return Err(Error::Message("Transaction simulation failed".into()));
    }

    Ok(TransferSPL20Instructions {
        setup_instructions,
        transfer_instructions,
    })
}

#[instrument(skip_all)]
pub async fn _get_solana_token_decimals(token_address: &str) -> Result<u8> {
    let rpc_url = env::var("SOLANA_RPC").map_err(|e| Error::EnvVar {
        name: "SOLANA_RPC".into(),
        source: e,
    })?;
    let client = reqwest::Client::new();
    let request_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenSupply",
        "params": [
            token_address
        ]
    });

    let response = client
        .post(rpc_url)
        .json(&request_body)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    if let Some(decimals) = response["result"]["value"]["decimals"].as_u64() {
        Ok(decimals as u8)
    } else {
        Err(Error::Message("Token information not available.".into()))
    }
}

#[instrument(skip_all)]
async fn get_token_program_id(rpc_client: &RpcClient, token_mint: &Pubkey) -> Result<Pubkey> {
    let mint_account = rpc_client
        .get_account(token_mint)
        .await
        .map_err(|e| Error::with_context("Failed to get token mint account", e))?;

    if mint_account.owner == spl_token_2022::ID {
        Ok(spl_token_2022::ID)
    } else if mint_account.owner == spl_token::ID {
        Ok(spl_token::ID)
    } else {
        Err(Error::Message(
            "Token mint is not owned by Token or Token2022 program".into(),
        ))
    }
}

#[instrument(skip_all)]
pub async fn solana_simulate_swap(
    dst_chain_user: &str,
    token_in: &str,
    mut token_out: &str,
    amount_in: u64,
) -> String {
    if token_out == system_program::ID.to_string() {
        token_out = WSOL_ADDRESS;
    }

    let memo_json = json!({
        "user_account": dst_chain_user,
        "token_in": token_in,
        "token_out": token_out,
        "amount": amount_in,
        "slippage_bps": 100
    });

    let memo = match Jup_Memo::from_json(&memo_json.to_string()) {
        Ok(memo) => memo,
        Err(_) => return "0".to_string(),
    };

    let quote_config = QuoteConfig {
        only_direct_routes: false,
        swap_mode: Some(SwapMode::ExactIn),
        slippage_bps: Some(memo.slippage_bps),
        ..QuoteConfig::default()
    };

    let quotes = match quote(memo.token_in, memo.token_out, memo.amount, quote_config).await {
        Ok(quotes) => quotes,
        Err(_) => return "0".to_string(),
    };

    BigInt::from(quotes.out_amount).to_string()
}

#[derive(Debug, Default)]
pub struct SendFundsToUserInstructions {
    pub setup_instructions: Vec<Instruction>,
    pub send_funds_to_user_instructions: Vec<Instruction>,
}

#[allow(clippy::too_many_arguments)]
#[instrument(skip_all)]
pub async fn solana_send_funds_to_user(
    ctx: Context,
    intent_id: &str,
    token_in_mint: &str,
    token_out_mint: &str,
    user: &str,
    solver_out: String,
    single_domain: bool,
    rpc_url: &str,
    program_id: Pubkey,
    amount_out_cross_chain: u64,
) -> Result<SendFundsToUserInstructions> {
    let solver_keypair = Arc::new(Keypair::from_base58_string(&ctx.envvars.solana_key));

    // Clone the necessary variables for the task
    let solver_clone = Arc::clone(&solver_keypair);
    let intent_id = intent_id.to_string();
    let token_in_mint = Pubkey::from_str(token_in_mint).map_err(|e| Error::ParsePubkey {
        name: "token_in_mint".into(),
        source: e,
    })?;
    let token_out_mint = Pubkey::from_str(token_out_mint).map_err(|e| Error::ParsePubkey {
        name: "token_out_mint".into(),
        source: e,
    })?;
    let user = Pubkey::from_str(user).map_err(|e| Error::ParsePubkey {
        name: "user".into(),
        source: e,
    })?;

    let rpc_client =
        RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());

    let solver_token_out_ata = get_associated_token_address(
        &user, // careful with cross-chain
        &token_out_mint,
    );

    let mut sftu_instructions = SendFundsToUserInstructions::default();

    if single_domain {
        let solver_token_in_ata =
            get_associated_token_address(&solver_clone.pubkey(), &token_in_mint);

        if rpc_client.get_account(&solver_token_in_ata).await.is_err() {
            let token_program_id = get_token_program_id(&rpc_client, &token_in_mint).await?;
            sftu_instructions.setup_instructions.push(
                instruction::create_associated_token_account_idempotent(
                    &solver_keypair.pubkey(),
                    &solver_clone.pubkey(),
                    &token_in_mint,
                    &token_program_id,
                ),
            );
        }
    }

    if rpc_client.get_account(&solver_token_out_ata).await.is_err() {
        let token_program_id = get_token_program_id(&rpc_client, &token_out_mint).await?;
        sftu_instructions.setup_instructions.push(
            instruction::create_associated_token_account_idempotent(
                &solver_keypair.pubkey(),
                &user,
                &token_out_mint,
                &token_program_id,
            ),
        );
    }

    // Spawn a blocking task to construct the transaction instructions
    sftu_instructions.send_funds_to_user_instructions = tokio::task::block_in_place(|| {
        let client = anchor_client::Client::new_with_options(
            Cluster::Custom(rpc_url.to_string(), rpc_url.to_string()),
            solver_clone.clone(),
            CommitmentConfig::processed(),
        );

        let program = client
            .program(program_id)
            .map_err(|e| Error::with_context("Failed to access bridge_escrow program", e))?;

        let user_token_out_addr = get_associated_token_address(&user, &token_out_mint);

        let intent_state =
            Pubkey::find_program_address(&[b"intent", intent_id.as_bytes()], &program_id).0;

        let auctioneer_state = Pubkey::find_program_address(&[b"auctioneer"], &program_id).0;

        let solver_token_out_addr =
            get_associated_token_address(&solver_clone.pubkey(), &token_out_mint);

        let (_storage, _bump_storage) =
            Pubkey::find_program_address(&[solana_ibc::SOLANA_IBC_STORAGE_SEED], &solana_ibc::ID);

        let (_trie, _bump_trie) =
            Pubkey::find_program_address(&[solana_ibc::TRIE_SEED], &solana_ibc::ID);

        let (_chain, _bump_chain) =
            Pubkey::find_program_address(&[solana_ibc::CHAIN_SEED], &solana_ibc::ID);

        let (_mint_authority, _bump_mint_authority) =
            Pubkey::find_program_address(&[solana_ibc::MINT_ESCROW_SEED], &solana_ibc::ID);

        let _dummy_token_mint = Pubkey::find_program_address(&[b"dummy"], &program_id).0;

        let _hashed_full_denom =
            lib::hash::CryptoHash::digest(_dummy_token_mint.to_string().as_bytes());

        let (_escrow_account, _bump_escrow_account) = Pubkey::find_program_address(
            &[solana_ibc::ESCROW, _hashed_full_denom.as_slice()],
            &solana_ibc::ID,
        );

        let _receiver_token_account =
            get_associated_token_address(&solver_keypair.pubkey(), &_dummy_token_mint);

        let (_fee_collector, _bump_fee_collector) =
            Pubkey::find_program_address(&[solana_ibc::FEE_SEED], &solana_ibc::ID);

        let storage;
        let trie;
        let chain;
        let mint_authority;
        let dummy_token_mint = Some(_dummy_token_mint);
        let escrow_account;
        let receiver_token_account;
        let fee_collector;

        if !single_domain {
            storage = Some(_storage);
            trie = Some(_trie);
            chain = Some(_chain);
            mint_authority = Some(_mint_authority);
            escrow_account = Some(_escrow_account);
            receiver_token_account = Some(_receiver_token_account);
            fee_collector = Some(_fee_collector);

            program
                .request()
                .instruction(ComputeBudgetInstruction::set_compute_unit_limit(1_000_000))
                .instruction(ComputeBudgetInstruction::request_heap_frame(128 * 1024))
                .accounts(bridge_escrow::accounts::SplTokenTransferCrossChain {
                    auctioneer_state,
                    solver: solver_clone.pubkey(),
                    auctioneer: AUCTIONEER_ADDRESS,
                    token_in: None,
                    token_out: token_out_mint,
                    auctioneer_token_in_account: None,
                    solver_token_in_account: None,
                    solver_token_out_account: solver_token_out_addr,
                    user_token_out_account: user_token_out_addr,
                    token_program: anchor_spl::token::ID,
                    associated_token_program: anchor_spl::associated_token::ID,
                    system_program: anchor_lang::solana_program::system_program::ID,
                    ibc_program: Some(solana_ibc::ID),
                    receiver: Some(user),
                    storage,
                    trie,
                    chain,
                    mint_authority,
                    token_mint: dummy_token_mint,
                    escrow_account,
                    receiver_token_account,
                    fee_collector,
                })
                .args(bridge_escrow::instruction::SendFundsToUserCrossChain {
                    intent_id: intent_id.clone(),
                    amount_out: amount_out_cross_chain,
                    solver_out: solver_out.clone(),
                })
                .payer(solver_clone.clone())
                .instructions()
                .map_err(|e| {
                    Error::with_context(
                        "Failed to create instructions for SendFundsToUserCrossChain",
                        e,
                    )
                })
        } else {
            storage = Some(_storage);
            trie = Some(_trie);
            chain = Some(_chain);
            mint_authority = Some(_mint_authority);
            escrow_account = Some(_escrow_account);
            receiver_token_account = Some(_receiver_token_account);
            fee_collector = Some(_fee_collector);
            let receiver = Some(user);
            let token_in_escrow_addr =
                get_associated_token_address(&auctioneer_state, &token_in_mint);
            let solver_token_in_addr =
                get_associated_token_address(&solver_clone.pubkey(), &token_in_mint);
            let auctioneer_token_in_account = Some(token_in_escrow_addr);
            let solver_token_in_account = Some(solver_token_in_addr);

            program
                .request()
                .instruction(ComputeBudgetInstruction::set_compute_unit_limit(1_000_000))
                .instruction(ComputeBudgetInstruction::request_heap_frame(128 * 1024))
                .accounts(bridge_escrow::accounts::SplTokenTransfer {
                    solver: solver_clone.pubkey(),
                    intent: Some(intent_state),
                    intent_owner: receiver.unwrap(),
                    auctioneer_state,
                    auctioneer: AUCTIONEER_ADDRESS,
                    token_in: Some(token_in_mint),
                    token_out: token_out_mint,
                    auctioneer_token_in_account,
                    solver_token_in_account,
                    solver_token_out_account: solver_token_out_addr,
                    user_token_out_account: user_token_out_addr,
                    token_program: anchor_spl::token::ID,
                    associated_token_program: anchor_spl::associated_token::ID,
                    system_program: anchor_lang::solana_program::system_program::ID,
                    ibc_program: Some(solana_ibc::ID),
                    receiver,
                    storage,
                    trie,
                    chain,
                    mint_authority,
                    token_mint: dummy_token_mint,
                    escrow_account,
                    receiver_token_account,
                    fee_collector,
                })
                .args(bridge_escrow::instruction::SendFundsToUser {
                    intent_id: intent_id.to_string(),
                })
                .payer(solver_clone.clone())
                .instructions()
                .map_err(|e| {
                    Error::with_context("Failed to create instructions for SendFundsToUser", e)
                })
        }
    })?;
    Ok(sftu_instructions)
}

#[instrument(skip_all)]
pub async fn submit(
    rpc_client: &RpcClient,
    fee_payer: Arc<Keypair>,
    instructions: Vec<Instruction>,
    jito_tip: u64,
) -> Result<Signature> {
    let tx_send_method: TxSendMethod = match SUBMIT_THROUGH_JITO.load(Ordering::Relaxed) {
        true => TxSendMethod::JITO,
        false => TxSendMethod::RPC,
    };
    match tx_send_method {
        TxSendMethod::JITO => {
            submit_through_jito(rpc_client, fee_payer, vec![], vec![instructions], jito_tip)
                .await
                .map(|signatures| signatures.first().cloned().unwrap())
        }
        TxSendMethod::RPC => submit_default(rpc_client, fee_payer, instructions, true).await,
    }
}

#[instrument(skip_all)]
pub async fn submit_default(
    rpc_client: &RpcClient,
    fee_payer: Arc<Keypair>,
    instructions: Vec<Instruction>,
    legacy_transaction: bool,
) -> Result<Signature> {
    let mut retries = 0;
    loop {
        let send_result;
        if legacy_transaction {
            let transaction = Transaction::new_signed_with_payer(
                &instructions,
                Some(&fee_payer.pubkey()),
                &[&*fee_payer],
                rpc_client.get_latest_blockhash().await?,
            );

            send_result = rpc_client
                .send_and_confirm_transaction_with_spinner(&transaction)
                .await;
        } else {
            let message = v0::Message::try_compile(
                &fee_payer.pubkey(),
                &instructions,
                &[],
                rpc_client.get_latest_blockhash().await?,
            )?;

            let transaction =
                VersionedTransaction::try_new(VersionedMessage::V0(message), &[&fee_payer])?;

            send_result = rpc_client
                .send_and_confirm_transaction_with_spinner(&transaction)
                .await;
        }

        match send_result {
            Ok(signature) => return Ok(signature),
            Err(error) if error.to_string().contains("unable to confirm transaction") => {
                if retries == MAX_RETRIES {
                    return Err(Error::with_context(
                        "Reached maximum retries for transaction",
                        error,
                    ));
                }
                tracing::error!("Sending transaction failed: {}", error);
                tracing::error!(
                    "Retrying transaction {} more time(s)",
                    MAX_RETRIES - retries
                );
                retries += 1;
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(error) => {
                return Err(Error::with_context(
                    "Transaction failed due to a non-retryable error",
                    error,
                ));
            }
        }
    }
}

#[instrument(skip_all)]
pub async fn submit_through_jito(
    rpc_client: &RpcClient,
    fee_payer: Arc<Keypair>,
    setup_instructions: Vec<Instruction>,
    bundle_instructions: Vec<Vec<Instruction>>,
    jito_tip: u64,
) -> Result<Vec<Signature>> {
    let recent_blockhash = rpc_client.get_latest_blockhash().await?;

    let mut setup_with_tip_instructions = setup_instructions.clone();

    let tip_instruction =
        system_instruction::transfer(&fee_payer.pubkey(), &JITO_ADDRESS, jito_tip);

    setup_with_tip_instructions.push(tip_instruction);

    let setup_with_tip_message = v0::Message::try_compile(
        &fee_payer.pubkey(),
        &setup_with_tip_instructions,
        &[],
        recent_blockhash,
    )?;

    let setup_with_tip_transaction =
        VersionedTransaction::try_new(VersionedMessage::V0(setup_with_tip_message), &[&fee_payer])?;

    let mut bundle_transactions: Vec<VersionedTransaction> = vec![setup_with_tip_transaction];

    // Create a VersionedTransaction from each instruction group in the bundle.
    for instructions in bundle_instructions.iter() {
        let message =
            v0::Message::try_compile(&fee_payer.pubkey(), instructions, &[], recent_blockhash)?;
        let transaction =
            VersionedTransaction::try_new(VersionedMessage::V0(message), &[&fee_payer])?;
        bundle_transactions.push(transaction);
    }

    let mut client =
        jito_searcher_client::get_searcher_client(JITO_BLOCK_ENGINE_URL, &fee_payer).await?;

    let mut bundle_results_subscription = client
        .subscribe_bundle_results(SubscribeBundleResultsRequest {})
        .await
        .map_err(|e| Error::with_context("Failed to subscribe to bundle results", e))?
        .into_inner();

    let jito_bundle_result = if bundle_transactions.len() > 5 {
        Err(Error::Message("Bundle has more than 5 transactions".into()))
    } else {
        let mut bundle_tx_signtures: Vec<Signature> = vec![];
        bundle_transactions
            .iter()
            .for_each(|tx| bundle_tx_signtures.extend(tx.signatures.clone()));
        tracing::info!(
            "Sending Jito bundle with {} transactions: {:?}",
            bundle_transactions.len(),
            bundle_tx_signtures
        );

        jito_searcher_client::send_bundle_with_confirmation(
            &bundle_transactions,
            rpc_client,
            &mut client,
            &mut bundle_results_subscription,
        )
        .await
        .map_err(|e| Error::Message(e.to_string()))
    };

    match jito_bundle_result {
        Err(error) => {
            tracing::error!("Failed to send the Jito bundle: {error}");
            let mut rpc_signatures: Vec<Signature> = vec![];
            for (i, tx_instructions) in bundle_instructions.iter().enumerate() {
                tracing::info!(
                    "Sending transaction {} of {} via RPC",
                    i + 1,
                    bundle_instructions.len()
                );
                let signature = submit_default(
                    rpc_client,
                    fee_payer.clone(),
                    tx_instructions.to_vec(),
                    false,
                )
                .await
                .map_err(|e| {
                    Error::Message(format!(
                        "Failed to submit transaction {} of {} via RPC: {e}",
                        i + 1,
                        bundle_instructions.len()
                    ))
                })?;
                rpc_signatures.push(signature);
            }
            Ok(rpc_signatures)
        }
        Ok(jito_signatures) => Ok(jito_signatures),
    }
}

#[instrument(skip_all)]
async fn send_tx_hash_to_auctioneer(auctioneer_url: &str, tx_hash: Signature) -> Result<()> {
    let response = reqwest::Client::new()
        .post(format!("{auctioneer_url}/solana_tx_proof"))
        .body(tx_hash.to_string())
        .send()
        .await?;
    tracing::info!("Auctioneer response: {}", response.status());
    Ok(())
}
