pub mod solana_chain {
    use crate::chains::*;
    use crate::routers::jupiter::create_token_account;
    use crate::routers::jupiter::jupiter_swap;
    use crate::routers::jupiter::quote;
    use crate::routers::jupiter::Memo as Jup_Memo;
    use crate::routers::jupiter::QuoteConfig;
    use crate::routers::jupiter::SwapMode;
    use crate::PostIntentInfo;
    use anchor_client::Cluster;
    use num_bigint::BigInt;
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use solana_client::nonblocking::rpc_client::RpcClient;
    use solana_client::rpc_config::RpcSendTransactionConfig;
    use solana_sdk::commitment_config::CommitmentConfig;
    use solana_sdk::pubkey::Pubkey;
    use solana_sdk::signature::{Keypair, Signer};
    use solana_sdk::transaction::Transaction;
    use spl_associated_token_account::get_associated_token_address;
    use spl_token::instruction::transfer;
    use std::env;
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::task::spawn_blocking;

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

    pub async fn solana_executing(intent: PostIntentInfo, amount: &str) -> Result<(), String> {
        let rpc_url = env::var("SOLANA_RPC").map_err(|_| "SOLANA_RPC must be set".to_string())?;

        let from_keypair_str =
            env::var("SOLANA_KEYPAIR").map_err(|_| "SOLANA_KEYPAIR must be set".to_string())?;
        let from_keypair = Keypair::from_base58_string(&from_keypair_str);

        let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

        match intent.function_name.as_str() {
            "transfer" => {
                let mut user_account = String::default();
                let mut token_out = String::default();
                let mut parsed_amount = 0u64;

                if let OperationOutput::SwapTransfer(transfer_output) = &intent.outputs {
                    user_account = transfer_output.dst_chain_user.clone();
                    token_out = transfer_output.token_out.clone();
                    parsed_amount = transfer_output
                        .amount_out
                        .parse::<u64>()
                        .map_err(|e| format!("Failed to parse amount_out: {}", e))?;
                }

                transfer_slp20(
                    &client,
                    &from_keypair,
                    &Pubkey::from_str(&user_account)
                        .map_err(|e| format!("Invalid user_account pubkey: {}", e))?,
                    &Pubkey::from_str(&token_out)
                        .map_err(|e| format!("Invalid token_out pubkey: {}", e))?,
                    parsed_amount,
                )
                .await
                .map_err(|err| format!("Transaction failed: {}", err))?;
            }
            "swap" => {
                let mut token_out = String::default();

                if let OperationOutput::SwapTransfer(transfer_output) = &intent.outputs {
                    token_out = transfer_output.token_out.clone();
                }

                let memo = format!(
                    r#"{{"user_account": "{}","token_in": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB","token_out": "{}","amount": {},"slippage_bps": {}}}"#,
                    SOLVER_ADDRESSES.get(1).unwrap(),
                    token_out,
                    amount,
                    100
                );

                jupiter_swap(&memo, &client, &from_keypair, SwapMode::ExactOut)
                    .await
                    .map_err(|err| format!("Swap failed: {}", err))?;
            }
            _ => {
                return Err("Function not supported".to_string());
            }
        };

        Ok(())
    }

    async fn transfer_slp20(
        client: &RpcClient,
        sender_keypair: &Keypair,
        recipient_wallet_pubkey: &Pubkey,
        token_mint_pubkey: &Pubkey,
        amount: u64,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let sender_wallet_pubkey = &sender_keypair.pubkey();
        let sender_token_account_pubkey =
            get_associated_token_address(sender_wallet_pubkey, token_mint_pubkey);
        let recipient_token_account_pubkey =
            get_associated_token_address(recipient_wallet_pubkey, token_mint_pubkey);

        if client
            .get_account(&sender_token_account_pubkey)
            .await
            .is_err()
        {
            eprintln!("Sender's associated token account does not exist");
            return Err("Sender's associated token account does not exist".into());
        }

        if client
            .get_account(&recipient_token_account_pubkey)
            .await
            .is_err()
        {
            create_token_account(
                recipient_wallet_pubkey,
                token_mint_pubkey,
                sender_keypair,
                client,
            )
            .await
            .unwrap();
        }

        let recent_blockhash = client.get_latest_blockhash().await.unwrap();
        let transfer_instruction = transfer(
            &spl_token::id(),
            &sender_token_account_pubkey,
            &recipient_token_account_pubkey,
            &sender_keypair.pubkey(),
            &[],
            amount,
        )
        .unwrap();

        let transaction = Transaction::new_signed_with_payer(
            &[transfer_instruction],
            Some(&sender_keypair.pubkey()),
            &[sender_keypair],
            recent_blockhash,
        );

        let simulation_result = client.simulate_transaction(&transaction).await.unwrap();
        if simulation_result.value.err.is_some() {
            eprintln!(
                "Transaction simulation failed: {:?}",
                simulation_result.value.err
            );
            return Err("Transaction simulation failed".into());
        }

        let result = client
            .send_and_confirm_transaction_with_spinner(&transaction)
            .await?;

        Ok(result.to_string())
    }

    pub async fn _get_solana_token_decimals(
        token_address: &str,
    ) -> Result<u8, Box<dyn std::error::Error>> {
        let rpc_url = env::var("SOLANA_RPC").expect("SOLANA_RPC must be set");
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
            Err("Token information not available.".into())
        }
    }

    pub async fn solana_simulate_swap(
        dst_chain_user: &str,
        token_in: &str,
        token_out: &str,
        amount_in: u64,
    ) -> String {
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

    pub async fn solana_send_funds_to_user(
        intent_id: &str,
        token_in_mint: &str,
        token_out_mint: &str,
        user: &str,
        single_domain: bool,
    ) -> Result<(), String> {
        // Load the keypair from environment variable
        let solana_keypair = env::var("SOLANA_KEYPAIR")
            .map_err(|e| format!("Failed to read SOLANA_KEYPAIR from environment: {}", e))?;

        let solver = Arc::new(Keypair::from_base58_string(&solana_keypair));

        // Clone the necessary variables for the task
        let solver_clone = Arc::clone(&solver);
        let intent_id = intent_id.to_string();
        let token_in_mint = token_in_mint.to_string();
        let token_out_mint = token_out_mint.to_string();
        let user = user.to_string();

        // Spawn a blocking task to execute the transaction
        spawn_blocking(move || {
            let client = anchor_client::Client::new_with_options(
                Cluster::Mainnet,
                solver_clone.clone(),
                CommitmentConfig::processed(),
            );

            let program = client
                .program(bridge_escrow::ID)
                .map_err(|e| format!("Failed to access bridge_escrow program: {}", e))?;

            if single_domain {
                let solver_token_in_addr = get_associated_token_address(
                    &solver_clone.pubkey(),
                    &Pubkey::from_str(&token_in_mint)
                        .map_err(|e| format!("Invalid token_in_mint pubkey: {}", e))?,
                );
                let user_token_out_addr = get_associated_token_address(
                    &Pubkey::from_str(&user).map_err(|e| format!("Invalid user pubkey: {}", e))?,
                    &Pubkey::from_str(&token_out_mint)
                        .map_err(|e| format!("Invalid token_out_mint pubkey: {}", e))?,
                );

                let intent_state = Pubkey::find_program_address(
                    &[b"intent", intent_id.as_bytes()],
                    &bridge_escrow::ID,
                )
                .0;

                let auctioneer_state =
                    Pubkey::find_program_address(&[b"auctioneer"], &bridge_escrow::ID).0;

                let token_in_escrow_addr = get_associated_token_address(
                    &auctioneer_state,
                    &Pubkey::from_str(&token_in_mint)
                        .map_err(|e| format!("Invalid token_in_mint pubkey: {}", e))?,
                );

                let solver_token_out_addr = get_associated_token_address(
                    &solver_clone.pubkey(),
                    &Pubkey::from_str(&token_out_mint)
                        .map_err(|e| format!("Invalid token_out_mint pubkey: {}", e))?,
                );

                program
                    .request()
                    .accounts(bridge_escrow::accounts::SplTokenTransfer {
                        solver: solver_clone.pubkey(),
                        intent: intent_state,
                        auctioneer_state,
                        auctioneer: Pubkey::from_str(
                            "CwmS7F8wL2Q54Kggd217Jj7BnbxaQFo7rmpFGi6QibDW",
                        )
                        .map_err(|e| format!("Invalid auctioneer pubkey: {}", e))?,
                        token_in: Pubkey::from_str(&token_in_mint)
                            .map_err(|e| format!("Invalid token_in_mint pubkey: {}", e))?,
                        token_out: Pubkey::from_str(&token_out_mint)
                            .map_err(|e| format!("Invalid token_out_mint pubkey: {}", e))?,
                        auctioneer_token_in_account: token_in_escrow_addr,
                        solver_token_in_account: solver_token_in_addr,
                        solver_token_out_account: solver_token_out_addr,
                        user_token_out_account: user_token_out_addr,
                        token_program: anchor_spl::token::ID,
                        associated_token_program: anchor_spl::associated_token::ID,
                        system_program: anchor_lang::solana_program::system_program::ID,
                        ibc_program: None,
                        receiver: None,
                        storage: None,
                        trie: None,
                        chain: None,
                        mint_authority: None,
                        token_mint: None,
                        escrow_account: None,
                        receiver_token_account: None,
                        fee_collector: None,
                    })
                    .args(bridge_escrow::instruction::SendFundsToUser {
                        intent_id: intent_id.to_string(),
                        hashed_full_denom: None,
                        solver_out: None,
                    })
                    .payer(solver_clone.clone())
                    .signer(&*solver_clone)
                    .send_with_spinner_and_config(RpcSendTransactionConfig {
                        skip_preflight: true,
                        ..Default::default()
                    })
                    .map_err(|e| format!("Transaction failed: {}", e))
                    .map(|_| ()) // Map the Signature result to ()
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|e| format!("Task failed: {:?}", e))?
    }
}
