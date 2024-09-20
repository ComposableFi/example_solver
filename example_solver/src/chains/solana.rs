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
    use solana_sdk::compute_budget::ComputeBudgetInstruction;

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

    pub async fn handle_solana_execution(
        intent: &PostIntentInfo,
        intent_id: &str,
        amount: &str,
    ) -> Result<(), String> {
        let from_keypair = Keypair::from_base58_string(
            env::var("SOLANA_KEYPAIR")
                .expect("SOLANA_KEYPAIR must be set")
                .as_str(),
        );
        let rpc_url = env::var("SOLANA_RPC").expect("SOLANA_RPC must be set");
        let client = RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());

        let usdt_contract_address = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

        let usdt_token_account = get_associated_token_address(
            &from_keypair.pubkey(),
            &Pubkey::from_str(usdt_contract_address).unwrap(),
        );

        let balance_ant = client
            .get_token_account_balance(&usdt_token_account)
            .await
            .map_err(|e| format!("Failed to get token account balance: {}", e))?
            .ui_amount
            .unwrap();

        let mut user_account = String::default();
        let mut token_in = String::default();
        let mut token_out = String::default();
        let mut amount_in = String::default();

        if let OperationOutput::SwapTransfer(transfer_output) = &intent.outputs {
            user_account = transfer_output.dst_chain_user.clone();
            token_out = transfer_output.token_out.clone();
        }
        if let OperationInput::SwapTransfer(transfer_input) = &intent.inputs {
            token_in = transfer_input.token_in.clone();
            amount_in = transfer_input.amount_in.clone();
        }

        let mut ok = true;
        if token_out != usdt_contract_address {
            if let Err(e) = solana_trasnfer_swap(intent.clone(), amount).await {
                println!(
                    "Error occurred on Solana swap USDT -> token_out (manual swap required): {}",
                    e
                );
                ok = false;
            }
        }

        if ok {
            if let Err(e) = solana_send_funds_to_user(
                intent_id,
                &token_in,
                &token_out,
                &user_account,
                SOLVER_ADDRESSES.get(1).unwrap().to_string(),
                intent.src_chain == intent.dst_chain,
                rpc_url,
                Pubkey::from_str("yAJJJMZmjWSQjvq8WuARKygH8KJkeQTXB5BGJBJcR4T").unwrap(),
            )
            .await
            {
                println!(
                    "Error occurred on send token_out -> user & user sends token_in -> solver: {}",
                    e
                );
            } else if token_in != usdt_contract_address {
                let memo = format!(
                    r#"{{"user_account": "{}","token_in": "{}","token_out": "{}","amount": {},"slippage_bps": {}}}"#,
                    SOLVER_ADDRESSES.get(1).unwrap(),
                    token_in,
                    usdt_contract_address,
                    amount_in,
                    100
                );

                if let Err(e) = jupiter_swap(&memo, &client, &from_keypair, SwapMode::ExactIn).await
                {
                    println!("Error on Solana swap token_in -> USDT: {e}");
                } else {
                    let balance_post = client
                        .get_token_account_balance(&usdt_token_account)
                        .await
                        .unwrap()
                        .ui_amount
                        .unwrap();

                    let balance = if balance_post >= balance_ant {
                        balance_post - balance_ant
                    } else {
                        balance_ant - balance_post
                    };

                    println!(
                        "You have {} {} USDT on intent {intent_id}",
                        if balance_post >= balance_ant {
                            "won"
                        } else {
                            "lost"
                        },
                        balance
                    );
                }
            }
        }

        Ok(())
    }

    pub async fn solana_trasnfer_swap(intent: PostIntentInfo, amount: &str) -> Result<(), String> {
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
        solver_out: String,
        single_domain: bool,
        rpc_url: String,
        program_id: Pubkey,
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

        let rpc_client = RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());
        let solver_token_in_addr = get_associated_token_address(
            &solver_clone.pubkey(),
            &Pubkey::from_str(&token_in_mint).unwrap(),
        );

        if rpc_client
            .get_token_account_balance(&solver_token_in_addr)
            .await
            .is_err()
        {
            if let Err(e) = create_token_account(
                &solver_clone.pubkey(),
                &Pubkey::from_str(&token_in_mint).unwrap(),
                &solver,
                &rpc_client,
            )
            .await
            {
                eprintln!("Failed to create token account: {}", e);
            }
        }

        // Spawn a blocking task to execute the transaction
        tokio::task::spawn_blocking(move || {
            let client = anchor_client::Client::new_with_options(
                Cluster::Custom(rpc_url.clone(), rpc_url),
                solver_clone.clone(),
                CommitmentConfig::processed(),
            );

            let program = client
                .program(program_id)
                .map_err(|e| format!("Failed to access bridge_escrow program: {}", e))?;

            let user_token_out_addr = get_associated_token_address(
                &Pubkey::from_str(&user).map_err(|e| format!("Invalid user pubkey: {}", e))?,
                &Pubkey::from_str(&token_out_mint)
                    .map_err(|e| format!("Invalid token_out_mint pubkey: {}", e))?,
            );

            let intent_state =
                Pubkey::find_program_address(&[b"intent", intent_id.as_bytes()], &program_id).0;

            let auctioneer_state = Pubkey::find_program_address(&[b"auctioneer"], &program_id).0;

            let solver_token_out_addr = get_associated_token_address(
                &solver_clone.pubkey(),
                &Pubkey::from_str(&token_out_mint)
                    .map_err(|e| format!("Invalid token_out_mint pubkey: {}", e))?,
            );

            let solana_ibc_id =
                Pubkey::from_str("2HLLVco5HvwWriNbUhmVwA2pCetRkpgrqwnjcsZdyTKT").unwrap();

            let (_storage, _bump_storage) = Pubkey::find_program_address(
                &[solana_ibc::SOLANA_IBC_STORAGE_SEED],
                &solana_ibc_id,
            );

            let (_trie, _bump_trie) =
                Pubkey::find_program_address(&[solana_ibc::TRIE_SEED], &solana_ibc_id);

            let (_chain, _bump_chain) =
                Pubkey::find_program_address(&[solana_ibc::CHAIN_SEED], &solana_ibc_id);

            let (_mint_authority, _bump_mint_authority) =
                Pubkey::find_program_address(&[solana_ibc::MINT_ESCROW_SEED], &solana_ibc_id);

            let _dummy_token_mint = Pubkey::find_program_address(&[b"dummy"], &program_id).0;

            let _hashed_full_denom =
                lib::hash::CryptoHash::digest(&_dummy_token_mint.to_string().as_bytes());

            let (_escrow_account, _bump_escrow_account) = Pubkey::find_program_address(
                &[solana_ibc::ESCROW, &_hashed_full_denom.as_slice()],
                &solana_ibc_id,
            );

            let _receiver_token_account =
                get_associated_token_address(&solver.pubkey(), &_dummy_token_mint);

            let (_fee_collector, _bump_fee_collector) =
                Pubkey::find_program_address(&[solana_ibc::FEE_SEED], &solana_ibc_id);

            let auctioneer_token_in_account;
            let solver_token_in_account;
            let token_in;
            let mut ibc_program = None;
            let mut receiver = None;
            let mut storage = None;
            let mut trie = None;
            let mut chain = None;
            let mut mint_authority = None;
            let dummy_token_mint = Some(Pubkey::from_str("3dsg7C6LGnCL17i4a4qU5N3n6RsKR7AFpVUyRc1hToAQ").unwrap());
            let mut escrow_account = None;
            let mut receiver_token_account = None;
            let mut fee_collector = None;
            let mut hashed_full_denom = None;

            if !single_domain {
                token_in = None;
                auctioneer_token_in_account = None;
                solver_token_in_account = None;
                ibc_program = Some(solana_ibc_id);
                receiver = Some(
                    Pubkey::from_str(&user).map_err(|e| format!("Invalid user pubkey: {}", e))?,
                );
                storage = Some(_storage);
                trie = Some(_trie);
                chain = Some(_chain);
                mint_authority = Some(_mint_authority);
                escrow_account = Some(_escrow_account);
                receiver_token_account = Some(_receiver_token_account);
                fee_collector = Some(_fee_collector);
                hashed_full_denom = Some(_hashed_full_denom);
            } else {
                token_in = Some(Pubkey::from_str(&token_in_mint).unwrap());

                let token_in_escrow_addr =
                    get_associated_token_address(&auctioneer_state, &token_in.unwrap());

                auctioneer_token_in_account = Some(token_in_escrow_addr);
                solver_token_in_account = Some(solver_token_in_addr);

                ibc_program = Some(solana_ibc_id);
                receiver = Some(
                    Pubkey::from_str(&user).map_err(|e| format!("Invalid user pubkey: {}", e))?,
                );
                storage = Some(_storage);
                trie = Some(_trie);
                chain = Some(_chain);
                mint_authority = Some(_mint_authority);
                escrow_account = Some(_escrow_account);
                receiver_token_account = Some(_receiver_token_account);
                fee_collector = Some(_fee_collector);
                hashed_full_denom = Some(_hashed_full_denom);
            }

            program
                .request()
                .instruction(ComputeBudgetInstruction::set_compute_unit_limit(1_000_000))
                .instruction(ComputeBudgetInstruction::request_heap_frame(128 * 1024))
                .accounts(bridge_escrow::accounts::SplTokenTransfer {
                    intent: intent_state,
                    auctioneer_state,
                    solver: solver_clone.pubkey(),
                    auctioneer: Pubkey::from_str("5zCZ3jk8EZnJyG7fhDqD6tmqiYTLZjik5HUpGMnHrZfC")
                        .map_err(|e| format!("Invalid auctioneer pubkey: {}", e))?,
                    token_in: token_in,
                    token_out: Pubkey::from_str(&token_out_mint)
                        .map_err(|e| format!("Invalid token_out_mint pubkey: {}", e))?,
                    auctioneer_token_in_account: auctioneer_token_in_account,
                    solver_token_in_account: solver_token_in_account,
                    solver_token_out_account: solver_token_out_addr,
                    user_token_out_account: user_token_out_addr,
                    token_program: anchor_spl::token::ID,
                    associated_token_program: anchor_spl::associated_token::ID,
                    system_program: anchor_lang::solana_program::system_program::ID,
                    ibc_program: ibc_program,
                    receiver: receiver,
                    storage: storage,
                    trie: trie,
                    chain: chain,
                    mint_authority: mint_authority,
                    token_mint: dummy_token_mint,
                    escrow_account: escrow_account,
                    receiver_token_account: receiver_token_account,
                    fee_collector: fee_collector,
                })
                .args(bridge_escrow::instruction::SendFundsToUser {
                    intent_id: intent_id.to_string(),
                    hashed_full_denom: hashed_full_denom,
                    solver_out: Some(solver_out),
                })
                .payer(solver_clone.clone())
                .signer(&*solver_clone)
                .send_with_spinner_and_config(RpcSendTransactionConfig {
                    skip_preflight: true,
                    ..Default::default()
                })
                .map_err(|e| format!("Transaction failed: {}", e))
                .map(|_| ()) // Map the Signature result to ()
        })
        .await
        .map_err(|e| format!("Task failed: {:?}", e))?
    }
}
