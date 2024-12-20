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
    use anyhow::anyhow;
    use jito_protos::searcher::SubscribeBundleResultsRequest;
    use num_bigint::BigInt;
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use solana_client::rpc_config::RpcSendTransactionConfig;
    use solana_sdk::commitment_config::CommitmentConfig;
    use solana_sdk::compute_budget::ComputeBudgetInstruction;
    use solana_sdk::pubkey::Pubkey;
    use solana_sdk::signature::Signature;
    use solana_sdk::signature::{Keypair, Signer};
    use spl_associated_token_account::get_associated_token_address;
    use spl_token::instruction::transfer;
    use std::env;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;
    use strum_macros::{Display, IntoStaticStr};
    use {
        solana_client::nonblocking::rpc_client::RpcClient,
        solana_sdk::{instruction::Instruction, transaction::Transaction},
    };

    pub const JITO_ADDRESS: Pubkey =
        solana_program::pubkey!("96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5");
    pub const JITO_TIP_AMOUNT: u64 = 1200000;
    pub const JITO_BLOCK_ENGINE_URL: &str = "https://mainnet.block-engine.jito.wtf";
    pub const RETRIES: u8 = 5;
    pub static SUBMIT_THROUGH_JITO: AtomicBool = AtomicBool::new(option_env!("JITO").is_some());

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

    pub async fn handle_solana_execution(
        intent: &PostIntentInfo,
        intent_id: &str,
        amount: &str,
    ) -> Result<(), String> {
        let from_keypair = Arc::new(Keypair::from_base58_string(
            env::var("SOLANA_KEYPAIR")
                .expect("SOLANA_KEYPAIR must be set")
                .as_str(),
        ));
        let rpc_url = env::var("SOLANA_RPC").expect("SOLANA_RPC must be set");
        let client = RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());

        let usdt_contract_address = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

        // let usdt_token_account = get_associated_token_address(
        //     &from_keypair.pubkey(),
        //     &Pubkey::from_str(usdt_contract_address).unwrap(),
        // );

        // let balance_ant = client
        //     .get_token_account_balance(&usdt_token_account)
        //     .await
        //     .map_err(|e| format!("Failed to get token account balance: {}", e))?
        //     .ui_amount
        //     .unwrap();

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

        // swap USDT -> token_out
        let token_out_account = get_associated_token_address(
            &from_keypair.pubkey(),
            &Pubkey::from_str(&token_out).unwrap(),
        );

        let balance = client
            .get_token_account_balance(&token_out_account)
            .await
            .map(|result| result.amount)
            .unwrap_or_else(|_| "0".to_string());

        let mut do_swap = false;

        if balance.parse::<u64>().unwrap() < amount.parse::<u64>().unwrap()
            && !token_out.eq_ignore_ascii_case(usdt_contract_address)
        {
            let mut attempts = 0;
            let max_attempts = 5;
            
            while attempts < max_attempts {
                match solana_transfer_swap(intent.clone(), amount).await {
                    Ok(_) => {
                        // Successful execution, exit the loop
                        break;
                    }
                    Err(e) => {
                        attempts += 1;
                        if attempts >= max_attempts {
                            return Err(format!(
                                "Error occurred on Solana swap USDT -> token_out (manual swap required) after {} attempts: {}",
                                attempts, e
                            ));
                        }
                        // Optional: Add a delay before retrying
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                }
            }
            
            do_swap = true;
        }

        let solver_out = if intent.src_chain == "ethereum" {
            SOLVER_ADDRESSES.get(0).unwrap()
        } else if intent.src_chain == "solana" {
            SOLVER_ADDRESSES.get(1).unwrap()
        } else {
            panic!("chain not supported, this should't happen");
        };

        // solver -> token_out -> user | user -> token_in -> solver
        if let Err(e) = solana_send_funds_to_user(
            intent_id,
            &token_in,
            &token_out,
            &user_account,
            solver_out.to_string(),
            intent.src_chain == intent.dst_chain,
            rpc_url,
            Pubkey::from_str(&bridge_escrow::ID.to_string()).unwrap(),
            amount.parse::<u64>().unwrap(),
        )
        .await
        {
            return Err(format!(
                "Error occurred on send token_out -> user & user sends token_in -> solver: {}",
                e
            ));
        }
        // swap token_in -> USDT
        if do_swap
            && intent.src_chain == intent.dst_chain
            && !token_in.eq_ignore_ascii_case(usdt_contract_address)
        {
            let memo = format!(
                r#"{{"user_account": "{}","token_in": "{}","token_out": "{}","amount": {},"slippage_bps": {}}}"#,
                SOLVER_ADDRESSES.get(1).unwrap(),
                token_in,
                usdt_contract_address,
                amount_in,
                100
            );

            sleep(Duration::from_secs(2));
            let mut attempts = 0;
            let max_attempts = 5;
            
            while attempts < max_attempts {
                match jupiter_swap(&memo, &client, from_keypair.clone(), SwapMode::ExactIn).await {
                    Ok(_) => {
                        // Successful execution, exit the loop
                        break;
                    }
                    Err(e) => {
                        attempts += 1;
                        if attempts >= max_attempts {
                            return Err(format!("Error on Solana swap token_in -> USDT after {} attempts: {e}", attempts));
                        }
                        // Optional: Add a delay before retrying
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                }
            }
            
        } else {
            println!("You sent token_out to user for intent_id {intent_id}. You will receive token_in from user on src_chain");
        }

        // if intent.src_chain == intent.dst_chain {
        //     let mut balance_post = client
        //         .get_token_account_balance(&usdt_token_account)
        //         .await
        //         .unwrap()
        //         .ui_amount
        //         .unwrap();

        //     let balance = if balance_post > balance_ant {
        //         balance_post - balance_ant
        //     } else if balance_post < balance_ant {
        //         balance_ant - balance_post
        //     } else {
        //         std::thread::sleep(Duration::from_secs(5));
        //         balance_post = client
        //             .get_token_account_balance(&usdt_token_account)
        //             .await
        //             .unwrap()
        //             .ui_amount
        //             .unwrap();

        //         balance_post - balance_ant
        //     };

        //     println!(
        //         "You have {} {} USDT on intent {intent_id}",
        //         if balance_post >= balance_ant {
        //             "won"
        //         } else {
        //             "lost"
        //         },
        //         balance
        //     );
        // }
        println!("intent {intent_id} solved");

        Ok(())
    }

    pub async fn solana_transfer_swap(intent: PostIntentInfo, amount: &str) -> Result<(), String> {
        let rpc_url = env::var("SOLANA_RPC").map_err(|_| "SOLANA_RPC must be set".to_string())?;

        let from_keypair_str =
            env::var("SOLANA_KEYPAIR").map_err(|_| "SOLANA_KEYPAIR must be set".to_string())?;
        let from_keypair = Arc::new(Keypair::from_base58_string(&from_keypair_str));

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
                    from_keypair.clone(),
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

                jupiter_swap(&memo, &client, from_keypair.clone(), SwapMode::ExactOut)
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
        sender_keypair: Arc<Keypair>,
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
                sender_keypair.clone(),
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
            &[&*sender_keypair],
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
        amount_out_cross_chain: u64,
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

        let rpc_client =
            RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());

        let solver_token_out_addr = get_associated_token_address(
            &Pubkey::from_str(&user).unwrap(), // careful with cross-chain
            &Pubkey::from_str(&token_out_mint).unwrap(),
        );

        if single_domain {
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
                    solver.clone(),
                    &rpc_client,
                )
                .await
                {
                    eprintln!("Failed to create token account: {}", e);
                }
            }
        }

        if rpc_client
            .get_token_account_balance(&solver_token_out_addr)
            .await
            .is_err()
        {
            if let Err(e) = create_token_account(
                &Pubkey::from_str(&user).unwrap(),
                &Pubkey::from_str(&token_out_mint).unwrap(),
                solver.clone(),
                &rpc_client,
            )
            .await
            {
                eprintln!("Failed to create token account: {}", e);
            }
        }

        // Spawn a blocking task to execute the transaction
        let instructions = tokio::task::block_in_place(|| {
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

            let storage;
            let trie;
            let chain;
            let mint_authority;
            let dummy_token_mint = Some(_dummy_token_mint);
            let escrow_account;
            let receiver_token_account;
            let fee_collector;
            let auctioneer =
                Pubkey::from_str("5zCZ3jk8EZnJyG7fhDqD6tmqiYTLZjik5HUpGMnHrZfC").unwrap();

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
                        auctioneer: auctioneer,
                        token_in: None,
                        token_out: Pubkey::from_str(&token_out_mint).unwrap(),
                        auctioneer_token_in_account: None,
                        solver_token_in_account: None,
                        solver_token_out_account: solver_token_out_addr,
                        user_token_out_account: user_token_out_addr,
                        token_program: anchor_spl::token::ID,
                        associated_token_program: anchor_spl::associated_token::ID,
                        system_program: anchor_lang::solana_program::system_program::ID,
                        ibc_program: Some(solana_ibc::ID),
                        receiver: Some(Pubkey::from_str(&user).unwrap()),
                        storage: storage,
                        trie: trie,
                        chain: chain,
                        mint_authority: mint_authority,
                        token_mint: dummy_token_mint,
                        escrow_account: escrow_account,
                        receiver_token_account: receiver_token_account,
                        fee_collector: fee_collector,
                    })
                    .args(bridge_escrow::instruction::SendFundsToUserCrossChain {
                        intent_id: intent_id.clone(),
                        amount_out: amount_out_cross_chain,
                        solver_out: solver_out.clone(),
                    })
                    .payer(solver_clone.clone())
                    .instructions()
                    .map_err(|e| format!("Failed to create instructions: {}", e))
            } else {
                storage = Some(_storage);
                trie = Some(_trie);
                chain = Some(_chain);
                mint_authority = Some(_mint_authority);
                escrow_account = Some(_escrow_account);
                receiver_token_account = Some(_receiver_token_account);
                fee_collector = Some(_fee_collector);
                let receiver = Some(
                    Pubkey::from_str(&user).map_err(|e| format!("Invalid user pubkey: {}", e))?,
                );
                let token_in_escrow_addr = get_associated_token_address(
                    &auctioneer_state,
                    &Pubkey::from_str(&token_in_mint).unwrap(),
                );
                let solver_token_in_addr = get_associated_token_address(
                    &solver_clone.pubkey(),
                    &Pubkey::from_str(&token_in_mint)
                        .map_err(|e| format!("Invalid token_out_mint pubkey: {}", e))?,
                );
                let auctioneer_token_in_account = Some(token_in_escrow_addr);
                let solver_token_in_account = Some(solver_token_in_addr);

                program
                    .request()
                    .instruction(ComputeBudgetInstruction::set_compute_unit_limit(1_000_000))
                    .instruction(ComputeBudgetInstruction::request_heap_frame(128 * 1024))
                    .accounts(bridge_escrow::accounts::SplTokenTransfer {
                        intent: Some(intent_state),
                        intent_owner: receiver.unwrap(),
                        auctioneer_state,
                        solver: solver_clone.pubkey(),
                        auctioneer: Pubkey::from_str(
                            "5zCZ3jk8EZnJyG7fhDqD6tmqiYTLZjik5HUpGMnHrZfC",
                        )
                        .map_err(|e| format!("Invalid auctioneer pubkey: {}", e))?,
                        token_in: Some(Pubkey::from_str(&token_in_mint).unwrap()),
                        token_out: Pubkey::from_str(&token_out_mint)
                            .map_err(|e| format!("Invalid token_out_mint pubkey: {}", e))?,
                        auctioneer_token_in_account: auctioneer_token_in_account,
                        solver_token_in_account: solver_token_in_account,
                        solver_token_out_account: solver_token_out_addr,
                        user_token_out_account: user_token_out_addr,
                        token_program: anchor_spl::token::ID,
                        associated_token_program: anchor_spl::associated_token::ID,
                        system_program: anchor_lang::solana_program::system_program::ID,
                        ibc_program: Some(solana_ibc::ID),
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
                    })
                    .payer(solver_clone.clone())
                    .instructions()
                    .map_err(|e| format!("Failed to create instructions: {}", e))
            }
        })?;

        // Submit transaction asynchronously
        let rpc_url = env::var("SOLANA_RPC").expect("SOLANA_RPC must be set");
        let client = RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());
        match submit(&client, solver_clone, instructions, JITO_TIP_AMOUNT).await {
            Ok(tx_hash) => {
                let _ = send_tx_hash_to_auctioner("http://34.78.217.187:8080", tx_hash).await;
                Ok(())
            },  // Transaction succeeded
            Err(_) => Ok(()), // Return error if transaction fails
        }
    }

    pub async fn submit(
        rpc_client: &RpcClient,
        fee_payer: Arc<Keypair>,
        instructions: Vec<Instruction>,
        jito_tip: u64,
    ) -> Result<Signature, String> {
        let tx_send_method: TxSendMethod = match SUBMIT_THROUGH_JITO.load(Ordering::Relaxed) {
            true => TxSendMethod::JITO,
            false => TxSendMethod::RPC,
        };
        match tx_send_method {
            TxSendMethod::JITO => {
                submit_through_jito(rpc_client, fee_payer, instructions, jito_tip).await
            }
            TxSendMethod::RPC => submit_default(rpc_client, fee_payer, instructions).await,
        }
        .map_err(|e| e.to_string())
    }

    pub async fn submit_default(
        rpc_client: &RpcClient,
        fee_payer: Arc<Keypair>,
        instructions: Vec<Instruction>,
    ) -> anyhow::Result<Signature> {
        let mut current_try = 0;
        loop {
            current_try += 1;

            let recent_blockhash = rpc_client
                .get_latest_blockhash()
                .await
                .map_err(|e| anyhow!("Failed to fetch blockhash: {}", e))?;
            let transaction = Transaction::new_signed_with_payer(
                &instructions,
                Some(&fee_payer.pubkey()),
                &[&*fee_payer],
                recent_blockhash,
            );

            let sig = rpc_client
                .send_and_confirm_transaction_with_spinner_and_config(
                    &transaction,
                    rpc_client.commitment(),
                    RpcSendTransactionConfig {
                        skip_preflight: true,
                        ..Default::default()
                    },
                )
                .await;

            match sig {
                Ok(sig) => return Ok(sig), // Transaction succeeded, exit loop
                Err(err) if err.to_string().contains("unable to confirm transaction") => {
                    eprintln!("Transaction failed: {}. Retrying...", err);
                    if current_try == RETRIES {
                        return Err(anyhow!("Failed to send transaction: {}", err));
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
                Err(err) => {
                    return Err(anyhow!(
                        "Transaction failed due to a non-retryable error: {}",
                        err
                    ))
                } // Break on other errors
            }
        }
    }

    pub async fn submit_through_jito(
        rpc_client: &RpcClient,
        fee_payer: Arc<Keypair>,
        instructions: Vec<Instruction>,
        jito_tip: u64,
    ) -> anyhow::Result<Signature> {
        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &fee_payer.pubkey(),
            &JITO_ADDRESS,
            jito_tip,
        );

        let mut all_instructions = vec![ix];
        all_instructions.extend_from_slice(instructions.as_slice());

        let tx =
            Transaction::new_with_payer(all_instructions.as_slice(), Some(&fee_payer.pubkey()));

        let mut current_try = 0;
        let mut signature: Signature = Signature::default();
        while current_try < RETRIES {
            let mut cloned_tx = tx.clone();
            let mut client =
                jito_searcher_client::get_searcher_client(&JITO_BLOCK_ENGINE_URL, &fee_payer)
                    .await?;
            let mut bundle_results_subscription = client
                .subscribe_bundle_results(SubscribeBundleResultsRequest {})
                .await?
                .into_inner();

            let blockhash = rpc_client.get_latest_blockhash().await?;
            cloned_tx.sign(&[&*fee_payer], blockhash);

            let signatures = jito_searcher_client::send_bundle_with_confirmation(
                &[cloned_tx.into()],
                &rpc_client,
                &mut client,
                &mut bundle_results_subscription,
            )
            .await
            .or_else(|e| {
                // println!("This is error {:?}", e);
                Err(e)
            });

            if let Ok(sigs) = signatures {
                signature = *sigs.first().unwrap();
                return Ok(signature);
            } else {
                current_try += 1;
                continue;
            }
        }
        if current_try == RETRIES {
            println!("Failed to send transaction with the tries, Sending it through RPC Now");
            submit_default(rpc_client, fee_payer, instructions).await
        } else {
            Ok(signature)
        }
    }

    async fn send_tx_hash_to_auctioner(auctioner_url: &str, tx_hash: Signature) -> anyhow::Result<()> {
        let _ = reqwest::Client::new()
            .post(&format!("{auctioner_url}/solana_tx_proof"))
            .body(tx_hash.to_string())
            .send()
            .await?;
        Ok(())
    }
}
