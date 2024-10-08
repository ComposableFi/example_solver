pub mod ethereum_chain {
    use crate::chains::get_token_info;
    use crate::chains::OperationOutput;
    use crate::env;
    use crate::json;
    use crate::routers::paraswap::paraswap_router::simulate_swap_paraswap;
    use crate::routers::paraswap::paraswap_router::ParaswapParams;
    use crate::OperationInput;
    use crate::PostIntentInfo;
    use crate::SOLVER_ADDRESSES;
    use crate::SOLVER_ID;
    use ethers::prelude::abigen;
    use ethers::prelude::*;
    use ethers::providers::{Http, Provider};
    use num_bigint::BigInt;
    use reqwest::Client;
    use serde::Deserialize;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    #[derive(Deserialize)]
    struct GasPrice {
        #[serde(rename = "SafeGasPrice")]
        _safe_gas_price: String,
        #[serde(rename = "ProposeGasPrice")]
        propose_gas_price: String,
        #[serde(rename = "FastGasPrice")]
        _fast_gas_price: String,
    }

    #[derive(Deserialize)]
    struct GasResponse {
        result: GasPrice,
    }

    abigen!(
        ERC20,
        r#"[{
            "constant": true,
            "inputs": [],
            "name": "decimals",
            "outputs": [{ "name": "", "type": "uint8" }],
            "type": "function"
        },
        {
            "constant": false,
            "inputs": [
                { "name": "_to", "type": "address" },
                { "name": "_value", "type": "uint256" }
            ],
            "name": "transfer",
            "outputs": [{ "name": "", "type": "bool" }],
            "type": "function"
        },
        {
            "constant": false,
            "inputs": [
                { "name": "_spender", "type": "address" },
                { "name": "_value", "type": "uint256" }
            ],
            "name": "approve",
            "outputs": [{ "name": "", "type": "bool" }],
            "type": "function"
        }]"#
    );

    abigen!(
        Escrow,
        r#"[{
            "constant": false,
            "inputs": [
                {
                    "components": [
                        { "name": "intentId", "type": "uint256" },
                        { "name": "tokenOut", "type": "address" },
                        { "name": "amountOut", "type": "uint256" },
                        { "name": "dstUser", "type": "address" },
                        { "name": "singleDomain", "type": "bool" },
                        { "name": "solverOut", "type": "string" }
                    ],
                    "name": "solverTransferData",
                    "type": "tuple"
                }
            ],
            "name": "sendFundsToUser",
            "outputs": [],
            "payable": true,
            "stateMutability": "payable",
            "type": "function"
        }]"#
    );

    abigen!(
        UsdtContract,
        r#"[
            function balanceOf(address owner) view returns (uint256)
        ]"#
    );

    pub const ESCROW_SC_ETHEREUM: &str = "0x59880a68fafcE2E282866bdb741Cf0b20E95c1B7";
    pub const PARASWAP: &str = "0x216b4b4ba9f3e719726886d34a177484278bfcae";

    pub async fn handle_ethereum_execution(
        intent: &PostIntentInfo,
        intent_id: U256,
        amount: &str,
        single_domain: bool
    ) -> Result<(), String> {
        let usdt_contract_address = "0xdac17f958d2ee523a2206206994597c13d831ec7";

        let rpc_url = env::var("ETHEREUM_RPC").expect("ETHEREUM_RPC must be set");
        let private_key = env::var("ETHEREUM_PKEY").expect("ETHEREUM_PKEY must be set");
        let target_address: Address = Address::from_str(SOLVER_ADDRESSES.get(0).unwrap()).unwrap();

        let provider = Arc::new(
            Provider::<Http>::try_from(&rpc_url)
                .map_err(|e| format!("Failed to create Ethereum provider: {}", e))?,
        );

        let usdt_contract = UsdtContract::new(
            Address::from_str(usdt_contract_address).unwrap(),
            provider.clone(),
        );

        let balance_ant = usdt_contract
            .balance_of(target_address)
            .call()
            .await
            .map_err(|e| format!("Failed to get USDT balance: {}", e))?;

        let mut token_in = String::default();
        let mut token_out = String::default();
        let mut amount_in = String::default();
        let mut amount_out = String::default();
        let mut dst_user = String::default();

        if let OperationOutput::SwapTransfer(transfer_output) = &intent.outputs {
            token_out = transfer_output.token_out.clone();
            amount_out = transfer_output.amount_out.clone();
            dst_user = transfer_output.dst_chain_user.clone();
        }
        if let OperationInput::SwapTransfer(transfer_input) = &intent.inputs {
            token_in = transfer_input.token_in.clone();
            amount_in = transfer_input.amount_in.clone();
        }

        // swap USDT -> token_out
        if !token_out.eq_ignore_ascii_case(usdt_contract_address) {
            if let Err(e) = ethereum_trasnfer_swap(&intent_id.to_string(), intent.clone(), amount).await {
                return Err(format!(
                    "Error occurred on Ethereum swap USDT -> token_out (solver must approve USDT to Paraswap 0x216b4b4ba9f3e719726886d34a177484278bfcae first): {}",
                    e
                ));
            }

            if let Err(e) = approve_erc20(
                &rpc_url,
                &private_key,
                &token_out,
                ESCROW_SC_ETHEREUM,
                amount,
            )
            .await
            {
                println!("Error approving {token_out} for solver: {e}");
                return Err(e.to_string());
            }
        }

        let solver_out = if intent.src_chain == "ethereum" {
            SOLVER_ADDRESSES.get(0).unwrap()
        } else if intent.src_chain == "solana" {
            SOLVER_ADDRESSES.get(1).unwrap()
        } else {
            panic!("chain not supported, this should't happen");
        };

        // solver -> token_out -> user | user -> token_in -> solver
        if let Err(e) = ethereum_send_funds_to_user(
            &rpc_url,
            &private_key,
            ESCROW_SC_ETHEREUM,
            intent_id,
            Address::from_str(&token_out).unwrap(),
            U256::from_dec_str(&amount_out).unwrap(),
            Address::from_str(&dst_user).unwrap(),
            single_domain,
            solver_out,
            U256::zero(),
        )
        .await
        {
            println!("Error occurred on Ethereum send token_out -> user & user sends token_in -> solver (solver must approve USDT to Escrow SC first): {}", e);
            return Err(e.to_string());
        // swap token_in -> USDT
        } else if intent.src_chain == intent.dst_chain
            && !token_in.eq_ignore_ascii_case(usdt_contract_address)
        {
            if let Err(e) =
                approve_erc20(&rpc_url, &private_key, &token_in, PARASWAP, &amount_in).await
            {
                println!("Error approving {token_in} for solver: {e}");
                return Err(e.to_string());
            }

            let (token_out, token1_decimals) = match get_token_info("USDT", "ethereum") {
                Some((token_out, token1_decimals)) => (token_out.to_string(), token1_decimals),
                None => {
                    println!("Failed to get token info for USDT on Ethereum");
                    return Err("Failed to get token info".to_string());
                }
            };

            let token0_decimals = get_evm_token_decimals(&ERC20::new(
                Address::from_str(&token_in).unwrap(),
                provider.clone(),
            ))
            .await;

            let paraswap_params = ParaswapParams {
                side: "SELL".to_string(),
                chain_id: 1,
                amount_in: BigInt::from_str(&amount_in).unwrap(),
                token_in: Address::from_str(&token_in).unwrap(),
                token_out: Address::from_str(&token_out).unwrap(),
                token0_decimals: token0_decimals as u32,
                token1_decimals: token1_decimals as u32,
                wallet_address: Address::from_str(SOLVER_ADDRESSES.get(0).unwrap()).unwrap(),
                receiver_address: Address::from_str(SOLVER_ADDRESSES.get(0).unwrap()).unwrap(),
                client_aggregator: Client::new(),
            };

            let (_res_amount, res_data, res_to) = simulate_swap_paraswap(paraswap_params)
                .await
                .map_err(|e| format!("Error simulating Paraswap swap: {}", e))?;

            if let Err(e) = send_tx(res_to, res_data, 1, 500_000, 0, rpc_url).await {
                println!("Error sending transaction on Ethereum: {}", e);
                return Err(e.to_string());
            }
        }

        if intent.src_chain == intent.dst_chain {
            let balance_post = usdt_contract
                .balance_of(target_address)
                .call()
                .await
                .map_err(|e| format!("Failed to get post-swap USDT balance: {}", e))?;

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
                balance.as_u128() as f64 / 1e6
            );
        }

        Ok(())
    }

    pub async fn ethereum_trasnfer_swap(
        intent_id: &str,
        intent: PostIntentInfo,
        amount: &str,
    ) -> Result<(), String> {
        let client_rpc =
            env::var("ETHEREUM_RPC").map_err(|e| format!("ETHEREUM_RPC must be set: {}", e))?;
        let mut token_out = String::default();

        match intent.function_name.as_str() {
            "transfer" => {
                if let OperationOutput::SwapTransfer(transfer_output) = &intent.outputs {
                    token_out = transfer_output.token_out.clone();
                }

                match transfer_erc20(
                    &client_rpc,
                    &env::var("ETHEREUM_PKEY")
                        .map_err(|e| format!("ETHEREUM_PKEY must be set: {}", e))?,
                    &token_out,
                    SOLVER_ADDRESSES.get(0).unwrap(),
                    &amount.to_string(),
                )
                .await
                {
                    Ok(signature) => {
                        let msg = json!({
                            "code": 1,
                            "msg": {
                                "intent_id": intent_id,
                                "solver_id": SOLVER_ID.to_string(),
                                "tx_hash": signature,
                            }
                        })
                        .to_string();
                        println!("{}", msg);
                        Ok(())
                    }
                    Err(err) => {
                        let msg = json!({
                            "code": 0,
                            "solver_id": 0,
                            "msg": format!("Transaction failed: {}", err)
                        })
                        .to_string();
                        Err(msg)
                    }
                }
            }
            "swap" => {
                let (token_in, token0_decimals) = get_token_info("USDT", "ethereum")
                    .ok_or_else(|| "Failed to get token info".to_string())?;

                if let OperationOutput::SwapTransfer(transfer_output) = &intent.outputs {
                    token_out = transfer_output.token_out.clone();
                }

                let provider = Provider::<Http>::try_from(client_rpc.replace("wss", "https"))
                    .map_err(|e| format!("Failed to create provider: {}", e))?;
                let provider = Arc::new(provider);

                let token1_decimals = get_evm_token_decimals(&ERC20::new(
                    Address::from_str(&token_out)
                        .map_err(|e| format!("Invalid token_out address: {}", e))?,
                    provider.clone(),
                ))
                .await;

                let paraswap_params = ParaswapParams {
                    side: "BUY".to_string(),
                    chain_id: 1,
                    amount_in: BigInt::from_str(amount)
                        .map_err(|e| format!("Invalid amount: {}", e))?,
                    token_in: Address::from_str(&token_in)
                        .map_err(|e| format!("Invalid token_in address: {}", e))?,
                    token_out: Address::from_str(&token_out)
                        .map_err(|e| format!("Invalid token_out address: {}", e))?,
                    token0_decimals: token0_decimals as u32,
                    token1_decimals: token1_decimals as u32,
                    wallet_address: Address::from_str(SOLVER_ADDRESSES.get(0).unwrap())
                        .map_err(|e| format!("Invalid wallet address: {}", e))?,
                    receiver_address: Address::from_str(SOLVER_ADDRESSES.get(0).unwrap())
                        .map_err(|e| format!("Invalid receiver address: {}", e))?,
                    client_aggregator: Client::new(),
                };

                let (_res_amount, res_data, res_to) = simulate_swap_paraswap(paraswap_params)
                    .await
                    .map_err(|e| format!("Failed to simulate swap: {}", e))?;

                let tx_hash = send_tx(res_to, res_data, 1, 500_000, 0, client_rpc).await;

                // since tx_hash is a String, handle error separately if needed
                if tx_hash.is_err() {
                    return Err(format!(
                        "Transaction failed with tx_hash error: {:?}",
                        tx_hash
                    ));
                }

                Ok(())
            }
            _ => Err("Function not supported".to_string()),
        }
    }

    async fn transfer_erc20(
        provider_url: &str,
        private_key: &str,
        token_address: &str,
        recipient_address: &str,
        amount: &str,
    ) -> Result<TxHash, Box<dyn std::error::Error>> {
        let provider = Provider::<Http>::try_from(provider_url)?;
        let provider = Arc::new(provider);

        let wallet: LocalWallet = private_key.parse()?;
        let wallet = wallet.with_chain_id(1u64); // Mainnet
        let wallet = Arc::new(SignerMiddleware::new(provider.clone(), wallet));

        let token_address = token_address.parse::<Address>()?;
        let erc20 = ERC20::new(token_address, wallet.clone());

        let recipient: Address = recipient_address.parse()?;
        let amount = U256::from_dec_str(amount).unwrap();

        let tx = erc20.transfer(recipient, amount);
        let tx = tx.send().await?;

        Ok(tx.tx_hash())
    }

    pub async fn send_tx(
        to: Address,
        data: String,
        chain_id: u64,
        gas: u64,
        value: u128,
        url: String,
    ) -> Result<(), String> {
        let prvk = match env::var("ETHEREUM_PKEY") {
            Ok(key) => match secp256k1::SecretKey::from_str(&key) {
                Ok(prvk) => prvk,
                Err(e) => return Err(format!("Failed to parse private key: {}", e)),
            },
            Err(_) => return Err("ETHEREUM_PKEY environment variable is not set".to_string()),
        };

        // Get gas
        let response =
            reqwest::get("https://api.etherscan.io/api?module=gastracker&action=gasoracle")
                .await
                .map_err(|e| format!("Failed to fetch gas price: {}", e))?;

        let gas_response: GasResponse = response
            .json::<GasResponse>()
            .await
            .map_err(|e| format!("Failed to parse gas response: {}", e))?;

        // Parse the propose gas price as f64
        let propose_gas_price_f64: f64 = gas_response
            .result
            .propose_gas_price
            .parse()
            .map_err(|e| format!("Failed to parse gas price: {}", e))?;

        // Convert to wei (1 Gwei = 1e9 wei)
        let propose_gas_price_wei: u128 = (propose_gas_price_f64 * 1e9) as u128;

        let base_fee_per_gas = propose_gas_price_wei;
        let priority_fee_per_gas: u128 = 2_000_000_000; // This is already in wei
        let max_fee_per_gas = base_fee_per_gas + priority_fee_per_gas;

        // EIP-1559 transaction
        let tx_object = web3::types::TransactionParameters {
            to: Some(to),
            gas: U256::from(gas),
            value: U256::from(value),
            data: web3::types::Bytes::from(
                hex::decode(&data[2..]).map_err(|e| format!("Failed to decode data: {}", e))?,
            ),
            chain_id: Some(chain_id),
            transaction_type: Some(web3::types::U64::from(2)),
            access_list: None,
            max_fee_per_gas: Some(U256::from(max_fee_per_gas)),
            max_priority_fee_per_gas: Some(U256::from(priority_fee_per_gas)),
            ..Default::default()
        };

        let web3_query = web3::Web3::new(
            web3::transports::Http::new(&url)
                .map_err(|e| format!("Failed to create HTTP transport: {}", e))?,
        );

        let signed = web3_query
            .accounts()
            .sign_transaction(tx_object, &prvk)
            .await
            .map_err(|e| format!("Failed to sign transaction: {}", e))?;

        let tx_hash = web3_query
            .eth()
            .send_raw_transaction(signed.raw_transaction)
            .await
            .map_err(|e| format!("Failed to send transaction: {}", e))?;

        // println!("Transaction hash: {:?}", tx_hash);

        // Poll for the transaction receipt
        loop {
            match web3_query.eth().transaction_receipt(tx_hash).await {
                Ok(Some(receipt)) => {
                    if receipt.status == Some(U64::from(1)) {
                        // println!("Transaction confirmed: {:?}", receipt);
                        return Ok(());
                    } else {
                        return Err("Transaction failed".to_string());
                    }
                }
                Ok(None) => {
                    // Receipt is not yet available, continue polling
                    //println!("Transaction pending...");
                    sleep(Duration::from_secs(5));
                }
                Err(e) => return Err(format!("Error while fetching transaction receipt: {}", e)),
            }
        }
    }

    pub async fn get_evm_token_decimals(erc20: &ERC20<Provider<Http>>) -> u8 {
        match erc20.decimals().call().await {
            Ok(decimals) => decimals,
            Err(e) => {
                eprintln!("Error getting decimals: {}", e);
                0
            }
        }
    }

    pub async fn ethereum_quote(
        token_in: Address,
        amount_in: BigInt,
        token_out: Address,
    ) -> BigInt {
        let rpc_url = env::var("ETHEREUM_RPC").expect("ETHEREUM_RPC must be set");
        let provider = Provider::<Http>::try_from(rpc_url)
            .map_err(|e| e.to_string())
            .unwrap();
        let provider = Arc::new(provider);
        let token0_decimals = get_evm_token_decimals(&ERC20::new(token_in, provider.clone())).await;
        let token1_decimals =
            get_evm_token_decimals(&ERC20::new(token_out, provider.clone())).await;

        let paraswap_params = ParaswapParams {
            side: "SELL".to_string(),
            chain_id: 1,
            amount_in,
            token_in,
            token_out,
            token0_decimals: token0_decimals as u32,
            token1_decimals: token1_decimals as u32,
            wallet_address: Address::from_str(SOLVER_ADDRESSES.get(0).unwrap()).unwrap(),
            receiver_address: Address::from_str(SOLVER_ADDRESSES.get(0).unwrap()).unwrap(),
            client_aggregator: Client::new(),
        };

        let (_res_amount, _, _) = simulate_swap_paraswap(paraswap_params).await.unwrap();
        _res_amount
    }

    pub async fn ethereum_send_funds_to_user(
        provider_url: &str,
        private_key: &str,
        contract_address: &str,
        intent_id: U256,
        token_out: Address,
        amount_out: U256,
        dst_user: Address,
        single_domain: bool,
        solver_out: &str,
        value_in_wei: U256
    ) -> Result<TransactionReceipt, Box<dyn std::error::Error>> {
        let provider = Provider::<Http>::try_from(provider_url)?;
        let provider = Arc::new(provider);
    
        let wallet: LocalWallet = private_key.parse()?;
        let wallet = wallet.with_chain_id(1u64); // Mainnet
        let wallet = Arc::new(SignerMiddleware::new(provider.clone(), wallet));
    
        let contract_address = contract_address.parse::<Address>()?;
        let contract = Escrow::new(contract_address, wallet.clone());
    
        let solver_transfer_data = (
            intent_id,
            token_out,
            amount_out,
            dst_user,
            single_domain,
            solver_out.to_string()
        );
    
        // let gas_price = provider.get_gas_price().await.unwrap();
        let contract = contract
            .send_funds_to_user(solver_transfer_data)
            .value(value_in_wei);
            // .gas_price(gas_price);  // Set the gas price
    
        let pending_tx = contract.send().await?;
    
        let tx_receipt = pending_tx
            .await?
            .expect("Failed to fetch transaction receipt");
    
        Ok(tx_receipt)
    }
    

    pub async fn approve_erc20(
        provider_url: &str,
        private_key: &str,
        token_address: &str,
        spender_address: &str,
        amount: &str,
    ) -> Result<(), String> {
        let provider = Provider::<Http>::try_from(provider_url)
            .map_err(|e| format!("Failed to create provider: {}", e))?;
        let provider = Arc::new(provider);

        let wallet: LocalWallet = private_key
            .parse()
            .map_err(|e| format!("Failed to parse private key: {}", e))?;
        let wallet = wallet.with_chain_id(1u64); // Mainnet
        let wallet = Arc::new(SignerMiddleware::new(provider.clone(), wallet));

        let token_address = token_address
            .parse::<Address>()
            .map_err(|e| format!("Failed to parse token address: {}", e))?;
        let erc20 = ERC20::new(token_address, wallet.clone());

        let spender: Address = spender_address
            .parse::<Address>()
            .map_err(|e| format!("Failed to parse spender address: {}", e))?;
        let amount =
            U256::from_dec_str(amount).map_err(|e| format!("Failed to parse amount: {}", e))?;

        let tx = erc20.approve(spender, amount);
        let pending_tx = tx
            .send()
            .await
            .map_err(|e| format!("Failed to send transaction: {}", e))?;

        pending_tx
            .await
            .map_err(|e| format!("Transaction failed: {}", e))?;

        Ok(())
    }
}
