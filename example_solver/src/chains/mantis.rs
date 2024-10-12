pub mod mantis_chain {
    use crate::chains::solana::solana_chain::solana_send_funds_to_user;
    use crate::chains::*;
    use crate::PostIntentInfo;
    use serde::{Deserialize, Serialize};
    use solana_sdk::pubkey::Pubkey;
    use std::env;
    use std::str::FromStr;

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

    pub async fn handle_mantis_execution(
        intent_info: &PostIntentInfo,
        intent_id: &str
    ) -> Result<(), String> {
        let rpc_url = env::var("MANTIS_RPC").expect("MANTIS_RPC must be set");

        let mut user = String::default();
        let mut token_in = String::default();
        let mut token_out = String::default();

        if let OperationOutput::SwapTransfer(transfer_output) = &intent_info.outputs {
            user = transfer_output.dst_chain_user.clone();
            token_out = transfer_output.token_out.clone();
        }
        if let OperationInput::SwapTransfer(transfer_input) = &intent_info.inputs {
            token_in = transfer_input.token_in.clone();
        }

        let solver_out = if intent_info.src_chain == "ethereum" {
            SOLVER_ADDRESSES.get(0).unwrap()
        } else if intent_info.src_chain == "solana" || intent_info.src_chain == "mantis" {
            SOLVER_ADDRESSES.get(1).unwrap()
        } else {
            panic!("chain not supported, this should't happen");
        };

        // solver -> token_out -> user | user -> token_in -> solver
        if let Err(e) = solana_send_funds_to_user(
            intent_id,
            &token_in,
            &token_out,
            &user,
            solver_out.to_string(),
            intent_info.src_chain == intent_info.dst_chain,
            rpc_url,
            Pubkey::from_str("61beRZG1h3SvPgGYh9tXhx42jABkMjbMQWpgqUqXw2hw").unwrap(),
        )
        .await
        {
            return Err(format!(
                "Error occurred on send token_out -> user & user sends token_in -> solver: {}",
                e
            ));
        } else {
            println!("solver succesfully solve intent: {}", intent_id);
        }

        Ok(())
    }
}
