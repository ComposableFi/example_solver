use ethers::prelude::Address;
use num_bigint::BigInt;
use reqwest::Client;
use serde_json::Value;
use std::str::FromStr;
use tracing::instrument;

#[derive(Debug)]
pub struct ParaswapParams {
    pub side: String,
    pub chain_id: u16,
    pub amount_in: BigInt,
    pub token_in: Address,
    pub token_out: Address,
    pub token0_decimals: u32,
    pub token1_decimals: u32,
    pub wallet_address: Address,
    pub receiver_address: Address,
    pub client_aggregator: Client,
}

#[instrument(skip_all)]
pub async fn simulate_swap_paraswap(
    params: ParaswapParams,
) -> Result<(BigInt, String, Address), String> {
    let mut res_amount = BigInt::from(0);
    let mut res_data = String::from("None");
    let mut res_to = Address::zero();

    let url = format!("https://apiv5.paraswap.io/prices?srcToken=0x{:x}&srcDecimals={}&destToken=0x{:x}&destDecimals={}&amount={}&side={}&network={}&maxImpact=10",
            params.token_in, params.token0_decimals, params.token_out, params.token1_decimals, params.amount_in, params.side, params.chain_id);

    let res = params
        .client_aggregator
        .get(url)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    let body = res.text().await.map_err(|err| err.to_string())?;
    let json_value = serde_json::from_str::<Value>(&body).map_err(|err| err.to_string())?;

    match json_value.get("priceRoute") {
        Some(json) => {
            let (amount_in, amount_out, mode) = if params.side == "SELL".to_string() {
                (params.amount_in.clone(), BigInt::from(1), "destAmount")
            } else {
                let agg_amount = json
                    .get("srcAmount")
                    .ok_or("Failed to get destination srcAmount")?
                    .to_string()
                    .trim_matches('"')
                    .to_string();
                (
                    BigInt::from_str(&agg_amount).unwrap() * BigInt::from(2),
                    params.amount_in.clone(),
                    "srcAmount",
                )
            };

            let dest_amount = json.get(mode).ok_or("Failed to get destination amount")?;

            res_amount =
                BigInt::from_str(&format!("{}", dest_amount.to_string().trim_matches('"')))
                    .map_err(|err| err.to_string())?;

            let url = format!(
                    "https://apiv5.paraswap.io/transactions/{}?gasPrice=50000000000&ignoreChecks=true&ignoreGasEstimate=true&onlyParams=false", params.chain_id
                );

            let body_0 = serde_json::json!({
                "srcToken": format!("0x{:x}", params.token_in),
                "destToken": format!("0x{:x}", params.token_out),
                "srcAmount": format!("{}", amount_in),
                "destAmount": format!("{}", amount_out),
                "priceRoute": json,
                "userAddress": format!("0x{:x}", params.wallet_address),
                "txOrigin": format!("0x{:x}", params.receiver_address),
                //"receiver": format!("0x{:x}", *MY_SC),
                "partner": "paraswap.io",
                "srcDecimals": params.token0_decimals,
                "destDecimals": params.token1_decimals
            });

            let res = params
                .client_aggregator
                .post(url)
                .json(&body_0)
                .send()
                .await
                .map_err(|err| err.to_string())?;

            let body = res.text().await.map_err(|err| err.to_string())?;

            let json_value =
                serde_json::from_str::<serde_json::Value>(&body).map_err(|err| err.to_string())?;

            match json_value.get("to") {
                Some(address) => {
                    res_to = Address::from_str(address.as_str().ok_or("Failed to get address")?)
                        .map_err(|err| err.to_string())?;
                    let data = json_value.get("data").ok_or("Failed to get data")?;
                    res_data = format!("{}", data.to_string().trim_matches('"'));
                }
                None => {
                    tracing::error!(
                        "Failed getting calldata in Paraswap (weird): {:#}",
                        json_value
                    );
                }
            }
        }
        None => {
            tracing::error!(
                "Failed getting price in Paraswap (maybe token doesn't exist): {:#}",
                body
            );
        }
    }

    Ok((res_amount, res_data, res_to))
}
