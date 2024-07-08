extern crate reqwest;
extern crate serde;
extern crate serde_json;
extern crate hmac;
extern crate sha2;
extern crate hex;
extern crate dotenv;

use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde::Deserialize;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use hex::encode as hex_encode;
use dotenv::dotenv;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

#[derive(Deserialize)]
struct ApiResponse {
    // Define fields according to the response structure
}

async fn enable_fast_withdraw(api_key: &str, secret_key: &str) -> Result<(), reqwest::Error> {
    let url = "https://api.binance.com/sapi/v1/account/enableFastWithdrawSwitch";
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis().to_string();
    let query_string = format!("timestamp={}", timestamp);

    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes()).expect("Invalid secret key length");
    mac.update(query_string.as_bytes());
    let signature = hex_encode(mac.finalize().into_bytes());

    let request_url = format!("{}?{}&signature={}", url, query_string, signature);

    let client = reqwest::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert("X-MBX-APIKEY", HeaderValue::from_str(api_key).unwrap());
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    let res = client.post(&request_url)
        .headers(headers)
        .send()
        .await?;

    if res.status().is_success() {
        println!("Fast withdraw enabled successfully.");
    } else {
        println!("Failed to enable fast withdraw: {:?}", res.text().await?);
    }

    Ok(())
}

async fn withdraw_usdt(api_key: &str, secret_key: &str, amount: &str, address: &str) -> Result<(), reqwest::Error> {
    let url = "https://api.binance.com/sapi/v1/capital/withdraw/apply";
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis().to_string();
    let asset = "USDT";
    let query_string = format!("asset={}&amount={}&address={}&timestamp={}", asset, amount, address, timestamp);

    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes()).expect("Invalid secret key length");
    mac.update(query_string.as_bytes());
    let signature = hex_encode(mac.finalize().into_bytes());

    let request_url = format!("{}?{}&signature={}", url, query_string, signature);

    let client = reqwest::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert("X-MBX-APIKEY", HeaderValue::from_str(api_key).unwrap());
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    let res = client.post(&request_url)
        .headers(headers)
        .send()
        .await?;

    if res.status().is_success() {
        println!("Withdrawal request submitted successfully.");
    } else {
        println!("Failed to submit withdrawal request: {:?}", res.text().await?);
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    dotenv().ok(); // 加载 .env 文件中的环境变量
    let api_key = env::var("BINANCE_API_KEY").expect("Missing BINANCE_API_KEY");
    let secret_key = env::var("BINANCE_SECRET_KEY").expect("Missing BINANCE_SECRET_KEY");
    let usdt_address = "0xc67cfbc0f2202e82bb1c7cd85065c8ad0552668b"; // srain 的USDT地址
    let amount = "0.1"; // 替换为你要提现的金额

    if let Err(e) = enable_fast_withdraw(&api_key, &secret_key).await {
        eprintln!("Error enabling fast withdraw: {:?}", e);
    }

    if let Err(e) = withdraw_usdt(&api_key, &secret_key, amount, usdt_address).await {
        eprintln!("Error withdrawing USDT: {:?}", e);
    }
}