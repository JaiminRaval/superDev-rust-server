use axum::{Router, extract::Request, http::StatusCode, response::Json, routing::post};
use serde::{Deserialize, Serialize};
use solana_sdk::signature::{Keypair, Signer};
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: String) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

async fn generate_keypair() -> Result<Json<ApiResponse<KeypairData>>, StatusCode> {
    match create_solana_keypair() {
        Ok(keypair_data) => Ok(Json(ApiResponse::success(keypair_data))),
        Err(e) => {
            eprintln!("Error generating keypair: {}", e);
            Ok(Json(ApiResponse::error(
                "Failed to generate keypair".to_string(),
            )))
        }
    }
}

fn create_solana_keypair() -> Result<KeypairData, Box<dyn std::error::Error>> {
    let keypair = Keypair::new();

    let pubkey = keypair.pubkey().to_string();

    let secret = bs58::encode(keypair.to_bytes()).into_string();

    Ok(KeypairData { pubkey, secret })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .layer(CorsLayer::permissive());

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let result = create_solana_keypair();
        assert!(result.is_ok());

        let keypair_data = result.unwrap();
        assert!(!keypair_data.pubkey.is_empty());
        assert!(!keypair_data.secret.is_empty());

        assert!(bs58::decode(&keypair_data.pubkey).into_vec().is_ok());
        assert!(bs58::decode(&keypair_data.secret).into_vec().is_ok());
    }
}
