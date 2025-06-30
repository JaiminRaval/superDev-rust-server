use axum::{
    Router,
    extract::Json,
    http::StatusCode,
    response::{Json as ResponseJson, Response},
    routing::post,
};

use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
};

use spl_token::instruction::{initialize_mint, mint_to, transfer};
use std::str::FromStr;
use tower_http::cors::CorsLayer;

#[derive(Serialize)]
struct SuccessResponse<T> {
    success: bool,
    data: T,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

type ApiResult<T> = Result<
    (StatusCode, ResponseJson<SuccessResponse<T>>),
    (StatusCode, ResponseJson<ErrorResponse>),
>;

fn success_response<T>(data: T) -> ApiResult<T> {
    Ok((
        StatusCode::OK,
        ResponseJson(SuccessResponse {
            success: true,
            data,
        }),
    ))
}

fn error_response(message: &str) -> (StatusCode, ResponseJson<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        ResponseJson(ErrorResponse {
            success: false,
            error: message.to_string(),
        }),
    )
}

#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct AccountMetaResponse {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct InstructionData {
    program_id: String,
    accounts: Vec<AccountMetaResponse>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SignMessageData {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
struct VerifyMessageData {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Serialize)]
struct SendSolData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize)]
struct TokenAccountMeta {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct SendTokenData {
    program_id: String,
    accounts: Vec<TokenAccountMeta>,
    instruction_data: String,
}

async fn generate_keypair() -> ApiResult<KeypairData> {
    let keypair = Keypair::new();
    let pubkey = bs58::encode(keypair.pubkey().to_bytes()).into_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    success_response(KeypairData { pubkey, secret })
}

async fn create_token(Json(payload): Json<CreateTokenRequest>) -> ApiResult<InstructionData> {
    let mint_authority = Pubkey::from_str(&payload.mint_authority)
        .map_err(|_| error_response("Invalid mint authority"))?;

    let mint =
        Pubkey::from_str(&payload.mint).map_err(|_| error_response("Invalid mint address"))?;

    let instruction = initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        payload.decimals,
    )
    .map_err(|_| error_response("Failed to create mint instruction"))?;

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| AccountMetaResponse {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    success_response(InstructionData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&instruction.data),
    })
}

async fn mint_token(Json(payload): Json<MintTokenRequest>) -> ApiResult<InstructionData> {
    let mint =
        Pubkey::from_str(&payload.mint).map_err(|_| error_response("Invalid mint address"))?;

    let destination = Pubkey::from_str(&payload.destination)
        .map_err(|_| error_response("Invalid destination address"))?;

    let authority = Pubkey::from_str(&payload.authority)
        .map_err(|_| error_response("Invalid authority address"))?;

    let instruction = mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    )
    .map_err(|_| error_response("Failed to create mint instruction"))?;

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| AccountMetaResponse {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    success_response(InstructionData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&instruction.data),
    })
}

async fn sign_message(Json(payload): Json<SignMessageRequest>) -> ApiResult<SignMessageData> {
    if payload.message.is_empty() || payload.secret.is_empty() {
        return Err(error_response("Missing required fields"));
    }

    let secret_bytes = bs58::decode(&payload.secret)
        .into_vec()
        .map_err(|_| error_response("Invalid secret key"))?;

    if secret_bytes.len() != 64 {
        return Err(error_response("Invalid secret key length"));
    }

    let keypair =
        Keypair::from_bytes(&secret_bytes).map_err(|_| error_response("Invalid keypair"))?;

    let message_bytes = payload.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);

    success_response(SignMessageData {
        signature: base64::encode(signature.as_ref()),
        public_key: bs58::encode(keypair.pubkey().to_bytes()).into_string(),
        message: payload.message,
    })
}

async fn verify_message(Json(payload): Json<VerifyMessageRequest>) -> ApiResult<VerifyMessageData> {
    let pubkey_bytes = bs58::decode(&payload.pubkey)
        .into_vec()
        .map_err(|_| error_response("Invalid public key"))?;

    let pubkey = Pubkey::try_from(pubkey_bytes.as_slice())
        .map_err(|_| error_response("Invalid public key format"))?;

    let signature_bytes =
        base64::decode(&payload.signature).map_err(|_| error_response("Invalid signature"))?;

    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| error_response("Invalid signature format"))?;

    let message_bytes = payload.message.as_bytes();
    let valid = signature.verify(pubkey.as_ref(), message_bytes);

    success_response(VerifyMessageData {
        valid,
        message: payload.message,
        pubkey: payload.pubkey,
    })
}

async fn send_sol(Json(payload): Json<SendSolRequest>) -> ApiResult<SendSolData> {
    let from =
        Pubkey::from_str(&payload.from).map_err(|_| error_response("Invalid from address"))?;

    let to = Pubkey::from_str(&payload.to).map_err(|_| error_response("Invalid to address"))?;

    if payload.lamports == 0 {
        return Err(error_response("Amount must be greater than 0"));
    }

    let instruction = system_instruction::transfer(&from, &to, payload.lamports);

    success_response(SendSolData {
        program_id: instruction.program_id.to_string(),
        accounts: instruction
            .accounts
            .iter()
            .map(|acc| acc.pubkey.to_string())
            .collect(),
        instruction_data: base64::encode(&instruction.data),
    })
}

async fn send_token(Json(payload): Json<SendTokenRequest>) -> ApiResult<SendTokenData> {
    let mint =
        Pubkey::from_str(&payload.mint).map_err(|_| error_response("Invalid mint address"))?;

    let owner =
        Pubkey::from_str(&payload.owner).map_err(|_| error_response("Invalid owner address"))?;

    let destination = Pubkey::from_str(&payload.destination)
        .map_err(|_| error_response("Invalid destination address"))?;

    if payload.amount == 0 {
        return Err(error_response("Amount must be greater than 0"));
    }

    let source_ata = spl_associated_token_account::get_associated_token_address(&owner, &mint);
    let dest_ata = spl_associated_token_account::get_associated_token_address(&destination, &mint);

    let instruction = transfer(
        &spl_token::id(),
        &source_ata,
        &dest_ata,
        &owner,
        &[],
        payload.amount,
    )
    .map_err(|_| error_response("Failed to create transfer instruction"))?;

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| TokenAccountMeta {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        })
        .collect();

    success_response(SendTokenData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&instruction.data),
    })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token))
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server running on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}
