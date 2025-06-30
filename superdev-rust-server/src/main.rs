use axum::{
    Router, extract::Json, http::StatusCode, response::Json as ResponseJson, routing::post,
};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction, sysvar,
};
use spl_token::{
    instruction::{initialize_mint, mint_to, transfer},
    state::Mint,
};
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
struct AccountMeta {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct InstructionData {
    program_id: String,
    accounts: Vec<AccountMeta>,
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

async fn generate_keypair() -> Result<ResponseJson<SuccessResponse<KeypairData>>, StatusCode> {
    let keypair = Keypair::new();
    let pubkey = bs58::encode(keypair.pubkey().to_bytes()).into_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: KeypairData { pubkey, secret },
    }))
}

async fn create_token(
    Json(payload): Json<CreateTokenRequest>,
) -> Result<ResponseJson<SuccessResponse<InstructionData>>, ResponseJson<ErrorResponse>> {
    let mint_authority = match Pubkey::from_str(&payload.mint_authority) {
        Ok(key) => key,
        Err(_) => {
            return Err(ResponseJson(ErrorResponse {
                success: false,
                error: "Invalid mint authority".to_string(),
            }));
        }
    };

    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(key) => key,
        Err(_) => {
            return Err(ResponseJson(ErrorResponse {
                success: false,
                error: "Invalid mint address".to_string(),
            }));
        }
    };

    let instruction = initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        payload.decimals,
    )
    .unwrap();

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| AccountMeta {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: InstructionData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(&instruction.data),
        },
    }))
}

async fn mint_token(
    Json(payload): Json<MintTokenRequest>,
) -> Result<ResponseJson<SuccessResponse<InstructionData>>, ResponseJson<ErrorResponse>> {
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(key) => key,
        Err(_) => {
            return Err(ResponseJson(ErrorResponse {
                success: false,
                error: "Invalid mint address".to_string(),
            }));
        }
    };

    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(key) => key,
        Err(_) => {
            return Err(ResponseJson(ErrorResponse {
                success: false,
                error: "Invalid destination address".to_string(),
            }));
        }
    };

    let authority = match Pubkey::from_str(&payload.authority) {
        Ok(key) => key,
        Err(_) => {
            return Err(ResponseJson(ErrorResponse {
                success: false,
                error: "Invalid authority address".to_string(),
            }));
        }
    };

    let instruction = mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    )
    .unwrap();

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| AccountMeta {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: InstructionData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(&instruction.data),
        },
    }))
}

async fn sign_message(
    Json(payload): Json<SignMessageRequest>,
) -> Result<ResponseJson<SuccessResponse<SignMessageData>>, ResponseJson<ErrorResponse>> {
    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(ResponseJson(ErrorResponse {
                success: false,
                error: "Invalid secret key".to_string(),
            }));
        }
    };

    if secret_bytes.len() != 64 {
        return Err(ResponseJson(ErrorResponse {
            success: false,
            error: "Invalid secret key length".to_string(),
        }));
    }

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return Err(ResponseJson(ErrorResponse {
                success: false,
                error: "Invalid keypair".to_string(),
            }));
        }
    };

    let message_bytes = payload.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);

    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: SignMessageData {
            signature: base64::encode(signature.as_ref()),
            public_key: bs58::encode(keypair.pubkey().to_bytes()).into_string(),
            message: payload.message,
        },
    }))
}

async fn verify_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> Result<ResponseJson<SuccessResponse<VerifyMessageData>>, ResponseJson<ErrorResponse>> {
    let pubkey_bytes = match bs58::decode(&payload.pubkey).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(ResponseJson(ErrorResponse {
                success: false,
                error: "Invalid public key".to_string(),
            }));
        }
    };

    let pubkey = match Pubkey::try_from(pubkey_bytes.as_slice()) {
        Ok(pk) => pk,
        Err(_) => {
            return Err(ResponseJson(ErrorResponse {
                success: false,
                error: "Invalid public key format".to_string(),
            }));
        }
    };

    let signature_bytes = match base64::decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(ResponseJson(ErrorResponse {
                success: false,
                error: "Invalid signature".to_string(),
            }));
        }
    };

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return Err(ResponseJson(ErrorResponse {
                success: false,
                error: "Invalid signature format".to_string(),
            }));
        }
    };

    let message_bytes = payload.message.as_bytes();
    let valid = signature.verify(pubkey.as_ref(), message_bytes);

    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: VerifyMessageData {
            valid,
            message: payload.message,
            pubkey: payload.pubkey,
        },
    }))
}

async fn send_sol(
    Json(payload): Json<SendSolRequest>,
) -> Result<ResponseJson<SuccessResponse<SendSolData>>, ResponseJson<ErrorResponse>> {
    let from = match Pubkey::from_str(&payload.from) {
        Ok(key) => key,
        Err(_) => {
            return Err(ResponseJson(ErrorResponse {
                success: false,
                error: "Invalid from address".to_string(),
            }));
        }
    };

    let to = match Pubkey::from_str(&payload.to) {
        Ok(key) => key,
        Err(_) => {
            return Err(ResponseJson(ErrorResponse {
                success: false,
                error: "Invalid to address".to_string(),
            }));
        }
    };

    if payload.lamports == 0 {
        return Err(ResponseJson(ErrorResponse {
            success: false,
            error: "Amount must be greater than 0".to_string(),
        }));
    }

    let instruction = system_instruction::transfer(&from, &to, payload.lamports);

    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: SendSolData {
            program_id: instruction.program_id.to_string(),
            accounts: instruction
                .accounts
                .iter()
                .map(|acc| acc.pubkey.to_string())
                .collect(),
            instruction_data: base64::encode(&instruction.data),
        },
    }))
}

async fn send_token(
    Json(payload): Json<SendTokenRequest>,
) -> Result<ResponseJson<SuccessResponse<SendTokenData>>, ResponseJson<ErrorResponse>> {
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(key) => key,
        Err(_) => {
            return Err(ResponseJson(ErrorResponse {
                success: false,
                error: "Invalid mint address".to_string(),
            }));
        }
    };

    let owner = match Pubkey::from_str(&payload.owner) {
        Ok(key) => key,
        Err(_) => {
            return Err(ResponseJson(ErrorResponse {
                success: false,
                error: "Invalid owner address".to_string(),
            }));
        }
    };

    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(key) => key,
        Err(_) => {
            return Err(ResponseJson(ErrorResponse {
                success: false,
                error: "Invalid destination address".to_string(),
            }));
        }
    };

    if payload.amount == 0 {
        return Err(ResponseJson(ErrorResponse {
            success: false,
            error: "Amount must be greater than 0".to_string(),
        }));
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
    .unwrap();

    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| TokenAccountMeta {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        })
        .collect();

    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: SendTokenData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(&instruction.data),
        },
    }))
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
