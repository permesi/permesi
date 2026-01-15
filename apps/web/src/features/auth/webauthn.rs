//! WebAuthn implementation for hardware security keys.
//!
//! This module provides a pure Rust interface to the browser's `navigator.credentials`
//! API via `web_sys`. it handles the conversion between the server's JSON-based
//! challenge options and the browser's binary-oriented WebAuthn types.
//!
//! ### Flow Overview
//! 1. **Preparation**: Unwraps the server's `publicKey` options and decodes Base64URL
//!    fields (challenges, user IDs, credential IDs) into binary buffers (`Uint8Array`).
//! 2. **Interaction**: Calls `navigator.credentials.create` (for registration) or
//!    `.get` (for authentication), triggering the browser's security key dialog.
//! 3. **Finalization**: Captures the binary response from the authenticator, encodes
//!    it back to Base64URL, and returns a JSON-serializable structure compatible with
//!    the `webauthn-rs` backend.

use crate::app_lib::AppError;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use js_sys::{Array, Object, Reflect, Uint8Array};
use serde::Serialize;
use serde_json::Value;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, CredentialCreationOptions,
    CredentialRequestOptions, PublicKeyCredential,
};

/// Registers a new hardware security key.
pub async fn register_key(challenge: &Value) -> Result<Value, AppError> {
    let window = web_sys::window().ok_or_else(|| AppError::Config("Window not found".into()))?;
    let navigator = window.navigator();
    let credentials = navigator.credentials();

    // 1. Prepare options
    let pk_options = challenge.get("publicKey").unwrap_or(challenge);

    let js_options = Object::new();

    // challenge
    let challenge_b64 = pk_options["challenge"]
        .as_str()
        .ok_or_else(|| AppError::Config("Missing challenge".into()))?;
    let challenge_buf = decode_base64_to_uint8array(challenge_b64)?;
    Reflect::set(&js_options, &"challenge".into(), &challenge_buf)
        .map_err(|_| AppError::Config("Failed to set challenge".into()))?;

    // user
    if let Some(user) = pk_options.get("user") {
        let js_user = Object::new();
        // Copy simple fields
        if let Some(name) = user["name"].as_str() {
            Reflect::set(&js_user, &"name".into(), &name.into()).ok();
        }
        if let Some(display_name) = user["displayName"].as_str() {
            Reflect::set(&js_user, &"displayName".into(), &display_name.into()).ok();
        }
        // Decode ID
        if let Some(id_b64) = user["id"].as_str() {
            let id_buf = decode_base64_to_uint8array(id_b64)?;
            Reflect::set(&js_user, &"id".into(), &id_buf).ok();
        }
        Reflect::set(&js_options, &"user".into(), &js_user).ok();
    }

    // rp
    if let Some(rp) = pk_options.get("rp") {
        let js_rp = Object::new();
        if let Some(name) = rp["name"].as_str() {
            Reflect::set(&js_rp, &"name".into(), &name.into()).ok();
        }
        if let Some(id) = rp["id"].as_str() {
            Reflect::set(&js_rp, &"id".into(), &id.into()).ok();
        }
        Reflect::set(&js_options, &"rp".into(), &js_rp).ok();
    }

    // pubKeyCredParams
    if let Some(params) = pk_options["pubKeyCredParams"].as_array() {
        let js_params = Array::new();
        for param in params {
            let js_param = Object::new();
            if let Some(alg) = param["alg"].as_i64() {
                Reflect::set(&js_param, &"alg".into(), &(alg as f64).into()).ok();
            }
            if let Some(typ) = param["type"].as_str() {
                Reflect::set(&js_param, &"type".into(), &typ.into()).ok();
            }
            js_params.push(&js_param);
        }
        Reflect::set(&js_options, &"pubKeyCredParams".into(), &js_params).ok();
    }

    // timeout
    if let Some(timeout) = pk_options["timeout"].as_u64() {
        Reflect::set(&js_options, &"timeout".into(), &(timeout as f64).into()).ok();
    }

    // attestation
    if let Some(attestation) = pk_options["attestation"].as_str() {
        Reflect::set(&js_options, &"attestation".into(), &attestation.into()).ok();
    }

    // authenticatorSelection
    if let Some(selection) = pk_options.get("authenticatorSelection") {
        let js_selection = Object::new();
        if let Some(auth_attachment) = selection["authenticatorAttachment"].as_str() {
            Reflect::set(
                &js_selection,
                &"authenticatorAttachment".into(),
                &auth_attachment.into(),
            )
            .ok();
        }
        if let Some(require_resident_key) = selection["requireResidentKey"].as_bool() {
            Reflect::set(
                &js_selection,
                &"requireResidentKey".into(),
                &require_resident_key.into(),
            )
            .ok();
        }
        if let Some(resident_key) = selection["residentKey"].as_str() {
            Reflect::set(&js_selection, &"residentKey".into(), &resident_key.into()).ok();
        }
        if let Some(user_verification) = selection["userVerification"].as_str() {
            Reflect::set(
                &js_selection,
                &"userVerification".into(),
                &user_verification.into(),
            )
            .ok();
        }
        Reflect::set(&js_options, &"authenticatorSelection".into(), &js_selection).ok();
    }

    // excludeCredentials
    if let Some(excludes) = pk_options["excludeCredentials"].as_array() {
        let js_excludes = Array::new();
        for cred in excludes {
            let js_cred = Object::new();
            if let Some(type_) = cred["type"].as_str() {
                Reflect::set(&js_cred, &"type".into(), &type_.into()).ok();
            }
            if let Some(id_b64) = cred["id"].as_str() {
                let id_buf = decode_base64_to_uint8array(id_b64)?;
                Reflect::set(&js_cred, &"id".into(), &id_buf).ok();
            }
            // transports
            if let Some(transports) = cred["transports"].as_array() {
                let js_transports = Array::new();
                for t in transports {
                    if let Some(s) = t.as_str() {
                        js_transports.push(&s.into());
                    }
                }
                Reflect::set(&js_cred, &"transports".into(), &js_transports).ok();
            }
            js_excludes.push(&js_cred);
        }
        Reflect::set(&js_options, &"excludeCredentials".into(), &js_excludes).ok();
    }

    // extensions
    if let Some(extensions) = pk_options.get("extensions") {
        // Naive copy for simple extensions
        let serializer = serde_wasm_bindgen::Serializer::json_compatible();
        if let Ok(js_ext) = extensions.serialize(&serializer) {
            Reflect::set(&js_options, &"extensions".into(), &js_ext).ok();
        }
    }

    let create_options = Object::new();
    Reflect::set(&create_options, &"publicKey".into(), &js_options)
        .map_err(|_| AppError::Config("Failed to set publicKey".into()))?;

    let create_options = create_options.unchecked_into::<CredentialCreationOptions>();

    // 2. Call create
    let promise = credentials
        .create_with_options(&create_options)
        .map_err(|e| AppError::Config(format!("WebAuthn create failed: {:?}", e)))?;

    let result = JsFuture::from(promise).await.map_err(|e| {
        let err_str = format!("{:?}", e);
        if err_str.contains("InvalidStateError") {
            AppError::Config("This security key is already registered.".to_string())
        } else if err_str.contains("NotAllowedError") {
            AppError::Config("Operation timed out or was cancelled.".to_string())
        } else {
            AppError::Config(format!("Hardware key registration failed: {:?}", e))
        }
    })?;

    let credential = result
        .dyn_into::<PublicKeyCredential>()
        .map_err(|_| AppError::Config("Invalid credential type".into()))?;

    // 3. Convert back
    let raw_id = encode_arraybuffer_to_base64(credential.raw_id());

    let response = credential
        .response()
        .dyn_into::<AuthenticatorAttestationResponse>()
        .map_err(|_| AppError::Config("Invalid response type".into()))?;

    let attestation_object = encode_arraybuffer_to_base64(response.attestation_object());
    let client_data_json = encode_arraybuffer_to_base64(response.client_data_json());

    Ok(serde_json::json!({
        "id": credential.id(),
        "rawId": raw_id,
        "type": credential.type_(),
        "response": {
            "attestationObject": attestation_object,
            "clientDataJSON": client_data_json,
        }
    }))
}

/// Authenticates using an existing hardware security key.
pub async fn authenticate_key(challenge: &Value) -> Result<Value, AppError> {
    let window = web_sys::window().ok_or_else(|| AppError::Config("Window not found".into()))?;
    let navigator = window.navigator();
    let credentials = navigator.credentials();

    // 1. Prepare options
    let pk_options = challenge.get("publicKey").unwrap_or(challenge);

    let js_options = Object::new();

    // challenge
    let challenge_b64 = pk_options["challenge"]
        .as_str()
        .ok_or_else(|| AppError::Config("Missing challenge".into()))?;
    let challenge_buf = decode_base64_to_uint8array(challenge_b64)?;
    Reflect::set(&js_options, &"challenge".into(), &challenge_buf).ok();

    // timeout
    if let Some(timeout) = pk_options["timeout"].as_u64() {
        Reflect::set(&js_options, &"timeout".into(), &(timeout as f64).into()).ok();
    }

    // rpId
    if let Some(rp_id) = pk_options["rpId"].as_str() {
        Reflect::set(&js_options, &"rpId".into(), &rp_id.into()).ok();
    }

    // allowCredentials
    if let Some(allow) = pk_options["allowCredentials"].as_array() {
        let js_allow = Array::new();
        for cred in allow {
            let js_cred = Object::new();
            if let Some(type_) = cred["type"].as_str() {
                Reflect::set(&js_cred, &"type".into(), &type_.into()).ok();
            }
            if let Some(id_b64) = cred["id"].as_str() {
                let id_buf = decode_base64_to_uint8array(id_b64)?;
                Reflect::set(&js_cred, &"id".into(), &id_buf).ok();
            }
            // transports
            if let Some(transports) = cred["transports"].as_array() {
                let js_transports = Array::new();
                for t in transports {
                    if let Some(s) = t.as_str() {
                        js_transports.push(&s.into());
                    }
                }
                Reflect::set(&js_cred, &"transports".into(), &js_transports).ok();
            }
            js_allow.push(&js_cred);
        }
        Reflect::set(&js_options, &"allowCredentials".into(), &js_allow).ok();
    }

    // userVerification
    if let Some(uv) = pk_options["userVerification"].as_str() {
        Reflect::set(&js_options, &"userVerification".into(), &uv.into()).ok();
    }

    let get_options = Object::new();
    Reflect::set(&get_options, &"publicKey".into(), &js_options)
        .map_err(|_| AppError::Config("Failed to set publicKey".into()))?;

    let get_options = get_options.unchecked_into::<CredentialRequestOptions>();

    // 2. Call get
    let promise = credentials
        .get_with_options(&get_options)
        .map_err(|e| AppError::Config(format!("WebAuthn get failed: {:?}", e)))?;

    let result = JsFuture::from(promise).await.map_err(|e| {
        let err_str = format!("{:?}", e);
        if err_str.contains("NotAllowedError") {
            AppError::Config("Operation timed out or was cancelled.".to_string())
        } else {
            AppError::Config(format!("Hardware key authentication failed: {:?}", e))
        }
    })?;

    let credential = result
        .dyn_into::<PublicKeyCredential>()
        .map_err(|_| AppError::Config("Invalid credential type".into()))?;

    // 3. Convert back
    let raw_id = encode_arraybuffer_to_base64(credential.raw_id());

    let response = credential
        .response()
        .dyn_into::<AuthenticatorAssertionResponse>()
        .map_err(|_| AppError::Config("Invalid response type".into()))?;

    let authenticator_data = encode_arraybuffer_to_base64(response.authenticator_data());
    let client_data_json = encode_arraybuffer_to_base64(response.client_data_json());
    let signature = encode_arraybuffer_to_base64(response.signature());
    let user_handle = response.user_handle().map(encode_arraybuffer_to_base64);

    Ok(serde_json::json!({
        "id": credential.id(),
        "rawId": raw_id,
        "type": credential.type_(),
        "response": {
            "authenticatorData": authenticator_data,
            "clientDataJSON": client_data_json,
            "signature": signature,
            "userHandle": user_handle,
        }
    }))
}

fn decode_base64_to_uint8array(b64: &str) -> Result<Uint8Array, AppError> {
    // Try URL safe first, then standard (webauthn-rs often uses URL safe without padding)
    let bytes = URL_SAFE_NO_PAD
        .decode(b64)
        .or_else(|_| STANDARD.decode(b64))
        .map_err(|e| AppError::Config(format!("Invalid base64: {}", e)))?;
    Ok(Uint8Array::from(&bytes[..]))
}

fn encode_arraybuffer_to_base64(buffer: js_sys::ArrayBuffer) -> String {
    let bytes = Uint8Array::new(&buffer).to_vec();
    URL_SAFE_NO_PAD.encode(&bytes)
}
