use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use fips205::slh_dsa_shake_128f;
use fips205::traits::{SerDes, Signer, Verifier};
use hex::{decode, encode};
use js_sys::Uint8Array;
use scrypt::{scrypt, Params};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop};
use getrandom::getrandom;
use bip39::{Mnemonic, Language};
use web_sys::console; //for debug

// Structure for encrypted data packet
#[wasm_bindgen]
pub struct EncryptionPacket {
    salt: String,        // Hex-encoded
    iv: String,          // Hex-encoded
    cipher_text: String, // Hex-encoded
}

// Structure for SPHINCS+ signer
#[wasm_bindgen]
pub struct SphincsPlusSigner {
    sphincs_plus_pub_key: String, // Hex-encoded
    sphincs_plus_pri_enc: EncryptionPacket,
}

// Constants
const SALT_LENGTH: usize = 16; // 128-bit salt
const IV_LENGTH: usize = 12; // 96-bit IV for AES-GCM

// TODO private function
// js_value trace in js env will be disposed by the javascript GC!
pub fn get_random_bytes(length: usize) -> Result<Vec<u8>, JsValue> {
    let mut buffer = vec![0u8; length];
    getrandom(buffer.as_mut_slice()).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(buffer)
}

/// Generate bip39 seed phrase and encrypt it
#[wasm_bindgen]
pub fn gen_seed(password: Uint8Array) {
    let mut entropy = get_random_bytes(32).unwrap(); // 32 bytes for 256-bit entropy
    let mut mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy).unwrap();
    // console::log_1(&">>>WASM mnemonic 1 2 3 4 5".into());
    // console::log_1(&format!("Mnemonic: {}", mnemonic).into());
    entropy.zeroize();
    mnemonic.zeroize();
}

/// Encrypts data using AES-GCM with a password-derived key.
#[wasm_bindgen]
pub fn encrypt(password: Uint8Array, input: Uint8Array) -> Result<EncryptionPacket, JsValue> {
    let mut password = password.to_vec();
    let mut input = input.to_vec();

    // Generate random salt and IV
    let mut salt = vec![0u8; SALT_LENGTH];
    let mut iv = vec![0u8; IV_LENGTH];
    let random_bytes = get_random_bytes(SALT_LENGTH + IV_LENGTH).unwrap();
    salt.copy_from_slice(&random_bytes[0..SALT_LENGTH]);
    iv.copy_from_slice(&random_bytes[SALT_LENGTH..]);

    // Derive key using Scrypt
    let mut scrypt_key = vec![0u8; 32];
    scrypt(&password, &salt, &Params::default(), &mut scrypt_key)
        .map_err(|e| JsValue::from_str(&format!("Scrypt error: {:?}", e)))?;

    // Encrypt using AES-GCM
    let aes_key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&scrypt_key);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&iv);
    let cipher_text = cipher
        .encrypt(nonce, input.as_ref())
        .map_err(|e| JsValue::from_str(&format!("Encryption error: {:?}", e)))?;

    password.zeroize();
    scrypt_key.zeroize(); // aes_key gone
    input.zeroize();

    Ok(EncryptionPacket {
        salt: encode(salt),
        iv: encode(iv),
        cipher_text: encode(cipher_text),
    })
}

/// Decrypts data using AES-GCM with a password-derived key.
#[wasm_bindgen]
pub fn decrypt(password: Uint8Array, packet: EncryptionPacket) -> Result<Uint8Array, JsValue> {
    let mut password = password.to_vec();
    let salt = decode(packet.salt)
        .map_err(|e| JsValue::from_str(&format!("Salt decode error: {:?}", e)))?;
    let iv =
        decode(packet.iv).map_err(|e| JsValue::from_str(&format!("IV decode error: {:?}", e)))?;
    let cipher_text = decode(packet.cipher_text)
        .map_err(|e| JsValue::from_str(&format!("Ciphertext decode error: {:?}", e)))?;

    // Derive key using Scrypt
    let mut scrypt_key = vec![0u8; 32];
    scrypt(&password, &salt, &Params::default(), &mut scrypt_key)
        .map_err(|e| JsValue::from_str(&format!("Scrypt error: {:?}", e)))?;

    // Decrypt using AES-GCM
    let aes_key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&scrypt_key);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&iv);
    let plain_text = cipher
        .decrypt(nonce, cipher_text.as_ref())
        .map_err(|e| JsValue::from_str(&format!("Decryption error: {:?}", e)))?;

    password.zeroize();
    scrypt_key.zeroize();

    Ok(Uint8Array::from(plain_text.as_slice()))
}

/// Generates a new SPHINCS+ account from a master seed.
#[wasm_bindgen]
pub fn gen_account(
    password: Uint8Array,
    encrypted_seed: EncryptionPacket,
    child_index: u32, // TODO
) -> Result<SphincsPlusSigner, JsValue> {
    let password = password.to_vec();
    let mut password_clone = password.clone();

    // Decrypt master seed
    let seed = decrypt(Uint8Array::from(password.as_slice()), encrypted_seed)?;
    let mut seed = seed.to_vec();

    // Derive SPHINCS+ seed using path
    let path = format!("pq/ckb/{}", child_index);
    let scrypt_params = Params::new(16, 8, 1, 48).unwrap();
    let mut sphincs_seed = vec![0u8; 48];
    scrypt(&seed, path.as_bytes(), &scrypt_params, &mut sphincs_seed)
        .map_err(|e| JsValue::from_str(&format!("Scrypt error: {:?}", e)))?;

    // Generate SPHINCS+ key pair
    // TODO random fallback
    let (pub_key, pri_key) = slh_dsa_shake_128f::try_keygen()?;
    let mut pri_key_bytes = pri_key.into_bytes();

    // Encrypt private key
    let encrypted_pri = encrypt(
        Uint8Array::from(password_clone.as_slice()),
        Uint8Array::from(pri_key_bytes.as_slice()),
    )?;

    seed.zeroize();
    sphincs_seed.zeroize();
    password_clone.zeroize();
    pri_key_bytes.zeroize();

    // TODO not return but settle to DB
    Ok(SphincsPlusSigner {
        sphincs_plus_pub_key: encode(pub_key.into_bytes()),
        sphincs_plus_pri_enc: encrypted_pri,
    })
}

/// Imports a seed phrase by encrypting it.
#[wasm_bindgen]
pub fn import_seed_phrase(
    seed_phrase: Uint8Array,
    password: Uint8Array,
) -> Result<EncryptionPacket, JsValue> {
    let mut seed_phrase = seed_phrase.to_vec();
    let encrypted_seed = encrypt(password, Uint8Array::from(seed_phrase.as_slice()))?;
    seed_phrase.zeroize();
    // TODO settle to DB
    Ok(encrypted_seed)
}

/// Exports the seed phrase by decrypting it.
#[wasm_bindgen]
pub fn export_seed_phrase(
    password: Uint8Array,
    encrypted_seed: EncryptionPacket,
) -> Result<Uint8Array, JsValue> {
    let seed = decrypt(password, encrypted_seed)?;
    Ok(seed)
}

/// Signs a message with SPHINCS+ after decrypting the private key.
#[wasm_bindgen]
pub fn sign(
    password: Uint8Array,
    signer: SphincsPlusSigner,
    message: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let mut password = password.to_vec();
    let pri_key = decrypt(
        Uint8Array::from(password.as_slice()),
        signer.sphincs_plus_pri_enc,
    )?;
    let mut pri_key = pri_key.to_vec();

    // let signing_key = SigningKey::<slh_dsa_shake_128f>::from_bytes(&pri_key)
    //     .map_err(|e| JsValue::from_str(&format!("Invalid private key: {:?}", e)))?;
    // let signature = signing_key.sign(&message.to_vec());
    pri_key.zeroize();

    Ok(Uint8Array::from(password.as_slice()))
}
