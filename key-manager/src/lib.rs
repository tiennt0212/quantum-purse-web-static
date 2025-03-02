use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use bip39::{Language, Mnemonic};
use fips205::slh_dsa_shake_128f;
use fips205::traits::{SerDes, Signer, Verifier};
use getrandom::getrandom;
use hex::{decode, encode};
use js_sys::Uint8Array;
use scrypt::{scrypt, Params};
use wasm_bindgen::{prelude::*, JsValue};
use web_sys::console;
use zeroize::{Zeroize, ZeroizeOnDrop};

use indexed_db_futures::{
    database::Database, error::Error, prelude::*, transaction::TransactionMode,
};
// for internal encryption & decryption
use serde::{Deserialize, Serialize};
// for communication between wasm and JS
use serde_wasm_bindgen;

// Structure for encrypted data packet
#[wasm_bindgen]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptionPacket {
    salt: String,        // Hex-encoded
    iv: String,          // Hex-encoded
    cipher_text: String, // Hex-encoded
}

// Structure for SPHINCS+ signer
#[wasm_bindgen]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SphincsPlusSigner {
    sphincs_plus_pub_key: String, // Hex-encoded
    sphincs_plus_pri_enc: EncryptionPacket,
}

// Constants
const SALT_LENGTH: usize = 16; // 128-bit salt
const IV_LENGTH: usize = 12; // 96-bit IV for AES-GCM
const DB_NAME: &str = "quantum_purse_db";
const MASTER_KEY_STORE: &str = "master_key_store";
const CHILD_KEYS_STORE: &str = "child_keys_store";
const MASTER_KEY: &str = "master_key";

async fn open_db() -> Result<Database, Error> {
    let db = Database::open(DB_NAME)
        .with_version(1u8)
        .with_on_blocked(|_event| {
            console::log_1(&"Database upgrade blocked.".into());
            Ok(())
        })
        .with_on_upgrade_needed(|_event, db| {
            // Create master_key_store if it doesn't exist
            if !db.object_store_names().any(|name| name == MASTER_KEY_STORE) {
                db.create_object_store(MASTER_KEY_STORE).build()?;
            }
            // Create child_keys_store if it doesn't exist
            if !db.object_store_names().any(|name| name == CHILD_KEYS_STORE) {
                db.create_object_store(CHILD_KEYS_STORE).build()?;
            }
            Ok(())
        })
        .await
        .map_err(|e| {
            Error::from(JsValue::from_str(&format!(
                "Error opening IndexedDB: {}",
                e
            )))
        })?;
    Ok(db)
}

pub async fn set_master_seed(encryption_packet: EncryptionPacket) -> Result<(), Error> {
    let db = open_db().await?;
    let tx = db
        .transaction(MASTER_KEY_STORE)
        .with_mode(TransactionMode::Readwrite)
        .build()?;
    let store = tx.object_store(MASTER_KEY_STORE)?;

    let js_value = serde_wasm_bindgen::to_value(&encryption_packet)
        .map_err(|e| Error::from(JsValue::from_str(&e.to_string())))?;

    store.put(&js_value).with_key(MASTER_KEY).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn get_master_seed() -> Result<Option<EncryptionPacket>, Error> {
    let db = open_db().await?;
    let tx = db
        .transaction(MASTER_KEY_STORE)
        .with_mode(TransactionMode::Readonly)
        .build()?;
    let store = tx.object_store(MASTER_KEY_STORE)?;

    if let Some(js_value) = store.get(MASTER_KEY).await? {
        let encryption_packet: EncryptionPacket = serde_wasm_bindgen::from_value(js_value)
            .map_err(|e| Error::from(JsValue::from_str(&e.to_string())))?;
        Ok(Some(encryption_packet))
    } else {
        Ok(None)
    }
}

pub async fn set_child_key(child_key: SphincsPlusSigner) -> Result<(), Error> {
    let db = open_db().await?;
    let tx = db
        .transaction(CHILD_KEYS_STORE)
        .with_mode(TransactionMode::Readwrite)
        .build()?;
    let store = tx.object_store(CHILD_KEYS_STORE)?;

    let js_value = serde_wasm_bindgen::to_value(&child_key)
        .map_err(|e| Error::from(JsValue::from_str(&e.to_string())))?;

    match store
        .add(js_value)
        .with_key(child_key.sphincs_plus_pub_key)
        .build()
    {
        Ok(_) => {
            tx.commit().await?;
            Ok(())
        }
        Err(e) => {
            if let Error::DomException(dom_err) = e {
                if dom_err.name() == "ConstraintError" {
                    // Key exists, ignore per requirement
                    Ok(())
                } else {
                    Err(Error::DomException(dom_err))
                }
            } else {
                Err(e)
            }
        }
    }
}

pub async fn get_child_key(pub_key: &str) -> Result<Option<SphincsPlusSigner>, Error> {
    let db = open_db().await?;
    let tx = db
        .transaction(CHILD_KEYS_STORE)
        .with_mode(TransactionMode::Readonly)
        .build()?;
    let store = tx.object_store(CHILD_KEYS_STORE)?;

    if let Some(js_value) = store.get(pub_key).await? {
        let child_key: SphincsPlusSigner = serde_wasm_bindgen::from_value(js_value)
            .map_err(|e| Error::from(JsValue::from_str(&e.to_string())))?;
        Ok(Some(child_key))
    } else {
        Ok(None)
    }
}

pub async fn get_child_keys() -> Result<Vec<SphincsPlusSigner>, Error> {
    let db = open_db().await?;
    let tx = db
        .transaction(CHILD_KEYS_STORE)
        .with_mode(TransactionMode::Readonly)
        .build()?;
    let store = tx.object_store(CHILD_KEYS_STORE)?;

    let iter = store.get_all().await?;
    let mut child_keys = Vec::new();
    for result in iter {
        let js_value = result?;
        let child_key: SphincsPlusSigner = serde_wasm_bindgen::from_value(js_value)
            .map_err(|e| Error::from(JsValue::from_str(&e.to_string())))?;
        child_keys.push(child_key);
    }
    Ok(child_keys)
}

// TODO private function
// js_value trace in js env will be disposed by the javascript GC!
pub fn get_random_bytes(length: usize) -> Result<Vec<u8>, JsValue> {
    let mut buffer = vec![0u8; length];
    getrandom(buffer.as_mut_slice()).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(buffer)
}

/// Generate bip39 seed phrase and encrypt it
#[wasm_bindgen]
pub fn gen_seed_phrase() {
    let mut entropy = get_random_bytes(32).unwrap(); // 32 bytes for 256-bit entropy
    let mut mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy).unwrap();
    entropy.zeroize();
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
