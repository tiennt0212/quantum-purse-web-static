use indexed_db_futures::error::Error as DBError;
use serde_wasm_bindgen::Error as SerdeError;
use std::fmt;

#[derive(Debug)]
pub enum KeyUnlockerError {
    SerializationError(String),
    DatabaseError(String),
}

impl fmt::Display for KeyUnlockerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyUnlockerError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            KeyUnlockerError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
        }
    }
}

impl KeyUnlockerError {
    pub fn to_jsvalue(&self) -> wasm_bindgen::JsValue {
        wasm_bindgen::JsValue::from_str(&self.to_string())
    }
}

impl From<DBError> for KeyUnlockerError {
    fn from(e: DBError) -> Self {
        KeyUnlockerError::DatabaseError(e.to_string())
    }
}

impl From<SerdeError> for KeyUnlockerError {
    fn from(e: SerdeError) -> Self {
        KeyUnlockerError::SerializationError(e.to_string())
    }
}
