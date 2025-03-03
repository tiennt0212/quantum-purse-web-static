use indexed_db_futures::error::Error as DBError;
use serde_wasm_bindgen::Error as SerdeError;
use std::fmt;

#[derive(Debug)]
pub enum QuantumPurseError {
    SerializationError(String),
    DatabaseError(String),
}

impl fmt::Display for QuantumPurseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            QuantumPurseError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            QuantumPurseError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
        }
    }
}

impl QuantumPurseError {
    pub fn to_jsvalue(&self) -> wasm_bindgen::JsValue {
        wasm_bindgen::JsValue::from_str(&self.to_string())
    }
}

impl From<DBError> for QuantumPurseError {
    fn from(e: DBError) -> Self {
        QuantumPurseError::DatabaseError(e.to_string())
    }
}

impl From<SerdeError> for QuantumPurseError {
    fn from(e: SerdeError) -> Self {
        QuantumPurseError::SerializationError(e.to_string())
    }
}
