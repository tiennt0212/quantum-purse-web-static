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

// Optional: Add a helper method to convert to JsValue for WASM
impl QuantumPurseError {
    pub fn to_jsvalue(&self) -> wasm_bindgen::JsValue {
        wasm_bindgen::JsValue::from_str(&self.to_string())
    }
}