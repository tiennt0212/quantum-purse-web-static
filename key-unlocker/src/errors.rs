use indexed_db_futures::error::Error as DBError;
use serde_wasm_bindgen::Error as SerdeError;
use std::fmt;

#[derive(Debug)]
pub enum KeyUnlocker {
    SerializationError(String),
    DatabaseError(String),
}

impl fmt::Display for KeyUnlocker {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyUnlocker::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            KeyUnlocker::DatabaseError(msg) => write!(f, "Database error: {}", msg),
        }
    }
}

impl KeyUnlocker {
    pub fn to_jsvalue(&self) -> wasm_bindgen::JsValue {
        wasm_bindgen::JsValue::from_str(&self.to_string())
    }
}

impl From<DBError> for KeyUnlocker {
    fn from(e: DBError) -> Self {
        KeyUnlocker::DatabaseError(e.to_string())
    }
}

impl From<SerdeError> for KeyUnlocker {
    fn from(e: SerdeError) -> Self {
        KeyUnlocker::SerializationError(e.to_string())
    }
}
