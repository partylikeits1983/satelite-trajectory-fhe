use std::io::Cursor;
use tfhe::named::Named;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::{Unversionize, Versionize};
// Struct to group satellite trajectory data.
pub struct SatelliteData {
    pub x: [u32; 3],
    pub y: [u32; 3],
    pub z: [u32; 3],
}

pub fn safe_serialize_item<T>(item: &T) -> Result<Vec<u8>, Box<dyn std::error::Error>>
where
    T: serde::Serialize + Versionize + Named,
{
    let mut buf = Vec::new();
    safe_serialize(item, &mut buf, 1 << 20)?;
    Ok(buf)
}

pub fn safe_deserialize_item<T>(data: &[u8]) -> Result<T, Box<dyn std::error::Error>>
where
    T: serde::de::DeserializeOwned + Unversionize + Named,
{
    let cursor = Cursor::new(data);
    let item = safe_deserialize(cursor, 1 << 20)?;
    Ok(item)
}
