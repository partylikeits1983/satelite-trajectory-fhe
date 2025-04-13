use std::io::Cursor;
use tfhe::ServerKey; // use the re-exported ServerKey
use tfhe::named::Named;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::{ConfigBuilder, FheBool, FheUint32, generate_keys, set_server_key};
use tfhe::{Unversionize, Versionize, prelude::*};

fn safe_serialize_item<T>(item: &T) -> Result<Vec<u8>, Box<dyn std::error::Error>>
where
    T: serde::Serialize + Versionize + Named,
{
    let mut buf = Vec::new();
    safe_serialize(item, &mut buf, 1 << 20)?;
    Ok(buf)
}

fn safe_deserialize_item<T>(data: &[u8]) -> Result<T, Box<dyn std::error::Error>>
where
    T: serde::de::DeserializeOwned + Unversionize + Named,
{
    let cursor = Cursor::new(data);
    let item = safe_deserialize(cursor, 1 << 20)?;
    Ok(item)
}

// Struct to group satellite trajectory data.
struct SatelliteData {
    x: [u32; 3],
    y: [u32; 3],
    z: [u32; 3],
}

#[tokio::test]
async fn test_satellite_collision() -> Result<(), Box<dyn std::error::Error>> {
    // =================================================
    // Satellite trajectory data is declared at the beginning.
    // =================================================
    let sat1 = SatelliteData {
        x: [100, 101, 102],
        y: [200, 201, 202],
        z: [300, 301, 302],
    };

    let sat2 = SatelliteData {
        x: [101, 401, 102],
        y: [200, 201, 202],
        z: [300, 601, 602],
    };

    // ======================================================
    // 1) Party A Key Generation & Encryption (Satellite 1)
    // ======================================================
    let config = ConfigBuilder::default().build();
    let (client_key_a, server_key_a) = generate_keys(config);

    let enc_sat1_x: Vec<FheUint32> = sat1
        .x
        .iter()
        .map(|&v| FheUint32::try_encrypt(v, &client_key_a).unwrap())
        .collect();
    let enc_sat1_y: Vec<FheUint32> = sat1
        .y
        .iter()
        .map(|&v| FheUint32::try_encrypt(v, &client_key_a).unwrap())
        .collect();
    let enc_sat1_z: Vec<FheUint32> = sat1
        .z
        .iter()
        .map(|&v| FheUint32::try_encrypt(v, &client_key_a).unwrap())
        .collect();

    // Serialize each ciphertext individually.
    let ser_enc_sat1_x: Vec<Vec<u8>> = enc_sat1_x
        .iter()
        .map(|ct| safe_serialize_item(ct).unwrap())
        .collect();
    let ser_enc_sat1_y: Vec<Vec<u8>> = enc_sat1_y
        .iter()
        .map(|ct| safe_serialize_item(ct).unwrap())
        .collect();
    let ser_enc_sat1_z: Vec<Vec<u8>> = enc_sat1_z
        .iter()
        .map(|ct| safe_serialize_item(ct).unwrap())
        .collect();

    // Serialize A's SERVER key using bincode.
    let ser_server_key_a = bincode::serialize(&server_key_a)?;

    // =====================================================
    // 2) Party B uses A's ciphertext vs. its own plaintext
    //     using A's server key.
    // =====================================================
    let dec_enc_sat1_x: Vec<FheUint32> = ser_enc_sat1_x
        .iter()
        .map(|bytes| safe_deserialize_item(bytes).unwrap())
        .collect();
    let dec_enc_sat1_y: Vec<FheUint32> = ser_enc_sat1_y
        .iter()
        .map(|bytes| safe_deserialize_item(bytes).unwrap())
        .collect();
    let dec_enc_sat1_z: Vec<FheUint32> = ser_enc_sat1_z
        .iter()
        .map(|bytes| safe_deserialize_item(bytes).unwrap())
        .collect();

    let server_key_a_for_b: ServerKey = bincode::deserialize(&ser_server_key_a)?;
    set_server_key(server_key_a_for_b);

    // Compare A's encrypted values with B's plaintext (from sat2) using eq (ciphertext vs plaintext).
    let mut collision_ciphertexts_from_b: Vec<FheBool> = Vec::new();
    for i in 0..sat2.x.len() {
        let eq_x = dec_enc_sat1_x[i].eq(sat2.x[i]);
        let eq_y = dec_enc_sat1_y[i].eq(sat2.y[i]);
        let eq_z = dec_enc_sat1_z[i].eq(sat2.z[i]);
        let collision = eq_x & eq_y & eq_z;
        collision_ciphertexts_from_b.push(collision);
    }

    // Serialize each collision ciphertext.
    let ser_collision_from_b: Vec<Vec<u8>> = collision_ciphertexts_from_b
        .iter()
        .map(|cb| safe_serialize_item(cb).unwrap())
        .collect();

    // ===============================================================
    // 3) Party A decrypts the collision results coming back from B.
    // ===============================================================
    let collision_ciphertexts_for_a: Vec<FheBool> = ser_collision_from_b
        .iter()
        .map(|bytes| safe_deserialize_item(bytes).unwrap())
        .collect();

    let mut collision_found = false;
    for (i, ciph_bool) in collision_ciphertexts_for_a.iter().enumerate() {
        let is_collision: bool = ciph_bool.decrypt(&client_key_a);
        if is_collision {
            collision_found = true;
            println!("Party A sees collision at index {} (A's key scenario).", i);
        }
    }
    println!(
        "Result from B->A check: collision_found = {}",
        collision_found
    );

    // =================================================
    // 4) Party B Key Generation & Encryption (Satellite 2)
    // =================================================
    let config_b = ConfigBuilder::default().build();
    let (client_key_b, server_key_b) = generate_keys(config_b);

    let enc_sat2_x: Vec<FheUint32> = sat2
        .x
        .iter()
        .map(|&v| FheUint32::try_encrypt(v, &client_key_b).unwrap())
        .collect();
    let enc_sat2_y: Vec<FheUint32> = sat2
        .y
        .iter()
        .map(|&v| FheUint32::try_encrypt(v, &client_key_b).unwrap())
        .collect();
    let enc_sat2_z: Vec<FheUint32> = sat2
        .z
        .iter()
        .map(|&v| FheUint32::try_encrypt(v, &client_key_b).unwrap())
        .collect();

    let ser_enc_sat2_x: Vec<Vec<u8>> = enc_sat2_x
        .iter()
        .map(|ct| safe_serialize_item(ct).unwrap())
        .collect();
    let ser_enc_sat2_y: Vec<Vec<u8>> = enc_sat2_y
        .iter()
        .map(|ct| safe_serialize_item(ct).unwrap())
        .collect();
    let ser_enc_sat2_z: Vec<Vec<u8>> = enc_sat2_z
        .iter()
        .map(|ct| safe_serialize_item(ct).unwrap())
        .collect();

    let ser_server_key_b = bincode::serialize(&server_key_b)?;

    // =====================================================
    // 5) Party A compares B's ciphertext to its own plaintext
    //     using B's server key.
    // =====================================================
    let dec_enc_sat2_x: Vec<FheUint32> = ser_enc_sat2_x
        .iter()
        .map(|bytes| safe_deserialize_item(bytes).unwrap())
        .collect();
    let dec_enc_sat2_y: Vec<FheUint32> = ser_enc_sat2_y
        .iter()
        .map(|bytes| safe_deserialize_item(bytes).unwrap())
        .collect();
    let dec_enc_sat2_z: Vec<FheUint32> = ser_enc_sat2_z
        .iter()
        .map(|bytes| safe_deserialize_item(bytes).unwrap())
        .collect();

    let server_key_b_for_a: ServerKey = bincode::deserialize(&ser_server_key_b)?;
    set_server_key(server_key_b_for_a);

    let mut collision_ciphertexts_from_a: Vec<FheBool> = Vec::new();
    for i in 0..sat1.x.len() {
        let eq_x = dec_enc_sat2_x[i].eq(sat1.x[i]);
        let eq_y = dec_enc_sat2_y[i].eq(sat1.y[i]);
        let eq_z = dec_enc_sat2_z[i].eq(sat1.z[i]);
        let collision = eq_x & eq_y & eq_z;
        collision_ciphertexts_from_a.push(collision);
    }

    let ser_collision_from_a: Vec<Vec<u8>> = collision_ciphertexts_from_a
        .iter()
        .map(|cb| safe_serialize_item(cb).unwrap())
        .collect();

    // ===============================================================
    // 6) Party B decrypts the collision results from A.
    // ===============================================================
    let collision_ciphertexts_for_b: Vec<FheBool> = ser_collision_from_a
        .iter()
        .map(|bytes| safe_deserialize_item(bytes).unwrap())
        .collect();

    let mut collision_found_b = false;
    for (i, ciph_bool) in collision_ciphertexts_for_b.iter().enumerate() {
        let is_collision: bool = ciph_bool.decrypt(&client_key_b);
        if is_collision {
            collision_found_b = true;
            println!("Party B sees collision at index {} (B's key scenario).", i);
        }
    }
    println!(
        "Result from A->B check: collision_found_b = {}",
        collision_found_b
    );

    Ok(())
}
