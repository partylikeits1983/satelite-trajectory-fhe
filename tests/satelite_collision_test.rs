use tfhe::ServerKey;
use tfhe::prelude::*;
use tfhe::{ConfigBuilder, FheBool, FheUint32, generate_keys, set_server_key};

use sat_trajectory_fhe::common::{SatelliteData, safe_deserialize_item, safe_serialize_item};

/// This test uses two different satellite trajectories ensuring that no collision occurs.
#[tokio::test]
async fn test_satellite_no_collision() -> Result<(), Box<dyn std::error::Error>> {
    // Satellite trajectory data
    let sat1 = SatelliteData {
        x: [100, 101, 102],
        y: [200, 201, 202],
        z: [300, 301, 302],
    };

    let sat2 = SatelliteData {
        // Not matching sat1 in every coordinate at any index.
        x: [101, 401, 102],
        y: [200, 201, 202],
        z: [300, 601, 602],
    };

    // ======================================================
    // 1) Party A: Key generation, encryption (Satellite 1).
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
    // 2) Party B: Uses A's ciphertext against its own plaintext (sat2)
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

    // Compare A's encrypted values with B's plaintext (from sat2)
    let mut collision_ciphertexts_from_b: Vec<FheBool> = Vec::new();
    for i in 0..sat2.x.len() {
        let eq_x = dec_enc_sat1_x[i].eq(sat2.x[i]);
        let eq_y = dec_enc_sat1_y[i].eq(sat2.y[i]);
        let eq_z = dec_enc_sat1_z[i].eq(sat2.z[i]);
        let collision = eq_x & eq_y & eq_z;
        collision_ciphertexts_from_b.push(collision);
    }

    let ser_collision_from_b: Vec<Vec<u8>> = collision_ciphertexts_from_b
        .iter()
        .map(|cb| safe_serialize_item(cb).unwrap())
        .collect();

    // ===============================================================
    // 3) Party A decrypts the collision results from B.
    // ===============================================================
    let collision_ciphertexts_for_a: Vec<FheBool> = ser_collision_from_b
        .iter()
        .map(|bytes| safe_deserialize_item(bytes).unwrap())
        .collect();

    let mut collision_found = false;
    for ciph_bool in collision_ciphertexts_for_a.iter() {
        let is_collision: bool = ciph_bool.decrypt(&client_key_a);
        if is_collision {
            collision_found = true;
            println!("Party A sees a collision.");
        }
    }
    println!(
        "Result from B->A check: collision_found = {}",
        collision_found
    );

    // Assert no collision was detected.
    assert!(!collision_found, "Expected no collision from B->A check");

    // =================================================
    // 4) Party B: Key generation, encryption (Satellite 2).
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
    // 5) Party A: Compares B's ciphertext with its own plaintext (sat1)
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
    for ciph_bool in collision_ciphertexts_for_b.iter() {
        let is_collision: bool = ciph_bool.decrypt(&client_key_b);
        if is_collision {
            collision_found_b = true;
            println!("Party B sees a collision.");
        }
    }
    println!(
        "Result from A->B check: collision_found_b = {}",
        collision_found_b
    );

    // Assert no collision was detected.
    assert!(!collision_found_b, "Expected no collision from A->B check");

    Ok(())
}

/// This test intentionally creates a collision on index 0 between two satellite trajectories.
#[tokio::test]
async fn test_satellite_collision() -> Result<(), Box<dyn std::error::Error>> {
    // Define satellite trajectory data.
    // For sat1, we use a reference trajectory.
    let sat1 = SatelliteData {
        x: [100, 101, 102],
        y: [200, 201, 202],
        z: [300, 301, 302],
    };

    // For sat2, we intentionally set index 0 to be the same as sat1 (collision),
    // while keeping the other indexes different.
    let sat2 = SatelliteData {
        x: [100, 401, 402],
        y: [200, 501, 502],
        z: [300, 601, 602],
    };

    // ======================================================
    // 1) Party A: Key generation, encryption (Satellite 1).
    // ======================================================
    let config_a = ConfigBuilder::default().build();
    let (client_key_a, server_key_a) = generate_keys(config_a);

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

    // Serialize A's server key.
    let ser_server_key_a = bincode::serialize(&server_key_a)?;

    // =====================================================
    // 2) Party B: Uses A's ciphertext against its own plaintext (sat2)
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

    // Compare A's encrypted values with B's plaintext (sat2).
    // A collision should be detected at index 0.
    let mut collision_ciphertexts_from_b: Vec<FheBool> = Vec::new();
    for i in 0..sat2.x.len() {
        let eq_x = dec_enc_sat1_x[i].eq(sat2.x[i]);
        let eq_y = dec_enc_sat1_y[i].eq(sat2.y[i]);
        let eq_z = dec_enc_sat1_z[i].eq(sat2.z[i]);
        let collision = eq_x & eq_y & eq_z;
        collision_ciphertexts_from_b.push(collision);
    }

    let ser_collision_from_b: Vec<Vec<u8>> = collision_ciphertexts_from_b
        .iter()
        .map(|cb| safe_serialize_item(cb).unwrap())
        .collect();

    // ===============================================================
    // 3) Party A decrypts the collision results from B.
    // ===============================================================
    let collision_ciphertexts_for_a: Vec<FheBool> = ser_collision_from_b
        .iter()
        .map(|bytes| safe_deserialize_item(bytes).unwrap())
        .collect();

    let mut collision_found_a = false;
    for ciph_bool in collision_ciphertexts_for_a.iter() {
        let is_collision: bool = ciph_bool.decrypt(&client_key_a);
        if is_collision {
            collision_found_a = true;
            println!("Party A sees a collision.");
        }
    }
    println!(
        "Result from B->A check: collision_found_a = {}",
        collision_found_a
    );

    // Assert at least one collision was detected by Party A.
    assert!(collision_found_a, "Expected a collision from B->A check");

    // =================================================
    // 4) Party B: Key generation, encryption (Satellite 2).
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
    // 5) Party A: Compares B's ciphertext with its own plaintext (sat1)
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

    // Compare B's encrypted values with A's plaintext (sat1).
    // Since only index 0 is shared, a collision should be detected at that index.
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
    for ciph_bool in collision_ciphertexts_for_b.iter() {
        let is_collision: bool = ciph_bool.decrypt(&client_key_b);
        if is_collision {
            collision_found_b = true;
            println!("Party B sees a collision.");
        }
    }
    println!(
        "Result from A->B check: collision_found_b = {}",
        collision_found_b
    );

    // Assert at least one collision was detected by Party B.
    assert!(collision_found_b, "Expected a collision from A->B check");

    Ok(())
}
