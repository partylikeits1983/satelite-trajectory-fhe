use bincode;
use sha2::{Digest, Sha256};
use std::time::Instant;
use tfhe::prelude::*;
use tfhe::{ConfigBuilder, FheUint32, generate_keys, set_server_key};

#[tokio::test]
async fn test_less_than() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configure TFHE for u32 operations.
    let config = ConfigBuilder::default().build();

    // 2. Generate keys.
    let (client_key, server_keys) = generate_keys(config);

    // Two clear (unencrypted) values:
    let clear_a = 11u32;
    let clear_b = 10u32;

    // 3. Encrypt the values using the client_key.
    let encrypted_a = FheUint32::try_encrypt(clear_a, &client_key)?;
    let encrypted_b = FheUint32::try_encrypt(clear_b, &client_key)?;

    // 4. Set the server key so we can perform homomorphic operations.
    set_server_key(server_keys);

    // --- Serialization ---
    let serialized_a = bincode::serialize(&encrypted_a)?;
    let serialized_b = bincode::serialize(&encrypted_b)?;

    // --- Hashing & byte size ---
    let mut hasher_a = Sha256::new();
    hasher_a.update(&serialized_a);
    let hash_a = hasher_a.finalize();

    let mut hasher_b = Sha256::new();
    hasher_b.update(&serialized_b);
    let hash_b = hasher_b.finalize();

    println!("Hash of Encrypted A: {:x}", hash_a);
    println!("Hash of Encrypted B: {:x}", hash_b);
    println!("Size of Encrypted A (bytes): {}", serialized_a.len());
    println!("Size of Encrypted B (bytes): {}", serialized_b.len());

    // --- Deserialization ---
    let deserialized_a: FheUint32 = bincode::deserialize(&serialized_a)?;
    let deserialized_b: FheUint32 = bincode::deserialize(&serialized_b)?;

    // --- Time the homomorphic comparison & decryption ---
    let start = Instant::now();

    let encrypted_is_greater = deserialized_a.gt(&deserialized_b);
    let is_greater: bool = encrypted_is_greater.decrypt(&client_key);

    let duration = start.elapsed();
    println!("Homomorphic comparison + decryption took: {:?}", duration);

    println!(
        "Is {} > {}? Homomorphic result: {}",
        clear_a, clear_b, is_greater
    );

    // Here's the test assertion:
    assert!(
        is_greater,
        "Expected {} > {}, but result was false",
        clear_a, clear_b
    );

    Ok(())
}
