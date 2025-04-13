## Using FHE for Privacy-Preserving Satellite Collision Checks

Imagine a scenario where NASA and Roscosmos each manage a fleet of satellites in Earth orbit. To avoid potential collisions, both agencies need to determine if any satellites’ orbits intersect. However, neither agency wants to reveal its sensitive orbital data—for example, NASA would rather not expose the precise coordinates or trajectories of its new space telescope to Roscosmos.

**Fully Homomorphic Encryption (FHE)** provides an innovative solution to this dilemma:

1. **NASA encrypts** all its satellite positions (e.g., `(x, y, z)` coordinates over time) using its own secret key.
2. **NASA sends** the encrypted coordinates along with an **evaluation key** (also referred to as the “server key” in TFHE) to Roscosmos. Importantly, this key enables only homomorphic operations and does not allow Roscosmos to decrypt the data.
3. **Roscosmos** then takes NASA’s encrypted data and compares it with its own plaintext satellite positions to determine if any orbits intersect.
4. The resulting comparison output (such as “collision: true or false”) remains **encrypted**. Roscosmos sends these encrypted results back to NASA.
5. **NASA**, the sole possessor of the decryption key, decrypts the data and discovers whether any collisions occur—all without disclosing its raw orbital data.

In this way, **Roscosmos** can perform the necessary computations on **NASA’s** data without ever seeing it, and vice versa. This is the fundamental advantage of FHE.

---

When satellites are launched, space agencies and private companies strive to assess any risk of collision. In competitive or adversarial contexts (such as “spy satellites”), neither party wishes to expose its precise orbital paths. That’s where **Fully Homomorphic Encryption (FHE)** steps in:

1. **Each party encrypts its satellite’s position data** with its own secret key.
2. The party then shares an **evaluation key** (or “server key” in TFHE) with the other side, which permits that party to perform computations on the encrypted data—without the ability to decrypt it.
3. Both parties perform collision checks *homomorphically*: they compare positions, compute distances, or evaluate relevant geometries directly on the encrypted data.
4. The encrypted outcomes of these checks are sent back, and only the respective party can decrypt them using its secret key.

This methodology ensures that while each party learns whether a collision is imminent, they never gain access to each other’s raw orbit data. Additionally, FHE’s robust cryptographic techniques prevent brute-force attacks; even if an adversary attempts to guess the other party’s data, they cannot determine its accuracy.

### Core Idea: “Compare Without Revealing”

Consider the following example, where two satellites—`sat1` and `sat2`—belong to different parties, Party A and Party B. The process unfolds as follows:

1. **Party A encrypts its data** using its secret key.
2. **Party A shares only its “server key”** with Party B.
3. **Party B uses this server key** to perform homomorphic equality comparisons (using the `.eq` operation) between the encrypted coordinates of `sat1` and the plaintext coordinates of `sat2`. Although the comparisons yield encrypted booleans, Party B cannot decrypt them.
4. **Party A receives these encrypted booleans**, and by decrypting them, determines if a collision has occurred.

The process is then repeated in reverse—where Party B encrypts its data and shares its own server key with Party A—so that both parties can independently verify the results without exposing their sensitive data.

---

## Walkthrough of the Code

The following sections provide a simplified overview of the essential parts of the provided Rust code, which utilizes `tokio` test syntax for async support.

Running all tests:
```
cargo test --release --nocapture
```


```
cargo test --release -- --exact test_satellite_collision --nocapture
```

### 1) Setting Up the Satellite Data

```rust
struct SatelliteData {
    x: [u32; 3],
    y: [u32; 3],
    z: [u32; 3],
}

// Initialize each party’s satellite coordinates
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
```

Each satellite is represented by an array of `(x, y, z)` coordinates, tracking positions over three time steps—idealizing the idea of capturing snapshots along an orbital path.

### 2) Party A Generates Keys & Encrypts Its Data

```rust
let config = ConfigBuilder::default().build();
let (client_key_a, server_key_a) = generate_keys(config);

// Encrypt sat1’s x, y, z arrays
let enc_sat1_x: Vec<FheUint32> = sat1
    .x
    .iter()
    .map(|&v| FheUint32::try_encrypt(v, &client_key_a).unwrap())
    .collect();
// Similar encryption is applied for enc_sat1_y and enc_sat1_z ...
```

Here, `client_key_a` serves as Party A’s secret key, while `server_key_a` is the public evaluation key shared with Party B, allowing computations on the encrypted data without revealing the underlying information.

### 3) Party B Receives A’s Encrypted Data & Server Key

```rust
let dec_enc_sat1_x = ser_enc_sat1_x
    .iter()
    .map(|bytes| safe_deserialize_item(bytes).unwrap())
    .collect();
// ... similar steps for y and z ...

let server_key_a_for_b: ServerKey = bincode::deserialize(&ser_server_key_a)?;
set_server_key(server_key_a_for_b);
```

Party B deserializes the encrypted data and loads the server key provided by Party A. By setting the server key, Party B configures the TFHE library for the subsequent homomorphic operations.

### 4) B Compares A’s Encrypted Positions with Its Own Plaintext Data

```rust
for i in 0..sat2.x.len() {
    let eq_x = dec_enc_sat1_x[i].eq(sat2.x[i]); // ciphertext vs plaintext
    let eq_y = dec_enc_sat1_y[i].eq(sat2.y[i]);
    let eq_z = dec_enc_sat1_z[i].eq(sat2.z[i]);
    let collision = eq_x & eq_y & eq_z; // combine equality results
    collision_ciphertexts_from_b.push(collision);
}
```

In this step, Party B performs the collision check by comparing each coordinate dimension. The results are stored as encrypted booleans, which Party B forwards to Party A.

### 5) A Decrypts the Collision Results

```rust
let is_collision: bool = ciph_bool.decrypt(&client_key_a);
if is_collision {
    println!("Party A sees collision at index {}.", i);
}
```

Only Party A can decrypt the collision results with its secret key. Thus, Party A learns whether a collision exists, while Party B remains unaware of the detailed findings.

### 6) Repeat in the Other Direction

Finally, the process is mirrored: Party B encrypts its satellite data and shares its server key with Party A, allowing Party A to conduct an independent collision check. This two-way process ensures that each party can confirm the presence (or absence) of collisions without compromising the security of their sensitive orbital data.

---

## Key Takeaways

- **Fully Homomorphic Encryption (FHE)** enables performing arithmetic and logical operations on encrypted data without the need for decryption during the process.
- Each party retains its **secret key** and shares only an **evaluation (server) key**, which permits computations on the encrypted data while preserving confidentiality.
- The final results of collision checks remain encrypted until they are sent back to the data owner, ensuring that sensitive positional data remains secure even when shared.

In practical applications, this methodology can extend to more complex geometrical calculations (such as thresholds based on distances or elliptical orbital paths). The underlying principle remains unchanged: secure homomorphic operations enable critical cross-party computations while ensuring that sensitive data is never directly exposed—even between potentially adversarial entities.
