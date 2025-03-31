use hex::{decode as hex_decode, encode as hex_encode};
use rand::{rng, RngCore};

use bitcoinpqc::{generate_keypair, sign, verify, Algorithm, PublicKey, SecretKey, Signature};

// Original random data generation function (commented out for deterministic tests)
fn _get_random_bytes_original(size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    rng().fill_bytes(&mut bytes);
    bytes
}

// Function to return fixed test data based on predefined hex strings
// This ensures deterministic test results
fn get_random_bytes(size: usize) -> Vec<u8> {
    match size {
        128 => {
            // Single common test vector for all tests (128 bytes)
            let random_data = "f47e7324fb639d867a35eea3558a54224e7ca5e357c588c136d2d514facd5fc0d93a31a624a7c3d9ba02f8a73bd2e9dac7b2e3a0dcf1900b2c3b8e56c6efec7ef2aa654567e42988f6c1b71ae817db8f7dbf25c5e7f3ddc87f39b8fc9b3c44caacb6fe8f9df68e895f6ae603e1c4db3c6a0e1ba9d52ac34a63426f9be2e2ac16";
            hex_decode(random_data).expect("Invalid hex data")
        }
        64 => {
            // Fixed test vector for signing (64 bytes)
            let sign_data = "7b8681d6e06fa65ef3b77243e7670c10e7c983cbe07f09cb1ddd10e9c4bc8ae6409a756b5bc35a352ab7dcf08395ce6994f4aafa581a843db147db47cf2e6fbd";
            hex_decode(sign_data).expect("Invalid hex data")
        }
        _ => {
            // Fallback for other sizes
            let mut bytes = vec![0u8; size];
            rng().fill_bytes(&mut bytes);
            bytes
        }
    }
}

#[test]
fn test_public_key_serialization() {
    // Generate a keypair with deterministic data
    let random_data = get_random_bytes(128);
    let keypair =
        generate_keypair(Algorithm::ML_DSA_44, &random_data).expect("Failed to generate keypair");

    // Print public key prefix for informational purposes
    let pk_prefix = hex_encode(&keypair.public_key.bytes[0..16]);
    println!("ML-DSA-44 Public key prefix: {}", pk_prefix);

    // Check the public key has the expected length
    assert_eq!(
        keypair.public_key.bytes.len(),
        1312,
        "Public key should have the correct length"
    );

    // Check the public key has a non-empty prefix
    assert!(
        !pk_prefix.is_empty(),
        "Public key should have a non-empty prefix"
    );

    // Extract the public key bytes
    let pk_bytes = keypair.public_key.bytes.clone();

    // Create a new PublicKey from the bytes
    let reconstructed_pk = PublicKey {
        algorithm: Algorithm::ML_DSA_44,
        bytes: pk_bytes,
    };

    // Sign a message using the original key
    let message = b"Serialization test message";
    let signature = sign(&keypair.secret_key, message).expect("Failed to sign message");

    // Print signature for informational purposes
    println!(
        "ML-DSA-44 Signature prefix: {}",
        hex_encode(&signature.bytes[0..16])
    );

    // Verify the signature using the reconstructed public key
    let result = verify(&reconstructed_pk, message, &signature);
    assert!(
        result.is_ok(),
        "Verification with reconstructed public key failed"
    );
}

#[test]
fn test_secret_key_serialization() {
    // Generate a keypair with deterministic data
    let random_data = get_random_bytes(128);
    let keypair = generate_keypair(Algorithm::SLH_DSA_128S, &random_data)
        .expect("Failed to generate keypair");

    // Print key prefixes for diagnostic purposes
    let sk_prefix = hex_encode(&keypair.secret_key.bytes[0..16]);
    let pk_prefix = hex_encode(&keypair.public_key.bytes[0..16]);
    println!("SLH-DSA-128S Secret key prefix: {}", sk_prefix);
    println!("SLH-DSA-128S Public key prefix: {}", pk_prefix);

    // Extract the secret key bytes
    let sk_bytes = keypair.secret_key.bytes.clone();

    // Create a new SecretKey from the bytes
    let reconstructed_sk = SecretKey {
        algorithm: Algorithm::SLH_DSA_128S,
        bytes: sk_bytes,
    };

    // Sign a message using the reconstructed secret key
    let message = b"Secret key serialization test message";
    let signature =
        sign(&reconstructed_sk, message).expect("Failed to sign with reconstructed key");

    // Print signature for informational purposes
    println!(
        "SLH-DSA-128S Signature prefix: {}",
        hex_encode(&signature.bytes[0..16])
    );

    // Verify the signature using the original public key
    let result = verify(&keypair.public_key, message, &signature);
    assert!(
        result.is_ok(),
        "Verification of signature from reconstructed secret key failed"
    );
}

#[test]
fn test_signature_serialization() {
    // Generate a keypair with deterministic data
    let random_data = get_random_bytes(128);
    let keypair =
        generate_keypair(Algorithm::ML_DSA_44, &random_data).expect("Failed to generate keypair");

    // Sign a message
    let message = b"Signature serialization test";
    let signature = sign(&keypair.secret_key, message).expect("Failed to sign message");

    // Print signature for informational purposes
    println!(
        "ML-DSA-44 Signature prefix: {}",
        hex_encode(&signature.bytes[0..16])
    );

    // Create a new Signature from the bytes
    let reconstructed_sig = Signature {
        algorithm: Algorithm::ML_DSA_44,
        bytes: signature.bytes.clone(),
    };

    // Verify that the reconstructed signature bytes match
    assert_eq!(
        signature.bytes, reconstructed_sig.bytes,
        "Reconstructed signature bytes should match original"
    );

    // Verify the reconstructed signature
    let result = verify(&keypair.public_key, message, &reconstructed_sig);
    assert!(
        result.is_ok(),
        "Verification with reconstructed signature failed"
    );
}

#[test]
fn test_cross_algorithm_serialization_failure() {
    // Generate keypairs for different algorithms with deterministic data
    let random_data = get_random_bytes(128);
    let keypair_ml_dsa = generate_keypair(Algorithm::ML_DSA_44, &random_data)
        .expect("Failed to generate ML-DSA keypair");
    let keypair_slh_dsa = generate_keypair(Algorithm::SLH_DSA_128S, &random_data)
        .expect("Failed to generate SLH-DSA keypair");

    // Sign with ML-DSA
    let message = b"Cross algorithm test";
    let signature = sign(&keypair_ml_dsa.secret_key, message).expect("Failed to sign message");

    // Print signature for informational purposes
    println!(
        "ML-DSA signature prefix: {}",
        hex_encode(&signature.bytes[0..16])
    );

    // Attempt to verify ML-DSA signature with SLH-DSA public key
    // This should fail because the algorithms don't match
    let result = verify(&keypair_slh_dsa.public_key, message, &signature);
    assert!(
        result.is_err(),
        "Verification should fail when using public key from different algorithm"
    );

    // Create an invalid signature by changing the algorithm but keeping the bytes
    let invalid_sig = Signature {
        algorithm: Algorithm::SLH_DSA_128S, // Wrong algorithm
        bytes: signature.bytes.clone(),
    };

    // This should fail because the signature was generated with ML-DSA but claimed to be SLH-DSA
    let result = verify(&keypair_slh_dsa.public_key, message, &invalid_sig);
    assert!(
        result.is_err(),
        "Verification should fail with mismatched algorithm"
    );

    // Also verify that the library correctly checks algorithm consistency
    let result = verify(&keypair_ml_dsa.public_key, message, &invalid_sig);
    assert!(
        result.is_err(),
        "Verification should fail when signature algorithm doesn't match public key algorithm"
    );
}

// Add new test for serialization consistency
#[test]
fn test_serialization_consistency() {
    // Generate keypairs for each algorithm using deterministic data
    let random_data = get_random_bytes(128);

    // ML-DSA-44
    let ml_keypair = generate_keypair(Algorithm::ML_DSA_44, &random_data)
        .expect("Failed to generate ML-DSA keypair");

    // Expected ML-DSA key serialization (from test output)
    let expected_ml_pk_prefix = "b3f22d3e1f93e3122063898b98eb89e6";
    let expected_ml_sk_prefix = "b3f22d3e1f93e3122063898b98eb89e6";

    // Print and verify ML-DSA public key
    let actual_ml_pk_prefix = hex_encode(&ml_keypair.public_key.bytes[0..16]);
    println!("ML-DSA-44 public key prefix: {}", actual_ml_pk_prefix);

    assert_eq!(
        actual_ml_pk_prefix, expected_ml_pk_prefix,
        "ML-DSA-44 public key serialization should be deterministic"
    );

    // Print and verify ML-DSA secret key
    let actual_ml_sk_prefix = hex_encode(&ml_keypair.secret_key.bytes[0..16]);
    println!("ML-DSA-44 secret key prefix: {}", actual_ml_sk_prefix);

    assert_eq!(
        actual_ml_sk_prefix, expected_ml_sk_prefix,
        "ML-DSA-44 secret key serialization should be deterministic"
    );

    // SLH-DSA-128S - Just print for informational purposes
    let slh_keypair = generate_keypair(Algorithm::SLH_DSA_128S, &random_data)
        .expect("Failed to generate SLH-DSA keypair");

    println!(
        "SLH-DSA-128S public key prefix: {}",
        hex_encode(&slh_keypair.public_key.bytes[0..16])
    );
    println!(
        "SLH-DSA-128S secret key prefix: {}",
        hex_encode(&slh_keypair.secret_key.bytes[0..16])
    );

    // FN-DSA-512 - Just print for informational purposes
    let fn_keypair = generate_keypair(Algorithm::FN_DSA_512, &random_data)
        .expect("Failed to generate FN-DSA-512 keypair");

    println!(
        "FN-DSA-512 public key prefix: {}",
        hex_encode(&fn_keypair.public_key.bytes[0..16])
    );
    println!(
        "FN-DSA-512 secret key prefix: {}",
        hex_encode(&fn_keypair.secret_key.bytes[0..16])
    );

    // Test serialization/deserialization consistency
    let message = b"Serialization consistency test";

    // ML-DSA-44 signature consistency
    let ml_sig = sign(&ml_keypair.secret_key, message).expect("Failed to sign with ML-DSA-44");

    // Print ML-DSA signature for informational purposes
    println!(
        "ML-DSA-44 signature prefix: {}",
        hex_encode(&ml_sig.bytes[0..16])
    );

    // Verify keys generated with the same random data are consistent
    let new_ml_keypair = generate_keypair(Algorithm::ML_DSA_44, &random_data)
        .expect("Failed to generate second ML-DSA-44 keypair");

    assert_eq!(
        hex_encode(&ml_keypair.public_key.bytes),
        hex_encode(&new_ml_keypair.public_key.bytes),
        "ML-DSA-44 public key generation should be deterministic"
    );

    assert_eq!(
        hex_encode(&ml_keypair.secret_key.bytes),
        hex_encode(&new_ml_keypair.secret_key.bytes),
        "ML-DSA-44 secret key generation should be deterministic"
    );
}

// Add new test for serde roundtrip serialization/deserialization
#[cfg(feature = "serde")]
#[test]
fn test_serde_roundtrip() {
    // Use deterministic random data
    let random_data = get_random_bytes(128);
    let message = b"Serde roundtrip test message";

    // Test each algorithm
    for algorithm in [
        Algorithm::ML_DSA_44,
        Algorithm::SLH_DSA_128S,
        Algorithm::FN_DSA_512,
    ]
    .iter()
    {
        // Generate keypair
        let keypair = generate_keypair(*algorithm, &random_data)
            .unwrap_or_else(|_| panic!("Failed to generate keypair for {:?}", algorithm));

        // Sign message
        let signature = sign(&keypair.secret_key, message)
            .unwrap_or_else(|_| panic!("Failed to sign message for {:?}", algorithm));

        // --- PublicKey Test ---
        let pk_json = serde_json::to_string_pretty(&keypair.public_key)
            .expect("Failed to serialize PublicKey"); // Use pretty print for readability

        // Define the expected fixture (UPDATE THIS STRING)
        let expected_pk_json = match *algorithm {
            Algorithm::ML_DSA_44 => {
                r#"{
  "algorithm": "ML_DSA_44",
  "bytes": "b3f22d3e1f93e3122063898b98eb89e65278d56bd6e81478d0f45dbd94640febe7702b2b820ec522340d3f38f64ad8e1a6ae768997d6f7b745fed46e3d710a8c37860ba777ebe1edc627127a278dad32f1eb1052af757913b98bf34eb946dc3f9e2428c65b56ee5c0ad09c8d1dee477ee41437ac027eb9529f516a9fb47b283c3edac57527e679426f806d9142fb9d5f71f86fcb9291225af9d62da8cf73effe46a1c06b32924d27944563ce269147e9b5ad49170a1ffb8fbbb1c44674a297b34d6ed9334e796909f106339a7ac3da7525ece96a164763cf551f3ce34118ef47d2d85436e1711f048d4ea1f04275c470c6fabf6c87ac737189d542744570a67f3fb445bef6cd3cfaea4317aae6c87afde574f183e8ebc8e5841eb0567fe0251e8a5efd2b6e265943907870bd41aa4e418806ac1fcd75cb245fa7751d1c10d9c1df02a1e0a30b3d6126522abb8d342fdc7316e16f8922e95ed5953175e0b2edb71d4021090e36b83e44764cf30277dbb1c9873aad6b77103149aac69042881803a1c59218a14279fa1cd440bd75694182b3a984b10390f213c9d2ab469c44f7f3b9b0da798fa47551bec0188fe5620a91c2408814566c552a5cdd6fc81e52d4ac3f93eec51f7909de0ab74d184b1eaf9c678fba85086bced79eec203da63e0bacf9d4b35b4e2ee4624c061def8c4ca9ed1cda6cfc9f69a76705a31ce6c7707e3d47ced1df946cd7abd7919c69021fa08c932e9d1df4a03b6be6a978bcf9381ff0bc86272ec4ded5ad5080e84da579309e01f8645dc0de9ba390ce06aa227b087df6d81d8df8b52f8293152d3ca687608f21239aff589b1f0c664f09a7c6d26a26754d49e21c58f66da7bf648f322aa5073d6f9c57d81311c0fa13e2ffcd9b4a13d2428e8e11551348d88a31cf9de3448cdd155758ca796949ebce1d2cb296faa5050f5854e1b01c337b0f07bb35719e7d2d8e8938591dd31f0344d84f30b50c287d72e47c1c15dff3237a12c7c5de86fdbb4a04254c2c1517df9681c97bee3d5ac6e53956d68780ab66dd4f617dd402d6c027e27e051de28aa9ad8b0db71ca0195f96e0d6fbf83f1cc6a3bc7409423e032861f57b040738472792ab558756a39381045697d8773d62b84c7555b3dd075146bb6ff6bb673094fa7ab978f8ae5e7dc160f584e0c3c7ca1a2f58147247a99aef07761424cdc20d893f6c0db80d8c01f53fda5f1fd4fab6eb4bd65abb3500705f289b871bb3890212ba11e4bdc8e9300f2b48bb0a53ee08df6474625d5c8adca4451c4b28f879b79de51ffbae224e0798f67303e4e41c7b332985ae738258a6a1bc87411f44bf248efec9e78c1961d06736b23eee2cd7d2126253caccd0196d0f6206187286b1c2990a639cdbba805c58716f859fa8f65837ae726dc7f7b84aaa299dcd3fed7a959a7ca0ce55de1bcebe7790162284687eaf5f22ed61642c07df42c37fc6e4feef35fa69b841f50d91b408383c01eca59dea1a59ae8eaf68b67f02a2b65ea63934616caf9af554374d2abbeba2b44c0a96218332817e71067f03b4716e294e46bd2cf8cd7e551e7f6807ad3127c2625f2feb18ce84750b430d0498d04cfa5300a82aaf61a704acc3cb006ef90837786b0c8e3d8bd1727489fe0021599a40fb93ece169dcbb4deea2755bbd14345580b7cf2009cebba635a27267da02e9da098ec84e3c75d224270d76cb3850529096e03653b718f6b0e0ea0b918146f1a5d259c60331cd8a64d703d6a16eb11d6a3483c236c02b2de002b1e83bc4a13cee8898c38f9574132c207086cfcd3405b840fcdaf7e4f2215ef6b5941811294e32619c55736e9d7b06e9581e"
}"#
            }
            Algorithm::SLH_DSA_128S => {
                r#"{
  "algorithm": "SLH_DSA_128S",
  "bytes": "d93a31a624a7c3d9ba02f8a73bd2e9dad0261c237a3fa1df610b30f2a06bc750"
}"#
            }
            Algorithm::FN_DSA_512 => {
                r#"{
  "algorithm": "FN_DSA_512",
  "bytes": "094048b817ccc551458200973105f10a0e5d8954851c1092bf7871dd3e865cf5b4fcee405a18e312bc8aa823aa6cb0cd5cd49f79bfa17bd34692798d48a99a7e9ef5589528e2455111a5402e85f45d7443f3cee4df2d468f31124c204e365b07fea9e1100486a6c9c833152d3ee26ac91a7151d6a2929024a9edbfe5f789f2b30dc8c12961b69bbafba9f7d7181cd1d0f1220e067a187a8a254da339a53a00852ff529c06e49221b0d159d25e014c2c36ed8722a65c6f4330d7b117d1cd48328faa41e5d1b7e859265718dbc92a85d9696080a73ba7161e3552c6694def708886521b9d7541d1e856fcc134083556c17d2fc004897468bfdc9f96f4f7a0f25a3306baaf962123e994014c011b45fb7f201f50ea803029b59b1a68d9031749daba3090ed54b029e8e52f0cab8d50bb599ab07d91a6f53ca43a250e1bea9252135f282654c41382b94537269463288d3c52a2222ace23d9befb496867821651ea84ada4b465dd31b6abd358407c39a0a42d15ad0edbe89515a4bce12804846a376ac6c222e440346c00da4107f449142931a842e3868cba56415df4a65197760b51503c4c220a7d96dbaeb493267c810d3b6640f0f96b9f2178009b441b5509489efbcec97282307f69eb26f78bc55c941c15316c2acda29593613d22372020261f534e4aa5b6d5bd4f44e0765f65a818742a26b7d95d2648e429c455d64c8688abadd2adbfc1f7a39fee167e35eef4d28c85304843283b0ec36b70d8c96817648cf1d4f3e91d1140a1756189cabd03bda631fd9d295beea6e56411530ce5a085466c7f5f6218711f5dc456fa41b2ffc5387b7a3043fa104339f2a3e32c13730b748364d4d5a1addd8852c05b7e7cf88e6aea94c1230a5968aca6b21b9940c098527e432cd0b8e693ed0121b270599d2f32f5cd382a47ce7315da79676d960a5cfb795983d998c10616980d554f767375fdc19312862e1515c3fd032a4c73ee49174185fd70d0652194805333ff67791a2844f58553a72a720a68142ef8a019814ac0a8943de20ab18020693578d880f62c9b328c15a09bd89c0e3ebacb5aaabd8d626dc5026d2f734006a24e60f070d6f9625080fd3c3199040b5b5972aa4ec23193aca8c64d20d744853f5dddabd5527418454cd093caf65265070ac0815c5a8121733ddd69b188e2b7b6491066365123b4aeb8969c2e7799c77a0e1a12a7d3de20471c8558628b164982564055cef78630dfe738ace60ff01ac78fdc16b0ad036"
}"#
            }
            _ => panic!("Fixture missing for algorithm {:?}", algorithm),
        };

        println!(
            "Algorithm: {:?}, Generated PublicKey JSON:\n{}",
            algorithm, pk_json
        ); // Print generated JSON to help update fixtures
        assert_eq!(
            pk_json,
            serde_json::to_string_pretty(
                &serde_json::from_str::<PublicKey>(expected_pk_json).unwrap()
            )
            .unwrap(), // Compare pretty formats
            "PublicKey JSON does not match fixture for {:?}",
            algorithm
        );

        // Roundtrip check (still useful)
        let reconstructed_pk: PublicKey =
            serde_json::from_str(&pk_json).expect("Failed to deserialize PublicKey");
        assert_eq!(
            keypair.public_key, reconstructed_pk,
            "PublicKey roundtrip failed for {:?}",
            algorithm
        );

        // --- SecretKey Test ---
        let sk_json = serde_json::to_string_pretty(&keypair.secret_key)
            .expect("Failed to serialize SecretKey");

        // Define the expected fixture (UPDATE THIS STRING)
        let expected_sk_json = match *algorithm {
            Algorithm::ML_DSA_44 => {
                r#"{
  "algorithm": "ML_DSA_44",
  "bytes": "b3f22d3e1f93e3122063898b98eb89e65278d56bd6e81478d0f45dbd94640febdec294921bd45b3bea23bc1d0158e1e34daf4c82e734524d505d10fa6113285e726ac719246cc34d032fd1e16c85821597acd5452af5a87e5fc84d8c5f332c839c0cd9d48b1dfa47352976ad7835e36577fdb30126c28ce2d214584ee2dbc2ca8a40499c02442015268800312090890b331250b40ccc8869031210910411d1c4501b24121b060a8b126cc80265e0364294184d99c464cc2866d2326998486601894880b06d984891a0142119491104106c5384450a05625c100a2421508c021049944192b22da422681aa2049c002202478810134618113224983081c20c1a1500212191db984d0b488164868d61308804298421a630d4340a984449c0426002a690c04249031721821802901091843820d2b41010c529e02405e3342823164111099192800123161220c925029785181728e1c6891b883181c6655c488249b64009a07082802dc042692422310b804411142264203111456c1c308104220a4b16801b432401a169032832d98209531489e4123198c001449631a2486119924c1c258444008d4232860316642147060c272821b70021266ae3c67122b760102170109808a444294b900823b1704a8040d4188611b0091c24001218669a82419b0060d3c04cd9400dca4471221724003846981461c9962dd038401022851345729b304622b8044a0461d186651895805936698aa27091802c928000cc8811c94885003389098021994680a3a251942652c9426c9ac669d38890910661cb9270211300c41884e190400a1062e11841d2245160308e59064a94908899b83123956454c28801c060c4868d5a948850806004463199880852960c60208021b94519366d0189051b086624328d89c26da11865203428d8a45041b8896498711c450e621468024290c194301a990c5916711a05304112280027210b2741c4c289d39465c3365240c850e0c04114444a64203109884114a13154902844c88001c26493807193a49101c6082003266146529c28110c12024c4088c9b00d1ac08153464013a88010426c08890823271290b62091228a6418458ba0641c272acc8630e0486d0ca371d3868da0168e48a23062800580142189b268a2884d0c373214038090c4711b477258002e64026a1aa12d00c8245b98684844019a004149026d10a08d82840012b45102435221a32d5b908c648290939250023986081711212905dcc2619d5be95a339c1bc29c0538fe02924c096b7c7063deb34148fc2ac4297d5f2e85aea1ef57e1236204f75c6264559eb6f933df5b55302d09d6c6cb889fd44508a2122accc2b3cc2a0699147ec848a846c37c33f55dad55aff5de196966d3d01f71aca8fbb72c9d9018e0830a5eb3424bccae6288c13558faf85f1b8f095365a6c7d3b699f9a6332a377b12498df39a595fe1265eb04f10c81b826aed2a266bab5d2ce07020395961fd6358cbabde2264c6083cda237f13db7481d6100b46480bef4652c786871196fec4564a96ab056f8c15586b351391a6d808c9e7f4359a1499f8f07d99aad4e589a25be4e617ab70b39ba9eed53aaec3a4bc400e294d7eed7583489cd5cf6ae450fafe2db09098fd0a8ccc68e4d2b77064874501daf62757daf653365acfaca2df2280520f8374ac8d5e84b6a43f98f4afae4f84413c030ec7f21cf0e8a7d23b5d12654f7364460c5d8b4c75f790e3ba538c2e3f776b2769b794f45d1e1aac14febcb24eb335afac4154a73dd4435ebb9d5326d74dfaf349e44d88703c08748d6c850d4107990f0a18fecf2beebb88123894d489cbfe0c26fb88ca76a89ab233fec7a5cbb8566145c0a4a3a0d86f9e9689e5450f90d3a099870cea373243793ca3e5a92ff916f935fabacda0bf6bd8977b1bcf36f52f7812645e615f26e7df37c7278da16e8024d9027673f942fd7b8d738b525a629f1ba6ac66779db0bd8c90ab3903f7e9047f66b21dac94a9c335fe6aa78c6927663c0a74c89550bdc9d8201127984aa89ee2b80728be9b3f0d54a73172ba2ea4d1f7c4804af6998f8cd081d2e04b5448d2952749e09dae4354b893f26d355635d20764055e30459c613bb32fdb4ae074f545deafb3c532aac9559c8d3674cd132e4f854f1d9aab8c23bc94a0269a61b0f3d0b5ac3afb1ea35a45aca151ec63ec5bcc02ca647f2982c205549a2c8a5382ddd0c9e06ce545a18718a1bcea27623814bd3a8ce3b8ff8494f89cc32e05bd5749daa63b894685ce6906dfbfc411c2917d4b35fed903d8dc22a3056c28438c772c592d850a4d58becf2a286ed2e72f4ec13835236b3734367ea0b0f2eb38eff07c87d69fc4c7e86dd135459da3c96aa34400ca2db9eac2018a6a9c8d1339b6752023df35e1bb97b44555d194bae18232f68d2206fc35ba3754a33c91e82819c62ef864166910c7e40ed375647069d98fe7805e75e285a160a7950348304791208d4d82c5410ea019c39076ec36e8ed9a4d3eb87dac7eb3067b5776535301d2c622e7fa67a13d70cc4450c3093c5a47689e90a1b4178ccde8719baed1d3a2630078740a502977474b7025abdcb7998ec442d5aea31d6a8533aacff0111f935de36dfc6e266701d7c3778e7f4ebfa6f7ff9e6b1fab8962f30e5276b2a76f20acbf7087bd2d092dbf642843fa980f8a4b80ce730902c0e637f6c480f1f441ee731c9fa4d33258d00ff47be9b413eb176ac1cbc0c06edf67a59f9a996f9175327de3b829d1d830a638bf6056a87ec4150b440440a2ef9e5bafcdcedf4753ff11b1f2b00e52070f4984af34cefd224f36e6d04358418b05e52ed089dac28aac67c0e4d0ab79e4ee82377c9c4ceda877dcdc2fad48a88ae1fe4cc2582f1e41b5d557897902435a27a9bffc63357135c7e6e60516f56dccbd412afb250f117cbfa234619d75f199e397c587c523e4942728cd7d4d59aca9b52fa9364a7b81d9fd7c23e688b04bdaa986e21d7dbfcbfa634b8fcdfa2619d9b6904e3d8e3205bbf5a3d526c4bf9017723fa8944a0b08595e5252e361c5a353ae737177f043e9c2460f48a8aadbd342d773ad6e034191763d87e8c33a3a443cba0174f0bc49385b5a6ca75bb7c000888dcef43bc22252eac9710afb4a6c7a63b363d08e083e691aa848cad7bec731067a1a90a7803328aed4c987eb586461a523ab8fbda4829511f7a427940b94351966c8cb37dc22dd34a81c0542adeb97fff1f1460e72c575c9d18c571ae7175a9ce269fc570c0945484e6e5fca628b5bf0904bad7027e691f1fc8d740ed172fe8816b06b7a672d67faffa91affad41828204d5dbc10c68edbe911131c6f8993c054a2165675794bf6dd1b617a9e5fca0a1a884b21d236163c559be4daf02d5ed54034f735fb031bc17e95066ab3ac9120fd24e238e6255f5ae72fe81c0f9fb69979c746b893421842aa7641d50ff2b2506d078b0aeee703f08223be66255e62fa568a244ef8642eda22ca33472c07e3d8398fe12dae1dcb37dab68aca08a8aa439c4f2257910a0f46af5bcbdad3f987c17ac6c52703a04705ed920c69526fc748f366974706d19143cef2c3441ffa01e06"
}"#
            }
            Algorithm::SLH_DSA_128S => {
                r#"{
  "algorithm": "SLH_DSA_128S",
  "bytes": "f47e7324fb639d867a35eea3558a54224e7ca5e357c588c136d2d514facd5fc0d93a31a624a7c3d9ba02f8a73bd2e9dad0261c237a3fa1df610b30f2a06bc750"
}"#
            }
            Algorithm::FN_DSA_512 => {
                r#"{
  "algorithm": "FN_DSA_512",
  "bytes": "59dc5e3d0c6f81fbae80dc4fc6f81ff8efbe82041041f46044fbcec6079ec70fff7803ff82ffbe82ec103de82044ffe080e41140f01000fff0be100f7e10207d08307e146ffe03ffc4103f092b717df82085ec30f9f8003e0c1f82201ec6007f81003f3f07f1c7f7ff831040c1e83fc02fdec307e085f7dd470be07c1010810c4f42ec0002083e3ffc1fb7fc1101dc103a03c0bdf81f40201f08000f410440bc0431040b90000bb03c105f3d0410840c10010fe03eefd0fcf02243f7f082f82104000181e830ff0fd00017e0bfeba082fba03ceff041043e010440bdfbc1421bf1c1f42fca0c2fc0f82ffaf03e7e102f8407e0fff00f061bef45fb9002f46147fb6f84f41ec4000fbef41202f42fbffc2e7e17ff49efffc003ed80104e0403c0c11fc0440ffe7e181081142043142f7f04023f0c3040fc613c001efe13d181f0503c2ba27bebd17b28217e13cfc00400bde40fbff3afc2005fc31010bf1be17b0bd10004103dff7fc3ffe0c2e03046002e80fbf0bef79f8113afc1fbc0bffc3083fc40c2fbaf820c00bdf8113ff0003f03ff3e08203eff4f8200307a0c2efdf7e180000f40203f40000f3f0f8042f8020207dff7ffbdc00c1f7f083fbe239ec0efeebef7d03e0bdf3ff02f81ebcf400bdecbe04f40045e0403e243d00041006184ec1084fbcf000bdf44f830860c2f7f07dffd03c03ddc9fbd0c1140040fb713de470c02021fd03df40f44d810bfeff0be044f80ffffc5ec81fdebdf7bec4f83ec6f80003fc2082f830c207d1ff0ff03ef7e0f804608400403bfbc105f7ffc2f3e13ce81f8a03ce40fbc0c3102efbffe045fff0fcfb8f7f18007ffc108508803e0bcf3afb9e42ffdeba0002bc083fba045048ffb0c2080280ec4045f3df81e3d0071bce7efb9dc8ec0083f00084081f4113dfbdf4304107f07bfc207b08314307f204043ebffc4ec10772bdd7f003fc4fc204504d03cfbaf84ec60bcf43f05ffff41ec2f86fc6ffe07f183e40ffe18bec50fb03c00017e17a0be07d0820c5ec2e860cafbb104141181f80002f06f4113fffe0c518327b0c607fe3af80041000f3f0efadbe70d201e22f30bee0c2109f50aee0cebef36efebd1ec1ff3fd0af4f0f2f510e3ee041205f9fbfe1004dee019c8d01a12e8e0ef1003dc1a1bcff5fbfdec20eee816e5ff010406fc140028ead40c0010ffe605e8fc13f9e3d741ffc70701f01ecd0cf8fc1d0fe0100a11eb0e2a03e31ccb0701fd16ffea1ed905e101e121fcf8f817e1fa16ff05f4e92005e911f7cc072706f305ffc711f3cb050bf3d1df3a08130bf20df31ce50d21161eeedd0102fdfafe24011300ea0616b02ae4fc021ada25d6cecf10f327ffedf9f5fce7e502f4fd0a0108dd2337e72704f72008e60fdff6fadc100cd30dee02f11910f1f3f6fd1bfc0ce110faddf22225e922f2efee23f907fef10fff25ef09de000c1322ee072eed0bf1d907ebf31bb21613e81ee014070d49e605e607fde419daf10639f2dd1124f0ee1307d0e4221339e8d5fa07cd020607fde10e0dcc23f50505cc0a010efc2e080be503f318e9e7e1df070cf10cf5eeffdf0408fa08fefbccfd020af116d01100f30a3b061501fff425f4130b1d06e9fc0b1b0ef6e8d5f5322df71916f9c90f270be9effd36ee1c12f1e705e308cbe90e0d07f2ed0123eef7160efb10fe06efe0f61b00341b06e108f5fac01019f0fa04080102efe3f813faf613dcf9f715fdf1ee21f80df215fcf0ed3cfff217090d0dd2190bfbf510cdf5fa05d7ffd71f08f935efe80ef41118eeebff1f"
}"#
            }
            _ => panic!("Fixture missing for algorithm {:?}", algorithm),
        };

        println!(
            "Algorithm: {:?}, Generated SecretKey JSON:\n{}",
            algorithm, sk_json
        );
        assert_eq!(
            sk_json,
            serde_json::to_string_pretty(
                &serde_json::from_str::<SecretKey>(expected_sk_json).unwrap()
            )
            .unwrap(),
            "SecretKey JSON does not match fixture for {:?}",
            algorithm
        );

        // Roundtrip check
        let reconstructed_sk: SecretKey =
            serde_json::from_str(&sk_json).expect("Failed to deserialize SecretKey");
        assert_eq!(
            keypair.secret_key, reconstructed_sk,
            "SecretKey roundtrip failed for {:?}",
            algorithm
        );

        // --- Signature Test ---
        let sig_json =
            serde_json::to_string_pretty(&signature).expect("Failed to serialize Signature");

        // Only check fixture for deterministic algorithms
        if *algorithm != Algorithm::SLH_DSA_128S {
            // Define the expected fixture (UPDATE THIS STRING)
            let expected_sig_json = match *algorithm {
                Algorithm::ML_DSA_44 => {
                    r#"{
      "algorithm": "ML_DSA_44",
      "bytes": "d44770409f4dacafbc779f68ef129f8f15138a5befa38a9ced36031ebae7bdcbb09e900350de29cf4b9c2ce04e41bfb40739dd9bd985ed1bbed4c9c7bc96cca6f4d0c921b43b8e4067789b6e7744e7a055a5edc5b4bf0d8fc5ec404c980b5b298e5d930df3375b7ab686177c99ec4be848ce7cc162adb578896d11d4fcc5f0cf1af5f9ad070ea6f3460c06627f937782aaa185304c068748ee86c91fec03853a7ce81a304fcc2afcbb66c2e308af5269cd1c9b45a2ab73d04474d96b1c5890947485dd6c3d6e7bdc7b8e445fb27fb525677b2a3b95954dfd3bb163985d4640a4c1c1102452341e4ad5cbf5b8eb4d30c3323a6572502670e748cddca9d18f12d3a3fffcfec7099f16f6542eb39d3032094023649de67af9ee8e06c9a53cc926388345d6a9412d2de82a4e59c6c11b6f3b259243e45ee57ccd2e4f3a68a8e53b808911b4afe9d72891ca40739e1ab7142ca935e161a19dedf234ed27a7c18ba722780dd53aefc40e921ff0de9ca3ed37ebbe02237f802ea073f11c1b2ef2b703d65739b1d8c060d62a834138d7a2e663854ac794999c95360d849f57b00c37f1cf90a13e0b831df1ada26742097b6465bd2755794e20271077b80ac4d2aa6b5c8e3c77c34ee574dace472eee5eb88b0c59209bb6081a63e3cd9280b4d766e00da79af6d496c90b3ae5800397ecabcaa94d80e765b016a250dddc227d2fd1f6342290cc4ed53d1416fca988cb3d4577e27d76bbd1adcc6b22e80bf9d5901ab5797081012e4fddd320238f5ebf4c4dc5cb17ca57cc76089c8fe54ac7b3bd909ffd37ab4440c4716bb1ea42582c12b195ec38f5654146476bb72bead204fc250671567098ef2fc7c63c111a8cd3abdc5ab6aa4ff47ba5e2998e2aa4950f0725c4c770f974e7e16975068ece9b81e76fe65c84134f31855d910bb2f8ce6de08b59c6020b9292913a6322757176bdb70d2a01428161cc4f858b777d0af656366aaab65bd54cf2ed7820c26f93152cc7e827e403b71a10863409e75dbfb450618c718c3d0ac6b6686f3efc41c07a226547fa21721aeacf09b9707cedca25624f17b52a9fbb80045b62099d31f71dffa551af1d7a7276aed9036939f6c04884d13db33783adfbdd9de05824f6fe2cfbadeecf0e318f1e34bfc03d5a70c4dc8c9cebe1c1b9b605d421144a3d66b7d86710a2b87171680569222480db421b1bd678999d22aa561c55942fd7c2a7900759ee095ed2213d6ed0b5354846a010328f81600b42949be02f48fce7caf64a03dcc97edadc42ef4971f5371ff3e520d2c1de923c0dac6439c3a7e9dd4e55090584f9e2eeea96f29b69417673a8e150efe779166ba498f4ec58b9ecd00aac8b01dff155f29750852fe2e30cb0d6378b1a17ce9d90b93a5c838bbea80cedeb609c600f3bb44314a8c36713c849ec47a3794f3b828b7a8f169f33f3a1eb6867ba5d1fb71e658e1709dd08ac7e874ef3b2077edf570eb3d3989874d729aea331e03caa07ba672bc6b512a7902557bea55ee5466205064193de95ff92d2f5fac41d914e6c7e6fc62cbfe5b9ada3383a502c391782374a1b1241c7368598492f48085aea05f065213f13d9463c4b144e80a426fa5c415e593bef0b541068a8ffa1464e9b8f4ded4da5caad827142778a17d119c3e7121020ff452aefaf816c7ebf190b684d43e2c5547cece9eb7fa4f5312b19fae7f2645ff38c6c9a2514fdfdb74d3ec40e93402027f5af826aaa6c076dc1815b0b7425d5c9f7880f0e82258ff88cc3090e561524bab84bd167840463802df66a18340d7d0ef438a5c99c788ab7f07aaa2ee6e37ae0488967600421e6ddcde2a44dd3ceec3e8914f7fb5a1a42c38e20c1666ccfad1a1ae0364cc85a5612f35e087c77c0c212099c4a60138cb9486a571a59a9993ee00abd77902b684163b50fb02373baa75834ac3638a6c8e6a6038ce2a907c6ba2647cbd3437fb4920b1a5d46fb04b2c36a8aee0f3fcae7709e4508d2c7cfdfb724483dc71881a385eecd8b4dc32f793037be625a8427690ddbd6e0e8d80a15516cbadba4034d6700cb6ec807815f6dd5e8619a336bab503cfe6473cc913a80f9e5897ea68f2866ef145a3f1ef371ebe1151a4a93eceb3059a27fa93a309363b8b23cbf401dff0134a6080805837ae9fcff26a58e86ce37ded0d08f7022a979f0f788e99e7cdf32f16e09282b61d4528c5b79a38feeedf210722a20a428ae5b404c7923d1fa10e790b166b98ab1e44ae6fa3612a723045d7c4b77570345f7e7204227433611644a2c75715184da36f0688fd406c878773c58646bb130146f7ec75f8b03c97eb4329c942d9d6006bd1fcbb4e9f56031191d00334ca77cf71bb895521ea7ba6f9c4d9b67f7c4fd38f4e914cbb9717dac45c802234505de0951f8d897365002feac6dcc8616bab1ec0583de1c3cbbbaab3cbd5db94ff2721c9a22541e6796fca0a217f4eee5e1441398a1286b4638533d4a455f3c83c85d886911072eb45c808306514ef4ad1c31e3e5f7151dab4d2d18ec8ac812e0c03c86d879865281cfa517b955c1842c7e093e35b107eda832356e2992adaa697565e2c4a8e9994767a9a61d717dd2a860695c83ea2c5b5f692493e79f2c184df7db7973dfd79abf00f042ba10ad9ade75ea1b01b62efcebc6a2c7b59a2af01b8691855919b1826799f0bba13509f5db2cb55e3f7c7f72eec95df0da8021ebbbb60d2f063c4129fcd9ed825d8671bb913b4b9cf91e148d941590536a44511b62296be5222a253a19c9293126b5e8b1aebb7a58c4353fced6f23c35f7414730e78024b7ba2f8bfead124bed379d4098a3be2abd3cc10a47fd0fdb40b35ec517fbc66bf2c06e1f6960f8595452705339cdda9a9b5102b8a1a5c1f1f872d0fc564555cc431f95b7ac24fb679188f4d49a94a20f6734c20acc0c7a2463e4eb23350d386198c086818f6ddf32d5842f41d7ef3f1644f76dc401f41e87027aa77671132e3d6faa099f1e28b10d4642fe3364cd82b4950211d741392454d5b395dbf89745cdcf43910add671639829495ceca0b0d6fb2c85a9a3369cc6228ab65d88198167de7519a4857d9f2a5b37b88f4258f9d01780f23174eb9c0b3cbc888e59144c3ccfcef165f6ebe1be85a73976bcb54ba95966299e6eeeeb8fbfc51ce86075a672107e84a56c61a00ebb08e579407da3651fcec5c515ca4a5e49a51fbb07915356b0fc1654a86be032fe6ca14a0ae2526b5c78c04c842ce586a85aa1dd7a80cf355af293be254236c9952f8b1a2f2663613154a74754d0913181d2324272f3d4b577285868999abb5b9bcc5d3dde9f5fbfc050e51595eadf0f1f3273d415e6069799da1b7babfc8c9cdd1d6e7f90a16313345465d7677aeafb5c8ced4ecfb00000000000000001b243748"
    }"#
                }
                Algorithm::FN_DSA_512 => {
                    r#"{
      "algorithm": "FN_DSA_512",
      "bytes": "39eefb6b924b3aee2a433639048859593790fc1d96736dbaba41236bf1d8a13cba44ba25b360f89a3c67fa4b34cc8a40d9c0f695b203a521d45d27e3a55ff3e2f448b4d99e647b792e8cc914316ff7c6fb9262778d5d1ed477e3ee94e60c795ac47a308df6a64c187be9a105c74e9fdbcacd166b8b3579e8751a046a9bb0903ff1536dd5fd574a754ce3af884662385388b281107221ee52192fb4dc8cac2e448eebd8fcca231d3668fd3d8c2e93eef57bd53f8d279115ee44fbf037ca65be3514af543e19243f3eed60d8db9097adb6fc34a18a5923537932d3839f69d7865f29fe61e4f2ed540a87b2e7ad6cba5a955e50998af9136a0c576f1f8443517c1060a9b64fded1824e929914d3793046e132de08ac69faef8433056763a1cafbdac6c1e5082a73f7ed78b6103d0f43096b86441157972d4a8c4d3422066b70d0bc8e10c0f3f00b62ef64b6279a65074f5a9392dd011fc2acf84269faf0ea54662916db217f192b8d744656f83b86541f32312281a1fd4c6224c0c04e0e798c54eb09ebdae4d8e372c59a494a4b8eb619cf4ffc303c830d5479a1f8f1ad65bd3b581cdd0e6a90e15031a5fe79f1288df57b006e9897421a45b3641910b54e5b3cd23a50ce32015ef67c13c83356deabddc59a0ec0a1c43accd867120527222fa5a3049938ac11afdea45a9b073ad9064fd86cf688e74ddbcdee8281961c1cdc664b1182d451aa3392e1a358fe1204c7ac0e23f158294c8117ebfc69741f0a84caa064eb46411e6c535251c4d47e0809b4c716bb54f3fee474677064291135b91eeb25fe8cc436125620b1934eafea6c84b37edf97f7976ec24299aa992610c7a20efa187f85d3792a84235ead926fe951b3d90b76728fea6dd938a6212fc85ff20bff87e33f80b56611fdd16f585663d5"
    }"#
                }
                // Add cases for other deterministic algorithms like SECP256K1_SCHNORR if needed
                _ => panic!("Fixture check not applicable for algorithm {:?}", algorithm),
            };

            println!(
                "Algorithm: {:?}, Generated Signature JSON:\n{}",
                algorithm, sig_json
            );
            // Compare generated JSON with the pretty-printed version of the parsed fixture
            assert_eq!(
                sig_json,
                serde_json::to_string_pretty(
                    &serde_json::from_str::<Signature>(expected_sig_json).unwrap()
                )
                .unwrap(),
                "Signature JSON does not match fixture for {:?}",
                algorithm
            );
        } else {
            println!("Skipping fixture check for non-deterministic SLH_DSA_128S signature.");
        }

        // Roundtrip check (always perform this)
        let reconstructed_sig: Signature =
            serde_json::from_str(&sig_json).expect("Failed to deserialize Signature");
        assert_eq!(
            signature, reconstructed_sig,
            "Signature roundtrip failed for {:?}",
            algorithm
        );

        // --- Verification Tests ---
        // Verify reconstructed signature with reconstructed public key
        let result1 = verify(&reconstructed_pk, message, &reconstructed_sig);
        assert!(
            result1.is_ok(),
            "Verification failed: reconstructed_pk with reconstructed_sig for {:?}",
            algorithm
        );

        // Verify original signature with reconstructed public key
        let result2 = verify(&reconstructed_pk, message, &signature);
        assert!(
            result2.is_ok(),
            "Verification failed: reconstructed_pk with original signature for {:?}",
            algorithm
        );

        // Verify reconstructed signature with original public key
        let result3 = verify(&keypair.public_key, message, &reconstructed_sig);
        assert!(
            result3.is_ok(),
            "Verification failed: original public_key with reconstructed_sig for {:?}",
            algorithm
        );

        println!("Serde roundtrip test passed for {:?}", algorithm);
    }
}
