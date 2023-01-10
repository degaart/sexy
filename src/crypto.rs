use anyhow::Result;

pub fn crypt_password(password: impl AsRef<str>, key: &[u8; 32]) -> String {
    use aes_gcm::{Aes256Gcm, Nonce, KeyInit};
    use aes_gcm::aead::Aead;
    use rand::Rng;

    let cipher = Aes256Gcm::new_from_slice(key)
        .expect("Invalid key size");

    let mut rng = rand::thread_rng();
    let mut nonce_bytes = [0u8; 12];
    for i in 0..nonce_bytes.len() {
        nonce_bytes[i] = rng.gen();
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, password.as_ref().as_bytes())
        .expect("encryption failure!");
    let mut salt_ciphertext = Vec::new();
    salt_ciphertext.extend_from_slice(&nonce_bytes);
    salt_ciphertext.extend_from_slice(&ciphertext);

    let encoded_salt_ciphertext = base64::encode(&salt_ciphertext);
    encoded_salt_ciphertext
}

pub fn decrypt_password(encoded_password: impl AsRef<str>, key: &[u8; 32]) -> Result<String> {
    use aes_gcm::{Aes256Gcm, Nonce, KeyInit};
    use aes_gcm::aead::generic_array::{GenericArray, typenum::U12};
    use aes_gcm::aead::Aead;

    let salt_ciphertext = base64::decode(encoded_password.as_ref())?;
    let salt = salt_ciphertext[0..12].to_vec();
    let ciphertext = salt_ciphertext[12..].to_vec();

    let nonce: GenericArray<_, U12> = Nonce::clone_from_slice(&salt);
    assert_eq!(nonce.len(), 12);

    let cipher = Aes256Gcm::new_from_slice(key)
        .expect("Invalid key length");
    let result = cipher.decrypt(&nonce, ciphertext.as_ref());
    match result {
        Ok(plaintext) => {
            Ok(String::from_utf8(plaintext)?)
        },
        Err(e) => {
            Err(anyhow::anyhow!(e))
        }
    }
}

