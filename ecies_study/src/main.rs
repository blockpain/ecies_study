use elliptic_curve::ecdh::{diffie_hellman, SharedSecret};
use elliptic_curve::{SecretKey, PublicKey};

use k256::Secp256k1;
use k256::ecdsa::{Signature, VerifyingKey, SigningKey, signature::{Signer, Verifier}};

use rand_core::OsRng;

use aes_gcm::{KeyInit,Aes256Gcm, Nonce, Error};
use aes_gcm::aead::{Aead, AeadCore, generic_array::{GenericArray, typenum::U12}};

use hkdf::Hkdf;
use sha2::Sha256;



fn main() {
    // Generate 2 sets of keys for testing purposes
    let (pubkey_a, secret_key_a) = generate_keypair();
    let (pubkey_b, secret_key_b) = generate_keypair();

    // Compute shared ECDH secret between parties a and b
    let shared_a = compute_shared_secret(pubkey_b, secret_key_a);
    let shared_b = compute_shared_secret(pubkey_a, secret_key_b);

    // Make sure the shared secret is equivalent from both perspectives
    assert!(shared_a.raw_secret_bytes() == shared_b.raw_secret_bytes());

    println!("raw_shared_bytes_a: {:?}\n\n raw_shared_bytes_b:{:?}", shared_a.raw_secret_bytes(), shared_b.raw_secret_bytes());

    // Generate HKDF/SHA256 cipher + nonce
    // In production, nonce should be based on an incremental message counter 
    // Probablility of repeating nonce is still incredibly low though
    let (cipher, nonce) = generate_cipher(shared_a);


    // milady 
    let message = "milady";

    println!("message: {:?}\nmessage as bytes:{:?}", message, message.as_bytes());

    // encrypt message using cipher and nonce computed above
    // cipher would be able to be recomputed for decryption on receiver side using 
    // senders ephemeral pubkey, their own secretkey, and the nonce used to encrypt
    // the message on the sender side (passed on with ciphertext along wit ephemeral pubkey by sender)
    let encrypted_message = encrypt_message_with_cipher(&message, &cipher, &nonce);

    println!("\nencrypted message:\n{:?}", encrypted_message);

    // decrypt message using same nonce and cipher
    let decrypted_message = decrypt_message(&nonce, &cipher, &encrypted_message);

    println!("decrypted message as bytes: {:?}", decrypted_message);

    // Make sure the decrypted bytes are the same as the original message bytes
    assert_eq!(message.as_bytes(), decrypted_message);
    
}

// Generate keypair helper function 
fn generate_keypair() -> (PublicKey<Secp256k1>, SecretKey<Secp256k1>) {

    let secret = SecretKey::<Secp256k1>::random(&mut OsRng);

    let public = secret.public_key();

    (public, secret)

}

// Compute ECDH shared secret between a receivers pubkey and the senders secretkey
fn compute_shared_secret(pubkey: PublicKey<Secp256k1>, secret: SecretKey<Secp256k1>) -> SharedSecret<Secp256k1> {
    let shared_secret = diffie_hellman(secret.to_nonzero_scalar(), pubkey.as_affine());
    shared_secret
}

// Compute AES-GCM cipher and nonce using the shared secret obtained from ECDH 
// ECDH shared secret should not be used directly for encryption
fn generate_cipher(diffie_secret: SharedSecret<Secp256k1>) -> (Aes256Gcm, Nonce<U12>) {
    let hkdf = Hkdf::<Sha256>::new(None, &diffie_secret.raw_secret_bytes());

    let mut okm = [0u8; 32]; // Output keying material
    hkdf.expand(&[], &mut okm).unwrap();
    

    let cipher_key = GenericArray::from_slice(&okm);
    let cipher = Aes256Gcm::new(cipher_key);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    (cipher, nonce)

}

// Helper function to encrypt message using AES-GCM cipher and nonce 
fn encrypt_message_with_cipher(message: &str, cipher: &Aes256Gcm, nonce: &Nonce<U12>) -> Vec<u8> {
    let ciphertext = cipher.encrypt(&nonce, message.as_bytes()).unwrap();
    
    ciphertext
}

// Decrypt ciphertext given computed AES-GCM symmetric secret 
fn decrypt_message(nonce: &Nonce<U12>, cipher: &Aes256Gcm, ciphertext: &Vec<u8>) -> Vec<u8> {
    let decrypted = cipher.decrypt(&nonce, ciphertext.as_ref());

    decrypted.unwrap()
}

// Helper function to sign messages
fn sign_message(secret_key: &SecretKey<Secp256k1>, message: &[u8]) -> Signature {
    let signing_key = SigningKey::from(secret_key.clone());
    signing_key.sign(message)
}

// Helper funciton to verify signatures
fn verify_signature(pubkey: &PublicKey<Secp256k1>, message: &[u8], signature: &Signature) -> bool {
    let verifying_key = VerifyingKey::from(pubkey.clone());
    verifying_key.verify(message, signature).is_ok()
}


// EncryptedMessageInfo struct must contain everything needed to recompute shared secret, and decrypt message on receiving end
pub struct EncryptedMessageInfo{
    ciphertext: Vec<u8>,
    receiver_pubkey: PublicKey<Secp256k1>,
    sender_ephemeral: PublicKey<Secp256k1>,
    nonce: Nonce<U12>,
    sender_id_pubkey: PublicKey<Secp256k1>,
    signature: Signature, 
}

// TODO: 
// send_message will be used in future to send a message to another user (pubkey)
// this returns a EncryptedMessageInfo, which would contain all the information
// necessary to decrypt the message on the receiving end
//
// ephemeral keys must be generated on a message-by-message bassis to preserve signature security.
// users will have main keypair used to sign encrypted messages and prove identity/validity of message
fn send_message(message: &str, from_pub: PublicKey<Secp256k1>, from_secret: SecretKey<Secp256k1>, to_pub: PublicKey<Secp256k1>) -> EncryptedMessageInfo {


    let (eph_pub, eph_sec) = generate_keypair(); 
    let shared_diffie = compute_shared_secret(to_pub, eph_sec);

    let (cipher, nonce) = generate_cipher(shared_diffie);

    let ciphertext = cipher.encrypt(&nonce, message.as_bytes());

    let signing_key = SigningKey::from(&from_secret.clone());

    let signature = sign_message(&from_secret, &ciphertext.clone().unwrap());

    assert!(verify_signature(&from_pub, &ciphertext.clone().unwrap(), &signature));

    let encrypted_message_info = EncryptedMessageInfo {
        ciphertext: ciphertext.clone().unwrap(),
        receiver_pubkey: to_pub,
        sender_ephemeral: eph_pub,
        nonce: nonce,
        sender_id_pubkey: from_pub,
        signature: signature
    };

    encrypted_message_info
}


// Using the information in a EncryptedMessageInfo + the secret key of the indended recipient of a message
// decrypt ciphertext contained in the struct and return the decoded bytes
fn decrypt_message_info(message_info: EncryptedMessageInfo, secret_key: SecretKey<Secp256k1>) -> Vec<u8> {

    // alright, so first recompute the shared secret using senders epheremeral pubkey and your secret key
    let shared_diffie = compute_shared_secret(message_info.sender_ephemeral, secret_key);

    let (cipher, _) = generate_cipher(shared_diffie);

    let decrypted = cipher.decrypt(&message_info.nonce, message_info.ciphertext.as_ref());

    decrypted.unwrap()

}