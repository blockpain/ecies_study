use k256::{ecdsa::{SigningKey, Signature, signature::Signer, VerifyingKey, signature::Verifier}, EncodedPoint, PublicKey};
use k256::ecdh::{EphemeralSecret, SharedSecret};
use rand_core::OsRng; 
use hkdf::Hkdf;
use sha2::Sha256;
use aes_gcm::{KeyInit,Aes256Gcm};
use aes_gcm::aead::{Aead, AeadCore, generic_array::GenericArray};

fn main() {

    let message = "Hello World";

    println!("Message: {message}");

    let msg = message.as_bytes();

    println!("\nMessage as bytes: {:?}", msg);

    let signing_key: SigningKey = SigningKey::random(&mut OsRng);

    let sk_bytes = signing_key.to_bytes();

    println!("\nSigning key: {:x?}",hex::encode(sk_bytes));

    let signature: Signature = signing_key.sign(msg);

    println!("\nSignature: {:?}", signature);


    let verify_key = VerifyingKey::from(&signing_key); 
    // Serialize with `::to_encoded_point()`
    let vk=verify_key.to_bytes();
    println!("\nVerifying key (PubKey): {:x?}",hex::encode(vk));


    let rtn = verify_key.verify(msg, &signature).is_ok();

    if rtn==true { println!("\nMessage '{:?}' signature correct", message); }
    else { println!("\nMessage '{:?}' signature incorrect",message);}




    let secret_a = EphemeralSecret::random(&mut OsRng);
    let encoded_a = EncodedPoint::from(secret_a.public_key());

    let secret_b = EphemeralSecret::random(&mut OsRng);
    let encoded_b = EncodedPoint::from(secret_b.public_key());

    let a_public = PublicKey::from_sec1_bytes(encoded_a.as_ref()).expect("A's public key invalid"); 


    let b_public = PublicKey::from_sec1_bytes(encoded_b.as_ref()).expect("B's public key invalid"); 

    let shared_secret_a: SharedSecret = secret_a.diffie_hellman(&b_public);
    let shared_secret_b: SharedSecret = secret_b.diffie_hellman(&a_public);

    let shared_bytes_a = shared_secret_a.as_bytes();
    let shared_bytes_b = shared_secret_b.as_bytes();

    println!("\nShared bytes a == shared bytes b: {}", shared_bytes_a == shared_bytes_b);

    let hkdf = Hkdf::<Sha256>::new(None, &shared_bytes_a);

    let mut okm = [0u8; 32]; // Output keying material
    hkdf.expand(&[], &mut okm).unwrap();
    

    let cipher_key = GenericArray::from_slice(&okm);
    let cipher = Aes256Gcm::new(cipher_key);

        // Now we can encrypt and authenticate our message.
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    

    let ciphertext = cipher.encrypt(&nonce, message.as_bytes()).unwrap();
    let decrypted = cipher.decrypt(&nonce, ciphertext.as_ref());

    // To authenticate the message, we can use the nonce and ciphertext.
    println!("\nEncrypted and authenticated message: {:?}", ciphertext);
    println!("\nNonce: {:?}", nonce);
    println!("\nDecrypted message: {:?}", decrypted.unwrap());

    

}

