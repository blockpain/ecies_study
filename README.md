# ecies_study

simple ecies study in rust focusing on key generation, compution of shared secret, encrytption/decryption of message

currently uses prgn for generation of nonce. in production an incremental message counter based nonce should be used. the probability of a repeating nonce is still incredibly low
