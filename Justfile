start-signer:
    cargo run --bin signer

# try user generation
user:
    cargo build --bin cli
    target/debug/cli make-sign-request to_sign.json request.json
    target/debug/cli sign-sign-request CAs/user/key.p8 request.json signed.json
    target/debug/cli check-sign-request CAs/user/public.pem signed.json