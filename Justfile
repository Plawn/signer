
# try user generation
user:
    cargo build --bin cli
    target/debug/cli make-sign-request to_sign.json request.json
    target/debug/cli sign-sign-request CAs/user/key.p8 request.json signed.json
    target/debug/cli check-sign-request CAs/user/public.pem signed.json

start-signer:
    cargo build --bin signer
    target/debug/signer --private-key "CAs/signer/key.p8" --public-key "CAs/signer/public.pem" --stamp-public-key "CAs/timestamp/public.pem"

start-front:
    cargo build --bin front
    target/debug/front --authority-address "http://localhost:8080" --stamp-address "http://localhost:3000"

start-stamper:
    cargo build --bin stamper
    target/debug/stamper --private-key "CAs/timestamp/key.p8" --public-key "CAs/timestamp/public.pem"

test-cli:
    cargo build --bin cli
    target/debug/cli sign "CAs/user/key.p8" "example/to_sign.json" > result.json
    echo "Did Sign"
    target/debug/cli check-result "result.json" "example/to_sign.json" "CAs/signer/public.pem"