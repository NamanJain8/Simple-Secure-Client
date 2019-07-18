# Simple-Secure-Client
This assignment was done as a part of Course: System Security under Prof. Pramod Subhramanyan.

## TEAM MEMBERS
- Abhishek Yadav (160040)
- Naman Jain (160427)

## Objectives and Delivered Goals
- Created a cryptographically authenticated, encrypted and secure file store given a untrusted storage server anda trusted public key server.
- Designed the data structures for file system and Implemented the various features like Creating user, Authenti-cating user, Storing file, Loading file, Efficiently Appending file, Sharing file and revoking file, etc while main-taining the confidentiality and integrity of data.
- Explored and Used various cryptographic algorithms and entities like HMAC, Argon2, SHA256, Symmetricand Asymmetric encryption, etc.

## How to run?
Get the required packages

```go get github.com/fenilfadadu/CS628-assn1/userlib```

```go get github.com/google/uuid```

Add tests to assn1/assn1_test.go and run

```go test -v```
