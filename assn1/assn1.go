package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/fenilfadadu/CS628-assn1/userlib
	"github.com/fenilfadadu/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}


// func structToBytes(){

// }

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

var aesBlockSize = userlib.BlockSize


// The structure definition for a user record
type User struct {
	// All fields must be capital for JSON marshal to work
	Username string 	// Username
	Argon_pass []byte	// Argon password
	RSAkey userlib.PrivateKey // Public Private pair for user RSA
	Filemap map[string]string // Map for filename -> location
	Filekey map[string]string // Hex string for filekey
	SHA string 	// hex string for SHA of above data (see GenerateUserHash)
}


// 
func toUserHash(userdata User) string{
	var userreq User
	userreq.Username = userdata.Username
	userreq.Argon_pass = userdata.Argon_pass
	userreq.RSAkey = userdata.RSAkey
	userreq.Filemap = userdata.Filemap
	userreq.Filekey = userdata.Filekey
    bytes,_ := json.Marshal(userreq)

    
	hash := userlib.NewSHA256()
	hash.Write([]byte(bytes))
	sha := hex.EncodeToString(hash.Sum(nil))
	return sha
}

// Generates SHA Hash of string
func toSHAString(key string)string{
	hash := userlib.NewSHA256()
	hash.Write([]byte(key))
	hashedkey := hex.EncodeToString(hash.Sum(nil))
	return hashedkey
}

// Takes password and salt, return 16 byte argon2hash
func toArgon2Hash(password string, salt string)[]byte{
	return userlib.Argon2Key([]byte(password), []byte(salt), 16)
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {

	// Generate Argon of password using username as salt
	argon_pass := toArgon2Hash(password, username)

	// Generate Public Private Pair
	key, err := userlib.GenerateRSAKey()
	pubkey := key.PublicKey
	userlib.KeystoreSet(username, pubkey)

	// Setup user structure
	var userdata User
	userdata.Username = username
	userdata.Argon_pass = argon_pass
	userdata.RSAkey = *key
	userdata.Filemap = make(map[string]string)
	userdata.Filekey = make(map[string]string)
	userdata.SHA = toUserHash(userdata)

	// Insert into DataStore with encryption	
	s := toSHAString(username)
	bytes,_ := json.Marshal(userdata) 

	ciphertext := make([]byte, aesBlockSize+len(bytes))
	iv := ciphertext[:aesBlockSize]
	copy(iv, argon_pass[:aesBlockSize])
	cipher := userlib.CFBEncrypter(argon_pass, iv) 
	cipher.XORKeyStream(ciphertext[aesBlockSize:], bytes)

	userlib.DatastoreSet(s, ciphertext)
	
	// Ensure if inserted or not
	_, valid := userlib.DatastoreGet(s)

	// Check initialisation
	if !valid {
		err := errors.New("[InitUser] User initialization failed")
		return nil,err
	}	else {
		return &userdata, err
	}
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	// Get user bytes corrsponding to SHA of username
	s := toSHAString(username)
	bytes, valid := userlib.DatastoreGet(s)

	// Return error if user not found
	if !valid {
		err := errors.New("[GetUser] DataStore corrupted or user not found")
		return nil,err
	} 
	
	// Decrypt using Argon2 of Password as key
	argon_pass := toArgon2Hash(password,username)
	ciphertext := make([]byte, len(bytes))
	iv := make([]byte, aesBlockSize)
	copy(iv, argon_pass[:aesBlockSize])
	cipher := userlib.CFBDecrypter(argon_pass, iv)
	cipher.XORKeyStream(ciphertext[aesBlockSize:], bytes[aesBlockSize:])

	// Unmarshal into User structure
	var userdata User
	json.Unmarshal(ciphertext[aesBlockSize:], &userdata)

	// Compare hash and throw error if not matched
	newhash := toUserHash(userdata)
	if userlib.Equal([]byte(newhash), []byte(userdata.SHA)) != true{
		err := errors.New("[GetUser] Userdata tampered")
		return nil, err
	}

	return &userdata,nil
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	return
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	msgid string, err error) {
	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	return
}