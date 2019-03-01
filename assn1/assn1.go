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
	Username   string             // Username
	Argon_pass []byte             // Argon password
	RSAkey     userlib.PrivateKey // Public Private pair for user RSA
	Filemap    map[string]string  // Map for filename -> location
	Filekey    map[string]string  // Hex string for filekey
	SHA        string             // hex string for SHA of above data (see GenerateUserHash)
}
type File struct {
	Symmetric_key  []byte   // Symmetric key (also IV) for encrypting the corresponding contents
	Locations      []string // locations at which these segments of file would be stored
	Hash_locations []string // hash of location_data for integrity check
	SHA            string   // hex string for SHA of above data
}
type File_data struct {
	Data []byte
	SHA  string
}

func toFileHash(filedata File) string {
	var filereq File
	filereq.Symmetric_key = filedata.Symmetric_key
	filereq.Locations = filedata.Locations
	filereq.Hash_locations = filedata.Hash_locations
	bytes, _ := json.Marshal(filereq)
	hash := userlib.NewSHA256()
	hash.Write([]byte(bytes))
	sha := hex.EncodeToString(hash.Sum(nil))
	return sha
}

func toUserHash(userdata User) string {
	var userreq User
	userreq.Username = userdata.Username
	userreq.Argon_pass = userdata.Argon_pass
	userreq.RSAkey = userdata.RSAkey
	userreq.Filemap = userdata.Filemap
	userreq.Filekey = userdata.Filekey
	bytes, _ := json.Marshal(userreq)
	hash := userlib.NewSHA256()
	hash.Write([]byte(bytes))
	sha := hex.EncodeToString(hash.Sum(nil))
	return sha
}

// Generates SHA Hash of string
func toSHAString(key string) string {
	hash := userlib.NewSHA256()
	hash.Write([]byte(key))
	hashedkey := hex.EncodeToString(hash.Sum(nil))
	return hashedkey
}

// Takes password and salt, return 16 byte argon2hash
func toArgon2Hash(password string, salt string) []byte {
	return userlib.Argon2Key([]byte(password), []byte(salt), 16)
}

func AESEncrypt(bytes []byte, key []byte)[]byte{
	ciphertext := make([]byte, aesBlockSize+len(bytes))
	iv := ciphertext[:aesBlockSize]
	copy(iv, key[:aesBlockSize])
	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(ciphertext[aesBlockSize:], bytes)
	return ciphertext
}

func AESDecrypt(bytes []byte, key []byte)[]byte{
	ciphertext := make([]byte, len(bytes))
	iv := make([]byte, aesBlockSize)
	copy(iv, key[:aesBlockSize])
	cipher := userlib.CFBDecrypter(key, iv)
	cipher.XORKeyStream(ciphertext[aesBlockSize:], bytes[aesBlockSize:])
	return ciphertext[aesBlockSize:]
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
	bytes, _ := json.Marshal(userdata)
	ciphertext := AESEncrypt(bytes, argon_pass)
	userlib.DatastoreSet(s, ciphertext)

	// Ensure if inserted or not
	_, valid := userlib.DatastoreGet(s)

	// Check initialisation
	if !valid {
		err := errors.New("[InitUser] User initialization failed")
		return nil, err
	} else {
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
		return nil, err
	}

	// Decrypt using Argon2 of Password as key
	argon_pass := toArgon2Hash(password, username)
	ciphertext := AESDecrypt(bytes, argon_pass)

	// Unmarshal into User structure
	var userdata User
	json.Unmarshal(ciphertext, &userdata)

	// Compare hash and throw error if not matched
	newhash := toUserHash(userdata)
	if userlib.Equal([]byte(newhash), []byte(userdata.SHA)) != true {
		err := errors.New("[GetUser] Userdata tampered")
		return nil, err
	}

	return &userdata, nil
}
func toFiledataHash(filedata File_data) string {
	hash := userlib.NewSHA256()
	hash.Write([]byte(filedata.Data))
	sha := hex.EncodeToString(hash.Sum(nil)) // this is the SHA of data
	return sha
}

func storeFiledata(data []byte, aeskey []byte, addressKey string) {

	var filedata File_data
	filedata.Data = data
	filedata.SHA = toFiledataHash(filedata)

	// Now we need to encrypt it

	bytes, _ := json.Marshal(filedata)
	ciphertext := make([]byte, aesBlockSize+len(bytes))
	iv := ciphertext[:aesBlockSize]
	copy(iv, aeskey[:aesBlockSize])
	cipher := userlib.CFBEncrypter(aeskey, iv)
	cipher.XORKeyStream(ciphertext[aesBlockSize:], bytes)

	// Now set it to the datastore

	userlib.DatastoreSet(addressKey, ciphertext)
	return
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	// generate all required contents first : IV(K_sym),'key' where to store this struct
	Ksym := userlib.RandomBytes(aesBlockSize) //bytes of AES key for the File struct
	aeskey := userlib.RandomBytes(aesBlockSize)

	var effective_filename = userdata.Username + "_" + filename
	var effective_filename2 = effective_filename + "_" + string(0)
	addresskey := toSHAString(effective_filename)
	addresskey2 := toSHAString(effective_filename2)
	// here first file data would be stored
	// addresskey2 would be stored in locations []
	// store the file content where it is supposed to be

	storeFiledata(data, aeskey, addresskey2)

	// now we have 'key' for storing data and 'symmetric_key' for AES encryption
	// Time to get hash(addressKey2,data) append addressKey2 + data and find SHA

	dataString := string(data)
	AddressContent := addresskey2 + dataString // element pf hash_locations []
	AddressContentHash := toSHAString(AddressContent)

	// now set all the fileds in the structure

	var filedata File
	filedata.Symmetric_key = aeskey
	filedata.Locations = make([]string, 0)
	filedata.Locations = append([]string(filedata.Locations), addresskey2)
	filedata.Hash_locations = make([]string, 0)
	filedata.Hash_locations = append([]string(filedata.Hash_locations), AddressContentHash)
	filedata.SHA = toFileHash(filedata)

	// Now we need to set map in user struct

	userdata.Filemap[filename] = addresskey
	KsymString := string(Ksym)
	userdata.Filekey[filename] = KsymString

	// remodify the userdata hash ===== importtant

	userdata.SHA = toUserHash(*userdata)

	// now encrypt it using Ksym
	bytes, _ := json.Marshal(filedata)
	ciphertext := AESEncrypt(bytes, Ksym)

	// place on the data store
	userlib.DatastoreSet(addresskey, ciphertext)
	// userlib.DebugMsg("Before Encryption: %v", bytes)
	// userlib.DebugMsg("After Encryption: %v", ciphertext)
	// userlib.DebugMsg("Aftre IV: %v", iv)
	// userlib.DebugMsg("Aftre Ksym: %v", Ksym)
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
	// get address of the corresponding File struct
	addresskey := userdata.Filemap[filename] // get string of the address
	KsymString := userdata.Filekey[filename] // get Symmetric Key for decryption
	Ksym := ([]byte(KsymString))
	bytes, valid := userlib.DatastoreGet(addresskey)
	// userlib.DebugMsg("addr key: %v", bytes)
	// Return error if File not found

	if !valid {
		err := errors.New("[LoadFile] DataStore corrupted or File not found")
		return nil, err
	}

	// Decrypt using Ksym as key
	ciphertext := AESDecrypt(bytes,Ksym)
	// userlib.DebugMsg("Before Decryuption: %v", bytes)
	// userlib.DebugMsg("After Decryuption: %v", ciphertext)
	// userlib.DebugMsg("Aftre IV: %v", iv)
	// userlib.DebugMsg("Aftre Ksym: %v", Ksym)
	// Unmarshal into User structure
	var file File
	json.Unmarshal(ciphertext, &file)
	newhash := toFileHash(file)
	if userlib.Equal([]byte(newhash), []byte(file.SHA)) != true {
		err := errors.New("[LoadFile] File tampered2")
		return nil, err
	}
	// userlib.DebugMsg("Reached")
	// Now the File data has been verified to be untampered, iterate over all locations
	var content = ""
	for index, element := range file.Locations {
		databytes, datavalid := userlib.DatastoreGet(element)
		if !datavalid {
			err := errors.New("[LoadFile] DataStore corrupted or filedata not found")
			return nil, err
		}

		// Decrypt using Ksym as key
		aeskey := file.Symmetric_key
		ciphertext := AESDecrypt(databytes, aeskey)

		var filedata File_data
		json.Unmarshal(ciphertext, &filedata)
		newhash := toFiledataHash(filedata)
		if userlib.Equal([]byte(newhash), []byte(filedata.SHA)) != true {
			err := errors.New("[LoadFile] File tampered")
			return nil, err
		}

		dataString := string(filedata.Data)
		AddressContent := element + dataString // element pf hash_locations []
		AddressContentHash := toSHAString(AddressContent)

		if userlib.Equal([]byte(AddressContentHash), []byte(file.Hash_locations[index])) != true {
			err := errors.New("[LoadFile] File tampered")
			return nil, err
		}
		// now this content has been verified, convert to string and append
		content += dataString
	}
	data = ([]byte(content))
	return data, err
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	Addresskey string 		// Key of file in datastore
	Symmetric_key []byte 	// Symmetric Key of file
	RSA_Sign []byte 		// RSA_Sign to verify integrity
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

	userlib.DebugMsg("address: %v", []byte("hello"))
	var record sharingRecord
	// Fill up record
	record.Addresskey = userdata.Filekey[filename]
	record.Symmetric_key = []byte(userdata.Filekey[filename])

	bytes, err2 := userlib.DatastoreGet(record.Addresskey)
	userlib.DebugMsg("bytes: %v", string(bytes))
	if !err2{
		err := errors.New("[ShareFile] DataStore corrupted")
		return "hello", err
	}

	// Sign the message (addresskey + symmetric_key) 
	// First convert to bytes and then RSAsign
	msg, _ := json.Marshal(record)
	sign, _ := userlib.RSASign(&(userdata.RSAkey), msg)
	record.RSA_Sign = sign

	pub,_ := userlib.KeystoreGet(recipient)
	signed_msg, _ := json.Marshal(record)
	// Encrypt the message
	message, err := userlib.RSAEncrypt(&pub,signed_msg,[]byte("Tag"))
	msgid = string(message)

	return
}


func recordToMsg(record sharingRecord) []byte{
	var recordreq sharingRecord
	recordreq.Addresskey = record.Addresskey
	recordreq.Symmetric_key = record.Symmetric_key
	bytes, _ := json.Marshal(recordreq)
	return bytes
}


// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	// Decrypt the message
	decrypted_msg,_ := userlib.RSADecrypt(&(userdata.RSAkey), []byte(msgid), []byte("Tag"))

	var record sharingRecord
	json.Unmarshal(decrypted_msg, &record)

	// Check RSA Sign
	sign := record.RSA_Sign
	msg := recordToMsg(record)
	pub,_ := userlib.KeystoreGet(sender)
	err := userlib.RSAVerify(&pub,msg,sign)

	if err!=nil {
		err := errors.New("[ReceiveFile] Message tampered")
		return err
	}
	userlib.DebugMsg("ReceiveFile record: %v", record)
	// Integrity preserved if control reaches here
	// Now we need to set map in user struct

	effective_filename := userdata.Username + "_" + filename
	addresskey := toSHAString(effective_filename)
	userdata.Filemap[filename] = addresskey
	KsymString := string(record.Symmetric_key)
	userdata.Filekey[filename] = KsymString

	// remodify the userdata hash ===== importtant

	userdata.SHA = toUserHash(*userdata)

	// var receiverFile *File

	_, ok := userlib.DatastoreGet(record.Addresskey) 
	if !ok{
		err := errors.New("[ReceiveFile] Datastore corrupted or file not found")
		return err
	}


	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	return
}
