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
	Username     string // Username
	Argon_pass   []byte // Argon password
	Password     string
	RSAkey       userlib.PrivateKey // Public Private pair for user RSA
	Filemap      map[string]string  // Map for filename -> location
	Metamap      map[string]string  // location of the metamap
	Filekey      map[string][]byte  // Hex string for filekey
	Userhmackeys map[string][]byte  // H (k,E(file))
	SHA          string             // hex string for SHA of above data (see GenerateUserHash)
}
type File struct {
	Symmetric_key  []byte   // Symmetric key (also IV) for encrypting the corresponding contents
	Locations      []string // locations at which these segments of file would be stored
	Hash_locations []string // hash of location_data for integrity check
	Filehamckeys   [][]byte // byte of hmac keys of the content
	Datasigns      [][]byte // Hmac sign of the corresponding content H(k,E(data))
	// SHA            string   // hex string for SHA of above data
}
type File_data struct {
	Data []byte
	// SHA  string
}
type Meta struct {
	Filesign []byte // store the H(k,E(m))
}

//////////// DEBUG
func GetMapContent(key string) ([]byte, bool) {
	content, status := userlib.DatastoreGet(key)
	if !status {
		return []byte("Content not found"), status
	}
	return content, true
}

func SetMapContent(key string, value []byte) {
	userlib.DatastoreSet(key, value)
}

///////////// DEBUG

func GetUserKey(username string, password string) string {
	// Generate the key corresponding to provided user credentials
	userKey := toSHAString(username)

	return userKey
}

func (user *User) GetInodeKey(filename string) string {
	// Generate the key corresponding to provided filename
	if user.Filemap[filename] == "" {
		userlib.DebugMsg("File not found")
	}
	fileKey := user.Filemap[filename]
	return fileKey
}

func toFileHash(filedata File) string {
	var filereq File
	filereq.Symmetric_key = filedata.Symmetric_key
	filereq.Locations = filedata.Locations
	filereq.Hash_locations = filedata.Hash_locations
	bytes, _ := json.Marshal(filereq)
	userlib.DebugMsg("This would be converted to SHA : %x", bytes)
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
	userreq.Password = userdata.Password
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

func AESEncrypt(bytes []byte, key []byte) []byte {
	ciphertext := make([]byte, aesBlockSize+len(bytes))
	iv := ciphertext[:aesBlockSize]
	copy(iv, key[:aesBlockSize])
	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(ciphertext[aesBlockSize:], bytes)
	return ciphertext
}

func AESDecrypt(bytes []byte, key []byte) []byte {
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
	userdata.Filekey = make(map[string][]byte)
	userdata.Metamap = make(map[string]string)
	userdata.Password = password
	userdata.Userhmackeys = make(map[string][]byte)
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
	if len(bytes) < aesBlockSize {
		err = errors.New("Data store corrupted")
		return nil, err
	}
	ciphertext := AESDecrypt(bytes, argon_pass)

	// Unmarshal into User structure
	var userdata User
	err = json.Unmarshal(ciphertext, &userdata)
	if err != nil {
		userlib.DebugMsg("[get user] error in unmarshal ", err)
		return nil, err
	}

	// Compare hash and throw error if not matched
	newhash := toUserHash(userdata)
	if userlib.Equal([]byte(newhash), []byte(userdata.SHA)) != true {
		err := errors.New("[GetUser] Userdata tampered")
		return nil, err
	}

	userlib.DebugMsg("User address: %v", &userdata)
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
	// filedata.SHA = toFiledataHash(filedata)

	// Now we need to encrypt it

	bytes, _ := json.Marshal(filedata)
	ciphertext := AESEncrypt(bytes, aeskey)

	// Now set it to the datastore

	userlib.DatastoreSet(addressKey, ciphertext)
	return
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	userdata, _ = GetUser(userdata.Username, userdata.Password)

	// generate all required contents first : IV(K_sym),'key' where to store this struct
	Ksym := userlib.RandomBytes(aesBlockSize) //bytes of AES key for the File struct
	aeskey := userlib.RandomBytes(aesBlockSize)
	userhmackey := userlib.RandomBytes(aesBlockSize) // generate a random HMAC key
	filehmackey := userlib.RandomBytes(aesBlockSize) // Hmac key for content
	var effective_filename = userdata.Username + "_" + filename
	var effective_filename2 = effective_filename + "_" + string(0)
	var meta_filename = "meta" + "_" + effective_filename
	addresskey := toSHAString(effective_filename)
	addresskey2 := toSHAString(effective_filename2)
	addresskey3 := toSHAString(meta_filename)
	if userdata.Filemap[filename] != "" {
		addresskey = userdata.Filemap[filename]
		Ksym = userdata.Filekey[filename]
		userhmackey = userdata.Userhmackeys[filename]
		addresskey3 = userdata.Metamap[filename]
	}

	// here first file data would be stored
	// addresskey2 would be stored in locations []
	// store the file content where it is supposed to be

	storeFiledata(data, aeskey, addresskey2)
	databytes, _ := userlib.DatastoreGet(addresskey2)
	// find the sign for this content
	datamac := userlib.NewHMAC(filehmackey)
	datamac.Write(databytes)
	datamaca := datamac.Sum(nil) // this is the required sign for the data that has been stored just now
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
	filedata.Filehamckeys = make([][]byte, 0)
	filedata.Filehamckeys = append([][]byte(filedata.Filehamckeys), (filehmackey))
	filedata.Datasigns = make([][]byte, 0)
	filedata.Datasigns = append([][]byte(filedata.Datasigns), (datamaca))
	// filedata.SHA = toFileHash(filedata)
	// userlib.DebugMsg("Found key in STORE : %x ", (filedata.Filehamckeys[0]))
	// now encrypt it using Ksym

	var metadata Meta

	filebytes, _ := json.Marshal(filedata)
	fileciphertext := AESEncrypt(filebytes, Ksym)

	// find the sign with username as the key

	mac := userlib.NewHMAC(userhmackey) // key is the bytes of the username itself
	mac.Write(fileciphertext)

	maca := mac.Sum(nil)
	userdata.Userhmackeys[filename] = userhmackey // add Hmac Key
	metadata.Filesign = maca
	userlib.DebugMsg("store File : %x", maca) // add this to user struct

	metabytes, _ := json.Marshal(metadata)
	metaciphertext := AESEncrypt(metabytes, Ksym)
	userlib.DatastoreSet(addresskey3, metaciphertext)

	// Now we need to set map in user struct and Sign of file
	userdata.Filemap[filename] = addresskey
	// KsymString := string(Ksym)
	userdata.Filekey[filename] = Ksym
	userdata.Metamap[filename] = addresskey3
	// remodify the userdata hash ===== importtant
	userdata.SHA = toUserHash(*userdata)

	// re-enter the user struct in data store because has has been changed

	s := toSHAString(userdata.Username)
	bytes, _ := json.Marshal(userdata)
	ciphertext := AESEncrypt(bytes, userdata.Argon_pass)
	userlib.DatastoreSet(s, ciphertext)

	// place on the data store
	userlib.DatastoreSet(addresskey, fileciphertext)
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// userdata, _ = GetUser(userdata.Username, userdata.Password)
	// Reload user
	mys := toSHAString(userdata.Username)
	mybytes, valid := userlib.DatastoreGet(mys)

	// Return error if user not found
	if !valid {
		err := errors.New("[GetUser] DataStore corrupted or user not found")
		return err
	}

	if len(mybytes) < aesBlockSize {
		err = errors.New("Data store corrupted")
		return err
	}
	myciphertext := AESDecrypt(mybytes, userdata.Argon_pass)

	// Unmarshal into User structure
	var myuserdata User
	err = json.Unmarshal(myciphertext, &myuserdata)
	if err != nil {
		userlib.DebugMsg("[get user] error in unmarshal ", err)
		return err
	}

	// Compare hash and throw error if not matched
	mynewhash := toUserHash(myuserdata)
	if userlib.Equal([]byte(mynewhash), []byte(myuserdata.SHA)) != true {
		err := errors.New("[GetUser] Userdata tampered")
		return err
	}

	userlib.DebugMsg("User address: %v", &userdata)
	*userdata = myuserdata

	// ================================================================

	addressKey := userdata.Filemap[filename]
	Ksym := userdata.Filekey[filename]
	bytes, valid := userlib.DatastoreGet(addressKey)
	if !valid {
		err := errors.New("[LoadFile] DataStore corrupted or File not found")
		return err
	}

	mac := userlib.NewHMAC(userdata.Userhmackeys[filename]) // key is the bytes of the username itself
	mac.Write(bytes)
	maca := mac.Sum(nil)
	// if userlib.Equal([]byte(maca), []byte(userdata.Filesign[filename])) != true {
	// 	err := errors.New("[LoadFile] File tampered2")
	// 	return err
	// }

	// Decrypt using Ksym as key
	if len(bytes) < aesBlockSize {
		err = errors.New("Data store corrupted")
		return err
	}
	ciphertext := AESDecrypt(bytes, Ksym)
	var file File
	err = json.Unmarshal(ciphertext, &file)
	if err != nil {
		userlib.DebugMsg("[append file] error in unmarshal ", err)
		return err
	}
	// newhash := toFileHash(file)
	// if userlib.Equal([]byte(newhash), []byte(file.SHA)) != true {
	// 	err := errors.New("[LoadFile] File tampered2")
	// 	return err
	// }
	var effective_filename = userdata.Username + "_" + filename
	var effective_filename2 = effective_filename + "_" + string(len(file.Locations))
	addresskey2 := toSHAString(effective_filename2) // here new data has to be put

	storeFiledata(data, file.Symmetric_key, addresskey2)

	// append the sign for the new content

	appendedbytes, _ := userlib.DatastoreGet(addresskey2)
	filehmackey := userlib.RandomBytes(aesBlockSize) // Hmac key for content
	mac = userlib.NewHMAC(filehmackey)
	mac.Write(appendedbytes)
	maca = mac.Sum(nil)

	// append the hmac key and sign in the respective list

	file.Filehamckeys = append([][]byte(file.Filehamckeys), filehmackey)
	file.Datasigns = append([][]byte(file.Datasigns), maca)
	// userlib.DebugMsg("Hmac key for appended : %x", filehmackey)

	// content jaa chuka hai, now its time to append to locations

	file.Locations = append([]string(file.Locations), addresskey2)

	// Now add the corresponding entry for hash locations
	dataString := string(data)
	AddressContent := addresskey2 + dataString // element pf hash_locations []
	AddressContentHash := toSHAString(AddressContent)
	file.Hash_locations = append([]string(file.Hash_locations), AddressContentHash)

	// change SHA of the file
	// file.SHA = toFileHash(file)

	// put back file in the data store

	filebytes, _ := json.Marshal(file)
	fileciphertext := AESEncrypt(filebytes, Ksym)

	var metadata Meta

	// now update the Hmac sign in the user struct
	mac = userlib.NewHMAC(userdata.Userhmackeys[filename])
	mac.Write(fileciphertext)
	maca = mac.Sum(nil)
	metadata.Filesign = maca

	metabytes, _ := json.Marshal(metadata)
	metaciphertext := AESEncrypt(metabytes, Ksym)
	userlib.DatastoreSet(userdata.Metamap[filename], metaciphertext)

	// userdata.Filesign[filename] = maca
	userdata.SHA = toUserHash(*userdata)

	s := toSHAString(userdata.Username)
	bytes, _ = json.Marshal(userdata)
	ciphertext = AESEncrypt(bytes, userdata.Argon_pass)
	userlib.DatastoreSet(s, ciphertext)

	// place on the data store
	userlib.DatastoreSet(addressKey, fileciphertext)
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	// reload the user ====

	userdata, _ = GetUser(userdata.Username, userdata.Password)

	// get address of the corresponding File struct
	addresskey := userdata.Filemap[filename] // get string of the address
	Ksym := userdata.Filekey[filename]       // get Symmetric Key for decryption
	// Ksym := ([]byte(KsymString))
	bytes, valid := userlib.DatastoreGet(addresskey)
	// userlib.DebugMsg("Found bytes from store : %x", bytes)

	metabytes, valid := userlib.DatastoreGet(userdata.Metamap[filename])
	if len(metabytes) < aesBlockSize {
		err = errors.New("Data store corrupted")
		return nil, err
	}
	metaciphertext := AESDecrypt(metabytes, Ksym)
	var metadata Meta
	_ = json.Unmarshal(metaciphertext, &metadata)

	mac := userlib.NewHMAC(userdata.Userhmackeys[filename]) // key is the bytes of the username itself
	mac.Write(bytes)
	maca := mac.Sum(nil)
	userlib.DebugMsg("Load file : %x", maca)
	userlib.DebugMsg("Load file : %x", []byte(metadata.Filesign))

	if userlib.Equal([]byte(maca), []byte(metadata.Filesign)) != true {
		err := errors.New("[LoadFile] File tampered2")
		return nil, err
	}

	// userlib.DebugMsg("addr key: %v", bytes)
	// Return error if File not found
	if !valid {
		err := errors.New("[LoadFile] DataStore corrupted or File not found")
		return nil, err
	}
	// userlib.DebugMsg("Sym key in load: %v", Ksym)

	// Decrypt using Ksym as key
	if len(bytes) < aesBlockSize {
		err = errors.New("Data store corrupted")
		return nil, err
	}
	ciphertext := AESDecrypt(bytes, Ksym)

	var file File
	_ = json.Unmarshal(ciphertext, &file) // for the time being do not get error from unmarshal
	// if err != nil {
	// 	userlib.DebugMsg("[load file] error in unmarshal here ", err)
	// 	return nil, err
	// }
	// newhash := toFileHash(file)
	// if userlib.Equal([]byte(newhash), []byte(file.SHA)) != true {
	// 	err := errors.New("[LoadFile] File tampered2")
	// 	return nil, err
	// }
	// Now the File data has been verified to be untampered, iterate over all locations
	var content = ""
	for index, element := range file.Locations {
		databytes, datavalid := userlib.DatastoreGet(element)
		if !datavalid {
			err := errors.New("[LoadFile] DataStore corrupted or filedata not found")
			return nil, err
		}
		// data bytes is encrypted bytes, check its integrity now using HMAC
		// userlib.DebugMsg("Found key in LOAD : %x ", (file.Filehamckeys[index]))

		datamac := userlib.NewHMAC([]byte(file.Filehamckeys[index]))
		datamac.Write(databytes)
		datamaca := datamac.Sum(nil)
		if userlib.Equal(datamaca, []byte(file.Datasigns[index])) != true {
			err := errors.New("[LoadFile] content tampered")
			return nil, err
		}

		// Decrypt using Ksym as key
		aeskey := file.Symmetric_key
		if len(databytes) < aesBlockSize {
			err = errors.New("Data store corrupted")
			return nil, err
		}
		ciphertext := AESDecrypt(databytes, aeskey)

		var filedata File_data
		err = json.Unmarshal(ciphertext, &filedata)
		if err != nil {
			userlib.DebugMsg("[load file] error in unmarshal in loop", err)
			return nil, err
		}
		// newhash := toFiledataHash(filedata)
		// if userlib.Equal([]byte(newhash), []byte(filedata.SHA)) != true {
		// 	err := errors.New("[LoadFile] File tampered")
		// 	return nil, err
		// }

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
	Addresskey    string // Key of file in datastore
	Symmetric_key []byte // Symmetric Key of file
	Userhmackey   []byte // send the key to the other user as well to sign the content
	Metadatakey   string // get the file sign as well to check if he recieved the correct file
	RSA_Sign      []byte // RSA_Sign to verify integrity of this message
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
	userdata, _ = GetUser(userdata.Username, userdata.Password)

	var record sharingRecord
	// Fill up record
	record.Addresskey = userdata.Filemap[filename]
	record.Symmetric_key = userdata.Filekey[filename]
	record.Userhmackey = userdata.Userhmackeys[filename] // can check here for integrity as well if needed
	record.Metadatakey = userdata.Metamap[filename]
	// record.Filesign = userdata.Filesign[filename]

	_, err2 := userlib.DatastoreGet(record.Addresskey)
	if !err2 {
		err := errors.New("[ShareFile] DataStore corrupted")
		return "", err
	}

	// Sign the message (addresskey + symmetric_key)
	// First convert to bytes and then RSAsign
	msg, _ := json.Marshal(record)
	sign, _ := userlib.RSASign(&(userdata.RSAkey), msg)
	record.RSA_Sign = sign

	pub, _ := userlib.KeystoreGet(recipient) // change this to original
	// pub, _ := userlib.KeystoreGet(userdata.Username)

	signed_msg, _ := json.Marshal(record)
	// Encrypt the message
	encryptedmessage := make([]byte, 0)
	for i := 0; i < len(signed_msg); i += 128 {
		prev := i
		last := (i + 128)
		if last > len(signed_msg) {
			last = len(signed_msg)
		}
		message, _ := userlib.RSAEncrypt(&pub, signed_msg[prev:last], []byte(nil))
		encryptedmessage = append(encryptedmessage, message...)
	}

	msgid = string(encryptedmessage)
	return
}

func recordToMsg(record sharingRecord) []byte {
	var recordreq sharingRecord
	recordreq.Addresskey = record.Addresskey
	recordreq.Symmetric_key = record.Symmetric_key
	recordreq.Userhmackey = record.Userhmackey
	recordreq.Metadatakey = record.Metadatakey
	bytes, _ := json.Marshal(recordreq)
	return bytes
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	userdata, _ = GetUser(userdata.Username, userdata.Password)

	// Decrypt the message
	encryptedmessage := []byte(msgid)
	decryptedmessage := make([]byte, 0)

	for i := 0; i < len(encryptedmessage); i += 256 {
		prev := i
		last := (i + 256)
		if last > len(encryptedmessage) {
			last = len(encryptedmessage)
		}
		decryptedbytes, err3 := userlib.RSADecrypt(&(userdata.RSAkey), []byte(encryptedmessage[prev:last]), []byte(nil))
		if err3 != nil {
			userlib.DebugMsg("wow : %s", err3)
		}
		decryptedmessage = append(decryptedmessage, decryptedbytes...)
	}
	var record sharingRecord
	err := json.Unmarshal(decryptedmessage, &record)
	if err != nil {
		userlib.DebugMsg("[recieve file] error in unmarshal ", err)
		return err
	}

	// Check RSA Sign
	sign := record.RSA_Sign
	msg := recordToMsg(record)
	pub, _ := userlib.KeystoreGet(sender)
	err = userlib.RSAVerify(&pub, msg, sign)

	if err != nil {
		err := errors.New("[ReceiveFile] Message tampered")
		return err
	}
	// Integrity preserved if control reaches here
	// Now we need to set map in user struct
	userdata.Filemap[filename] = record.Addresskey
	Ksym := record.Symmetric_key
	userdata.Filekey[filename] = Ksym
	userdata.Userhmackeys[filename] = record.Userhmackey
	// userdata.Filesign[filename] = record.Filesign
	userdata.Metamap[filename] = record.Metadatakey

	// remodify the userdata hash ===== importtant

	userdata.SHA = toUserHash(*userdata)
	s := toSHAString(userdata.Username)
	bytes, _ := json.Marshal(userdata)
	ciphertext := AESEncrypt(bytes, userdata.Argon_pass)
	userlib.DatastoreSet(s, ciphertext)

	// var receiverFile *File

	_, ok := userlib.DatastoreGet(record.Addresskey)
	if !ok {
		err := errors.New("[ReceiveFile] Datastore corrupted or file not found")
		return err
	}

	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	userdata, _ = GetUser(userdata.Username, userdata.Password)

	// check if the file actually belongs to the user

	// var effective_filename = userdata.Username + "_" + filename
	// addresskey := toSHAString(effective_filename)
	// if userlib.Equal([]byte(addresskey), []byte(userdata.Filemap[filename])) != true {
	// 	err := errors.New("cant be revoked")
	// 	return err
	// }

	// Generate new symmetric key and get file
	Ksym := userdata.Filekey[filename]
	Ksymnew := userlib.RandomBytes(aesBlockSize) //bytes of AES key for the File struct
	userdata.Filekey[filename] = Ksymnew
	file_addr := userdata.Filemap[filename]
	bytes, valid := userlib.DatastoreGet(file_addr)
	if !valid {
		err := errors.New("[ShareFile] DataStore corrupted2")
		return err
	}

	// Decrypt using Ksym as key
	if len(bytes) < aesBlockSize {
		err = errors.New("Data store corrupted")
		return err
	}
	ciphertext := AESDecrypt(bytes, Ksym)
	var file File
	err = json.Unmarshal(ciphertext, &file)
	if err != nil {
		userlib.DebugMsg("[revoke file] error in unmarshal ", err)
		return err
	}
	// newhash := toFileHash(file)
	// if userlib.Equal([]byte(newhash), []byte(file.SHA)) != true {
	// 	err := errors.New("[RevokeFile] File tampered")
	// 	return err
	// }

	// Change symmetic key to new symmetric key
	// file.SHA = toFileHash(file)

	filebytes, _ := json.Marshal(file)
	fileciphertext := AESEncrypt(filebytes, Ksymnew)
	userlib.DatastoreSet(file_addr, fileciphertext)

	mac := userlib.NewHMAC(userdata.Userhmackeys[filename])
	mac.Write(fileciphertext)
	maca := mac.Sum(nil)

	var metadata Meta
	metadata.Filesign = maca

	metabytes, _ := json.Marshal(metadata)
	metaciphertext := AESEncrypt(metabytes, Ksymnew)
	userlib.DatastoreSet(userdata.Metamap[filename], metaciphertext)

	// remodify the userdata hash ===== importtant
	userdata.SHA = toUserHash(*userdata)

	// re-enter the user struct in data store because has has been changed

	s := toSHAString(userdata.Username)

	userbytes, _ := json.Marshal(*userdata)
	userciphertext := AESEncrypt(userbytes, userdata.Argon_pass)
	userlib.DatastoreSet(s, userciphertext)

	return
}
