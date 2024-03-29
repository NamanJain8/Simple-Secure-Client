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
	Username   string // Username
	Argon_pass []byte // Argon password
	Password   string
	RSAkey     userlib.PrivateKey // Public Private pair for user RSA
	Filemap    map[string]string  // Map for filename -> location
	Metamap    map[string]string  // location of the metamap
	Filekey    map[string][]byte  // Hex string for filekey
	// FileIV     map[string][]byte  // Store file IVs
	SHA string // hex string for SHA of above data (see GenerateUserHash)
}
type File struct {
	Symmetric_key []byte // Symmetric key (also IV) for encrypting the corresponding contents
	First         string
	Last          string
	// FirstIV       []byte
	// LastIV        []byte
	FirstHMACKey []byte
	LastHMACKey  []byte
	// Locations     []string // locations at which these segments of file would be stored
	// // Hash_locations []string // hash of location_data for integrity check
	// Filehamckeys [][]byte // byte of hmac keys of the content
	// FileDataIV   [][]byte // File Data IVs
	// Datasigns    [][]byte // Hmac sign of the corresponding content H(k,E(data))
	// SHA            string   // hex string for SHA of above data
}
type File_data struct {
	Next string
	// NextIV      []byte
	NextHMACKey []byte
	DataAddr    string
	Sign        []byte
	DataSign    []byte
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

func ReloadUser(userdata User) *User {

	mys := toSHAString(userdata.Username)
	mybytes, valid := userlib.DatastoreGet(mys)
	// Return error if user not found
	if !valid {
		// err := errors.New("[GetUser] DataStore corrupted or user not found")
		return nil
	}

	if len(mybytes) < aesBlockSize {
		// err := errors.New("Data store corrupted")
		return nil
	}
	myciphertext := AESDecrypt(mybytes, userdata.Argon_pass)

	// Unmarshal into User structure
	// start := time.Now()

	var myuserdata User
	err := json.Unmarshal(myciphertext, &myuserdata)

	// end := time.Now()
	// userlib.DebugMsg("Reload time: %d", (end.Sub(start)).Nanoseconds())
	if err != nil {
		userlib.DebugMsg("[get user] error in unmarshal ", err)
		return nil
	}

	return &myuserdata
}

func AESEncrypt(bytes []byte, key []byte) []byte {
	ciphertext := make([]byte, aesBlockSize+len(bytes))
	iv := userlib.RandomBytes(aesBlockSize)
	copy(ciphertext[:aesBlockSize], iv)
	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(ciphertext[aesBlockSize:], bytes)
	return ciphertext
}

func AESDecrypt(bytes []byte, key []byte) []byte {
	ciphertext := make([]byte, len(bytes))
	iv := bytes[:aesBlockSize]
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
	return &userdata, nil
}

func toCheckMAC(filedata File_data) []byte {
	var myfiledata File_data
	myfiledata.DataAddr = filedata.DataAddr
	myfiledata.Next = filedata.Next
	myfiledata.NextHMACKey = filedata.NextHMACKey
	myfiledata.DataSign = filedata.DataSign
	bytes, _ := json.Marshal(myfiledata)
	return bytes
}

func storeFiledata(data []byte, aeskey []byte, addressKey string, iv []byte, HMACkey []byte) {

	var filedata File_data

	filedata.DataAddr = toSHAString(string(userlib.RandomBytes(aesBlockSize)))

	mac2 := userlib.NewHMAC(HMACkey)
	mac2.Write(data)
	maca2 := mac2.Sum(nil)
	filedata.DataSign = maca2

	mac := userlib.NewHMAC(HMACkey)
	mac.Write(toCheckMAC(filedata))
	maca := mac.Sum(nil)

	filedata.Sign = maca
	// Now we need to encrypt it

	bytes, _ := json.Marshal(filedata)
	ciphertext := AESEncrypt(bytes, aeskey)
	ciphertext2 := AESEncrypt(data, aeskey)
	// Now set it to the datastore

	userlib.DatastoreSet(addressKey, ciphertext)
	userlib.DatastoreSet(filedata.DataAddr, ciphertext2)
	return
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	// userdata, _ = GetUser(userdata.Username, userdata.Password)
	// Reload user
	*userdata = *ReloadUser(*userdata)
	if userdata == nil {
		// err2 := errors.New("aPPEND ERROR")
		return
	}

	// generate all required contents first : IV(K_sym),'key' where to store this struct
	Ksym := userlib.RandomBytes(aesBlockSize) //bytes of AES key for the File struct
	aeskey := userlib.RandomBytes(aesBlockSize)
	firstHMACKey := userlib.RandomBytes(aesBlockSize) // Hmac key for first block
	firstIV := userlib.RandomBytes(aesBlockSize)      // Hmac key for content

	var effective_filename = userdata.Username + "_" + filename
	var effective_filename2 = effective_filename + "_" + string(0)
	var meta_filename = "meta" + "__" + effective_filename
	addresskey := toSHAString(effective_filename)   // file struct
	addresskey2 := toSHAString(effective_filename2) // first content
	addresskey3 := toSHAString(meta_filename)       // meta
	if userdata.Filemap[filename] != "" {
		addresskey = userdata.Filemap[filename]
		Ksym = userdata.Filekey[filename]
		addresskey3 = userdata.Metamap[filename]
	}

	// here first file data would be stored
	// addresskey2 would be stored in locations []
	// store the file content where it is supposed to be

	storeFiledata(data, aeskey, addresskey2, firstIV, firstHMACKey)
	// databytes, _ := userlib.DatastoreGet(addresskey2)

	// now set all the fileds in the structure

	var filedata File
	filedata.Symmetric_key = aeskey
	filedata.First = addresskey2
	filedata.FirstHMACKey = firstHMACKey
	filedata.Last = addresskey2
	filedata.LastHMACKey = firstHMACKey

	// now encrypt it using Ksym

	var metadata Meta

	filebytes, _ := json.Marshal(filedata)
	fileciphertext := AESEncrypt(filebytes, Ksym)

	// find the sign with username as the key

	mac := userlib.NewHMAC(Ksym) // HMAC same as symmetric
	mac.Write(fileciphertext)
	maca := mac.Sum(nil)
	metadata.Filesign = maca

	// userlib.DebugMsg("store File : %x", maca) // add this to user struct

	metabytes, _ := json.Marshal(metadata)
	metaciphertext := AESEncrypt(metabytes, Ksym)

	// Now we need to set map in user struct and Sign of file
	userdata.Filemap[filename] = addresskey
	userdata.Filekey[filename] = Ksym
	userdata.Metamap[filename] = addresskey3

	// remodify the userdata hash ===== importtant
	userdata.SHA = toUserHash(*userdata)

	// re-enter the user struct in data store because has has been changed
	s := toSHAString(userdata.Username)
	bytes, _ := json.Marshal(userdata)
	ciphertext := AESEncrypt(bytes, userdata.Argon_pass)

	// place on the data store
	userlib.DatastoreSet(s, ciphertext)
	userlib.DatastoreSet(addresskey, fileciphertext)
	userlib.DatastoreSet(addresskey3, metaciphertext)
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// start := time.Now()
	// Reload user

	// start := time.Now()
	userdata = ReloadUser(*userdata)
	if userdata == nil {
		err2 := errors.New("aPPEND ERROR")
		return err2
	}
	// ================================================================

	// load file struct and check integrity
	addressKey := userdata.Filemap[filename]
	Ksym := userdata.Filekey[filename]
	bytes, valid := userlib.DatastoreGet(addressKey)

	// userlib.DebugMsg("Hello")
	if !valid {
		err := errors.New("[LoadFile] DataStore corrupted or File not found")
		return err
	}

	mac := userlib.NewHMAC(Ksym) // key is the bytes of the username itself
	mac.Write(bytes)
	maca := mac.Sum(nil)

	// Check integrity of file struct
	metacipher, _ := userlib.DatastoreGet(userdata.Metamap[filename])
	metabytes := AESDecrypt(metacipher, Ksym)
	var metadata Meta
	_ = json.Unmarshal(metabytes, &metadata)

	if userlib.Equal([]byte(maca), metadata.Filesign) != true {
		err := errors.New("[Append File] File tampered2")
		return err
	}

	// Decrypt using Ksym as key and unmarshal it into file struct
	if len(bytes) < aesBlockSize {
		err = errors.New("Data store corrupted")
		return err
	}

	ciphertext := AESDecrypt(bytes, Ksym)
	var file File

	// then := time.Now()
	err = json.Unmarshal(ciphertext, &file)
	// now := time.Now()
	// userlib.DebugMsg("Time taken unarshal: %d", (now.Sub(then)).Nanoseconds())
	if err != nil {
		userlib.DebugMsg("[append file] error in unmarshal ", err)
		return err
	}

	// Load last block and unmarshal it with checking integrity
	var last File_data
	lastcipher, _ := userlib.DatastoreGet(file.Last)
	lastbytes := AESDecrypt(lastcipher, file.Symmetric_key)

	// then = time.Now()
	_ = json.Unmarshal(lastbytes, &last)

	// now = time.Now()
	// userlib.DebugMsg("Time taken unarshal: %d", (now.Sub(then)).Nanoseconds())

	// Check integrity of file struct
	mac = userlib.NewHMAC(file.LastHMACKey)
	lastmacbytes := toCheckMAC(last)
	mac.Write(lastmacbytes)
	maca = mac.Sum(nil)

	if userlib.Equal([]byte(maca), last.Sign) != true {
		err := errors.New("[LoadFile] File tampered2")
		return err
	}

	// Generate data for new block
	next := toSHAString(string(userlib.RandomBytes(aesBlockSize)))
	nextIV := userlib.RandomBytes(aesBlockSize) // Hmac key for content
	nextHMACKey := userlib.RandomBytes(aesBlockSize)

	storeFiledata(data, file.Symmetric_key, next, nextIV, nextHMACKey)

	lastAddr := file.Last
	lastHMACkey := file.LastHMACKey

	file.Last = next
	file.LastHMACKey = nextHMACKey

	last.Next = next
	last.NextHMACKey = nextHMACKey
	mac = userlib.NewHMAC(lastHMACkey)
	mac.Write(toCheckMAC(last))
	maca = mac.Sum(nil)
	last.Sign = maca

	// put back file in the data store

	filebytes, _ := json.Marshal(file)
	fileciphertext := AESEncrypt(filebytes, Ksym)

	var metadata2 Meta
	// now update the Hmac sign in the meta struct
	mac = userlib.NewHMAC(Ksym)
	mac.Write(fileciphertext)
	maca = mac.Sum(nil)
	metadata2.Filesign = maca

	metabytes2, _ := json.Marshal(metadata2)
	metaciphertext2 := AESEncrypt(metabytes2, Ksym)

	lastbytes, _ = json.Marshal(last)
	lastcipher = AESEncrypt(lastbytes, file.Symmetric_key)

	// place on the data store
	userlib.DatastoreSet(addressKey, fileciphertext)
	userlib.DatastoreSet(userdata.Metamap[filename], metaciphertext2)
	userlib.DatastoreSet(lastAddr, lastcipher)

	// end := time.Now()
	// userlib.DebugMsg("Time taken inner: %d", (end.Sub(start)).Nanoseconds())
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	// Reload user
	*userdata = *ReloadUser(*userdata)
	if userdata == nil {
		return
	}

	// get address of the corresponding File struct
	addresskey := userdata.Filemap[filename] // get string of the address
	Ksym := userdata.Filekey[filename]       // get Symmetric Key for decryption
	// Ksym := ([]byte(KsymString))
	bytes, valid := userlib.DatastoreGet(addresskey)

	if !valid {
		err := errors.New("[Load file] not found or corrupted")
		return nil, err
	}

	metabytes, valid := userlib.DatastoreGet(userdata.Metamap[filename])
	if len(metabytes) < aesBlockSize {
		err = errors.New("Data store corrupted")
		return nil, err
	}
	metaciphertext := AESDecrypt(metabytes, Ksym)
	var metadata Meta
	_ = json.Unmarshal(metaciphertext, &metadata)

	mac := userlib.NewHMAC(Ksym) // key is the bytes of the username itself
	mac.Write(bytes)
	maca := mac.Sum(nil)

	if userlib.Equal([]byte(maca), []byte(metadata.Filesign)) != true {
		err := errors.New("[LoadFile] File tampered2")
		return nil, err
	}

	// Return error if File not found
	if !valid {
		err := errors.New("[LoadFile] DataStore corrupted or File not found")
		return nil, err
	}

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
	// Now the File data has been verified to be untampered, iterate over all locations
	element := file.First
	dataHMACkey := file.FirstHMACKey
	// userlib.DebugMsg("[Load	File] File: %v", file)

	var content = ""
	for {
		databytes, datavalid := userlib.DatastoreGet(element)
		if !datavalid {
			err := errors.New("[LoadFile] DataStore corrupted or filedata not found")
			return nil, err
		}

		if len(databytes) < aesBlockSize {
			err = errors.New("Data store corrupted")
			return nil, err
		}
		userlib.DebugMsg("[Load] databytes:%v || key: %v || dataIV: %v:", databytes, file.Symmetric_key)
		ciphertext := AESDecrypt(databytes, file.Symmetric_key)
		var filedata File_data
		err = json.Unmarshal(ciphertext, &filedata)
		if err != nil {
			userlib.DebugMsg("[load file] error in unmarshal in loop", err)
			return nil, err
		}

		// data bytes is encrypted bytes, check its integrity now using HMAC
		datamac := userlib.NewHMAC(dataHMACkey)
		datamac.Write(toCheckMAC(filedata))
		datamaca := datamac.Sum(nil)

		if userlib.Equal(datamaca, filedata.Sign) != true {
			err := errors.New("[LoadFile] content tampered")
			return nil, err
		}

		realdatabytes, realdatavalid := userlib.DatastoreGet(filedata.DataAddr)
		if !realdatavalid {
			err = errors.New("[LoadFile] DataStore corrupted or filedata not found")
			return nil, err
		}
		if len(realdatabytes) < aesBlockSize {
			err = errors.New("Data store corrupted")
			return nil, err
		}

		realtext := AESDecrypt(realdatabytes, file.Symmetric_key)
		// data bytes is encrypted bytes, check its integrity now using HMAC
		realdatamac := userlib.NewHMAC(dataHMACkey)
		realdatamac.Write(realtext)
		realdatamaca := realdatamac.Sum(nil)

		if userlib.Equal(realdatamaca, filedata.DataSign) != true {
			err := errors.New("[LoadFile] content tampered")
			return nil, err
		}

		dataString := string(realtext)
		// userlib.DebugMsg("")

		content += dataString
		if element == file.Last {
			break
		}

		element = filedata.Next
		dataHMACkey = filedata.NextHMACKey
	}
	data = ([]byte(content))

	// end := time.Now()
	// userlib.DebugMsg("Time taken for load: %d", (end.Sub(start)).Nanoseconds())
	return data, err
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	Addresskey    string // Key of file in datastore
	Symmetric_key []byte // Symmetric Key of file
	Metadatakey   string // get the file sign as well to check if he recieved the correct file
	FileIV        []byte // File IV
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
	// userdata, _ = GetUser(userdata.Username, userdata.Password)
	// Reload user
	*userdata = *ReloadUser(*userdata)
	if userdata == nil {
		return
	}

	var record sharingRecord
	// Fill up record
	record.Addresskey = userdata.Filemap[filename]
	record.Symmetric_key = userdata.Filekey[filename]
	record.Metadatakey = userdata.Metamap[filename]

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
	recordreq.Metadatakey = record.Metadatakey
	recordreq.FileIV = record.FileIV
	bytes, _ := json.Marshal(recordreq)
	return bytes
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	// userdata, _ = GetUser(userdata.Username, userdata.Password)
	// Reload user
	*userdata = *ReloadUser(*userdata)
	if userdata == nil {
		err2 := errors.New("aPPEND ERROR")
		return err2
	}
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
	*userdata = *ReloadUser(*userdata)

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

	filebytes, _ := json.Marshal(file)
	fileciphertext := AESEncrypt(filebytes, Ksymnew)
	userlib.DatastoreSet(file_addr, fileciphertext)

	mac := userlib.NewHMAC(Ksymnew)
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
