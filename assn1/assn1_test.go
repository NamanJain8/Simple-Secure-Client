// // package assn1

// // import "testing"
// // import "reflect"

// // You can actually import other stuff if you want IN YOUR TEST
// // HARNESS ONLY.  Note that this is NOT considered part of your
// // solution, but is how you make sure your solution is correct.

// func TestInit(t *testing.T) {
// 	t.Log("Initialization test")
// 	// userlib.DebugPrint = true
// 	//	someUsefulThings()

// 	// userlib.DebugPrint = false
// 	u, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		// t.Error says the test fails
// 		t.Error("Failed to initialize user", err)
// 	}
// 	// t.Log() only produces output if you run with "go test -v"
// 	t.Log("Got user", u)
// 	// You probably want many more tests here.
// }

// // func TestSome(t *testing.T){
// // 	t.Log("Something test")
// // 	userlib.DebugPrint = true
// // 	someUsefulThings()
// // 	// if err != nil {
// // 	// 	// t.Error says the test fails
// // 	// 	t.Error("Failed to initialize user", err)
// // 	// }
// // 	// t.Log("Got user", u)
// // }

// func TestStorage(t *testing.T) {
// 	// And some more tests, because
// 	u, err := GetUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to reload user", err)
// 		return
// 	}
// 	// userlib.DebugPrint = true
// 	t.Log("Loaded user", u)

// 	v := []byte("This is a test")
// 	u.StoreFile("file1", v)

// 	v2, err2 := u.LoadFile("file1")
// 	if err2 != nil {
// 		t.Error("Failed to upload and download", err2)
// 	}

// 	t.Log("file1: ", v)
// 	t.Log("file2: ", v2)
// 	if !reflect.DeepEqual(v, v2) {
// 		t.Error("Downloaded file is not the same", v, v2)
// 	}

// 	// v3 := []byte("This is a testyyyy")
// 	// u.StoreFile("file22", v3)
// 	// v2, err2 = u.LoadFile("file1")
// 	// if err2 != nil {
// 	// 	t.Error("Failed to upload and download", err2)
// 	// }

// 	// t.Log("file1: " , v)
// 	// t.Log("file2: " , v2)
// 	// if !reflect.DeepEqual(v, v2) {
// 	// 	t.Error("Downloaded file is not the same", v, v2)
// 	// }

// }

// func TestShare(t *testing.T) {
// 	// userlib.DebugPrint = true

// 	u, err := GetUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to reload user", err)
// 	}

// 	u2, err2 := InitUser("bob", "foobar")
// 	if err2 != nil {
// 		t.Error("Failed to initialize bob", err2)
// 	}

// 	//
// 	// v5 := []byte("This is a test")
// 	// u.StoreFile("file1", v5)

// 	//

// 	var v, v2 []byte
// 	var msgid string

// 	v, err = u.LoadFile("file1")
// 	if err != nil {
// 		t.Error("Failed to download the file from alice", err)
// 	}

// 	msgid, err = u.ShareFile("file1", "bob")
// 	if err != nil {
// 		t.Error("Failed to share the a file", err)
// 	}
// 	t.Log("please")
// 	t.Log(msgid)
// 	err = u2.ReceiveFile("file2", "alice", msgid)
// 	if err != nil {
// 		t.Error("Failed to receive the share message", err)
// 	}

// 	v2, err = u2.LoadFile("file2")
// 	if err != nil {
// 		t.Error("Failed to download the file after sharing", err)
// 	}
// 	if !reflect.DeepEqual(v, v2) {
// 		t.Error("Shared file is not the same", v, v2)
// 	}

// }

// func TestAppend(t *testing.T) {
// 	// userlib.DebugPrint = true
// 	u, err := GetUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to reload user", err)
// 	}
// 	v := []byte("Appended here")
// 	err = u.AppendFile("file1", v)
// 	v = []byte("Appended here again")
// 	err = u.AppendFile("file1", v)
// 	v2, err := u.LoadFile("file1")
// 	t.Log(" Content : ", string(v2))
// }

// func TestRevoke(t *testing.T) {
// 	// userlib.DebugPrint = true

// 	u, err := GetUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to reload user", err)
// 	}

// 	err = u.RevokeFile("file1")
// 	if err != nil {
// 		t.Log("Error in revoke")
// 	}

// 	u2, err2 := GetUser("bob", "foobar")
// 	if err2 != nil {
// 		t.Error("Failed to reload user", err)
// 	}

// 	_, err3 := u2.LoadFile("file2")
// 	if err3 == nil {
// 		t.Error("Not revoked", err)
// 	}
// 	// if !reflect.DeepEqual(v, v2) {
// 	// 	t.Error("Shared file is not the same", v, v2)
// 	// }

// }
package assn1

import (
	"testing"

	"github.com/fenilfadadu/CS628-assn1/userlib"
)

// // You can actually import other stuff if you want IN YOUR TEST
// // HARNESS ONLY.  Note that this is NOT considered part of your
// // solution, but is how you make sure your solution is correct.

// func TestInit(t *testing.T) {
// 	t.Log("Initialization test")
// 	userlib.DebugPrint = true
// 	//	someUsefulThings()

// 	userlib.DebugPrint = false
// 	u, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		// t.Error says the test fails
// 		t.Error("Failed to initialize user", err)
// 	}
// 	// t.Log() only produces output if you run with "go test -v"
// 	t.Log("Got user", u)
// 	// You probably want many more tests here.
// }

// func TestStorage(t *testing.T) {
// 	// And some more tests, because
// 	u, err := GetUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to reload user", err)
// 		return
// 	}
// 	t.Log("Loaded user", u)

// 	v := []byte("This is a test")
// 	u.StoreFile("file1", v)

// 	v2, err2 := u.LoadFile("file1")
// 	if err2 != nil {
// 		t.Error("Failed to upload and download", err2)
// 	}
// 	if !reflect.DeepEqual(v, v2) {
// 		t.Error("Downloaded file is not the same", v, v2)
// 	}
// 	v = []byte("This is a test again")
// 	u.StoreFile("file1", v)
// 	v2, err2 = u.LoadFile("file1")
// 	t.Log("again loaded file s : ", string(v2))
// }
// func TestAppend(t *testing.T) {
// 	userlib.DebugPrint = true
// 	u1, err := GetUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to reload user", err)
// 	}
// 	u2, err2 := InitUser("bob", "foobar")
// 	if err2 != nil {
// 		t.Error("Failed to initialize bob", err2)
// 	}
// 	t.Log("Loaded user", u1)

// 	v := []byte("This is a test")
// 	u1.AppendFile("file1", v)
// 	v, _ = u1.LoadFile("file1")

// 	t.Log(string(v))

// 	sharing, _ := u1.ShareFile("file1", "bob")
// 	u2.ReceiveFile("file2", "alice", sharing)
// 	u2.StoreFile("file2", []byte("changes"))
// 	u2.AppendFile("file2", []byte("again"))

// 	t.Log(string(v))
// 	v, err = u1.LoadFile("file1")
// 	if err != nil {
// 		t.Log(err)
// 	}
// 	t.Log(string(v))
// 	// bytes, _ := userlib.DatastoreGet(toSHAString("alice_file1"))
// 	// bytes[0] = 0
// 	// t.Log(bytes)
// 	// userlib.DatastoreSet(toSHAString("alice_file1"), bytes)
// 	// v, err = u1.LoadFile("file1")
// 	// if err != nil {
// 	// 	t.Log(err)
// 	// }

// }

// // func TestShare(t *testing.T) {
// // 	u, err := GetUser("alice", "fubar")
// // 	if err != nil {
// // 		t.Error("Failed to reload user", err)
// // 	}
// // 	u2, err2 := InitUser("bob", "foobar")
// // 	if err2 != nil {
// // 		t.Error("Failed to initialize bob", err2)
// // 	}

// // 	var v, v2 []byte
// // 	var msgid string

// // 	v, err = u.LoadFile("file1")
// // 	if err != nil {
// // 		t.Error("Failed to download the file from alice", err)
// // 	}
// // 	t.Log("Loaded info:", string(v))

// // 	msgid, err = u.ShareFile("file1", "bob")
// // 	if err != nil {
// // 		t.Error("Failed to share the a file", err)
// // 	}
// // 	err = u2.ReceiveFile("file2", "alice", msgid)
// // 	if err != nil {
// // 		t.Error("Failed to receive the share message", err)
// // 	}

// // 	v2, err = u2.LoadFile("file2")
// // 	if err != nil {
// // 		t.Error("Failed to download the file after sharing", err)
// // 	}
// // 	if !reflect.DeepEqual(v, v2) {
// // 		t.Error("Shared file is not the same", v, v2)
// // 	}

// // }

// // // func TestUserCorrupt(t *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	t.Log(user1, user2)

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // }

// // func TestStoreFile(t *testing.T) {
// // 	u, err := GetUser("alice", "fubar")
// // 	if err != nil {
// // 		t.Error("Failed to reload user", err)
// // 		return
// // 	}
// // 	t.Log("Loaded user", u)

// // 	v2, err2 := u.LoadFile("file1")
// // 	if err2 != nil {
// // 		t.Error("Failed to upload and download", err2)
// // 	}

// // 	t.Log("File received: ", string(v2))

// // }

// // func TestShareMutate(t *testingt *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	t.Log(user1, user2)

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // }T) {
// // 	u, err := GetUser("alice", t *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	t.Log(user1, user2)

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // }fubar")
// // 	if err != nil {
// // 		t.Error("Failed to relot *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	t.Log(user1, user2)

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // }d alice", err)
// // 	}
// // 	u2, err2 := GetUser("bob", t *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	t.Log(user1, user2)

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // }foobar")
// // 	if err2 != nil {
// // 		t.Error("Failed to relot *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	t.Log(user1, user2)

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // }d bob", err2)
// // 	}

// // 	// Bob's version of sharedft *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	t.Log(user1, user2)

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // }le
// // 	t.Log("Just before")
// // 	v2, err := u2.LoadFile("filt *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	t.Log(user1, user2)

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // }2")
// // 	if err != nil {
// // 		t.Error("Failed to downt *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Errot *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	t.Log(user1, user2)

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // }r())
// // // 	}t *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	t.Log(user1, user2)

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // }
// // t *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	t.Log(user1, user2)

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // }
// // // 	t.Log(user1, user2)t *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	t.Log(user1, user2)

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // }

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // }oad the file after sharing", err)
// // 	}

// // 	t.Log("The content of file t *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	t.Log(user1, user2)

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // }s : ", string(v2))

// // 	// Bob rewrites the shared-t *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	t.Log(user1, user2)

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // }ile
// // 	newCont := []byte("This is t *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	t.Log(user1, user2)

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // }EW content")
// // 	u2.StoreFile("file2", newCot *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	t.Log(user1, user2)

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // }t)
// // 	// Alice loads the same filt *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	t.Log(user1, user2)

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // } (expect the test to currently fail)
// // 	v1, err := u.LoadFile("filet *testing.T) {
// // // 	// InitUser
// // // 	user1, err := InitUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	user2, err := InitUser("ashish", "password2")
// // // 	if err != nil {
// // // 		t.Error(err.Error())
// // // 	}

// // // 	t.Log(user1, user2)

// // // 	// GetUser (Try to ruin user data)
// // // 	aniketKey := GetUserKey("aniket", "password1")
// // // 	aniketCnt, _ := GetMapContent(aniketKey)
// // // 	// fmt.Println(aniketCnt)
// // // 	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
// // // 	SetMapContent(aniketKey, aniketCnt)

// // // 	// Here, we intentionally want the unmarshalling to fail
// // // 	user1, err = GetUser("aniket", "password1")
// // // 	if err != nil {
// // // 		t.Log(err.Error())
// // // 	} else {
// // // 		t.Error(user1)
// // // 	}
// // // }")

// // 	if err != nil {
// // 		t.Error(err.Error())
// // 	}
// // 	t.Log("The new content of file is : ", string(v1))
// // 	if string(newCont) != string(v1) {
// // 		t.Error("The file contents don't match")
// // 	}

// // 	t.Log("The contents match: ", string(newCont))

// // 	newCont = []byte("This is NEW content")
// // 	u2.AppendFile("file2", newCont)
// // 	// Alice loads the same file (expect the test to currently fail)
// // 	v1, err = u.LoadFile("file1")
// // 	v4, _ := u2.LoadFile("file2")
// // 	if err != nil {
// // 		t.Error(err.Error())
// // 	}
// // 	t.Log("The new content of file is : ", string(v1))
// // 	if string(v4) != string(v1) {
// // 		t.Error("The file contents don't match")
// // 	}

// // 	t.Log("The contents match: ", string(newCont))
// // 	userlib.DebugPrint = true
// // 	err = u.RevokeFile("file1")
// // 	u, err = GetUser("alice", "fubar")
// // 	if err != nil {
// // 		t.Error("Failed to reload alice", err)
// // 	}

// // 	v1, err = u2.LoadFile("file2")
// // 	if err == nil {
// // 		t.Log("ERROR ")
// // 	}
// // 	v1, err = u.LoadFile("file1")
// // 	if err != nil {
// // 		// t.Error(err.Error())
// // 		t.Log("Error")
// // 	}
// // 	t.Log("U1 file1 contents :", string(v1))

// // }

// // func TestRevokeTransitive(t *testing.T) {
// // 	userlib.DebugPrint = true
// // 	t.Log("Reached here")
// // 	u1, _ := GetUser("alice", "fubar")
// // 	u2, _ := GetUser("bob", "foobar")
// // 	u3, _ := InitUser("adam", "fuobar")

// // 	u1.StoreFile("file11", []byte("This belongs to Alice"))
// // 	u1.AppendFile("file11", []byte("appended"))

// // 	sharing, _ := u1.ShareFile("file11", "bob")
// // 	u2.ReceiveFile("file22", "alice", sharing)

// // 	sharing, _ = u2.ShareFile("file22", "adam")
// // 	u3.ReceiveFile("file33", "bob", sharing)

// // 	v := []byte("adam overwrites the file22")
// // 	u3.StoreFile("file33", v)
// // 	u3.AppendFile("file33", v)

// // 	v33, _ := u3.LoadFile("file33")
// // 	v22, err := u2.LoadFile("file22")
// // 	v11, _ := u1.LoadFile("file11")
// // 	if err != nil {
// // 		t.Error("Failed to load file ", err)
// // 	}
// // 	t.Log("File at adam : ", string(v33))
// // 	t.Log("File at bob : ", string(v22))
// // 	t.Log("File at alice : ", string(v11))

// // 	v = []byte("adam has modified the file11")
// // 	u1.StoreFile("file11", v)

// // 	v33, _ = u3.LoadFile("file33")
// // 	v22, _ = u2.LoadFile("file22")
// // 	v11, _ = u1.LoadFile("file11")
// // 	t.Log("File at adam : ", string(v33))
// // 	t.Log("File at bob : ", string(v22))
// // 	t.Log("File at alice : ", string(v11))

// // 	u2.RevokeFile("file22")
// // 	v22, _ = u2.LoadFile("file22")
// // 	t.Log("File at bob : ", string(v22))
// // 	u1.AppendFile("file11", []byte("tried")) // this is not appending .. as expected
// // 	// share again
// // 	sharing, _ = u1.ShareFile("file11", "bob")
// // 	u2.ReceiveFile("file22", "alice", sharing)
// // 	v33, _ = u3.LoadFile("file33")
// // 	v22, _ = u2.LoadFile("file22")
// // 	v11, _ = u1.LoadFile("file11")
// // 	t.Log("File at adam : ", string(v33))
// // 	t.Log("File at bob : ", string(v22))
// // 	t.Log("File at alice : ", string(v11))
// // }
// // func TestMutate(t *testing.T) {
// // 	// userlib.DebugPrint = true
// // 	u2, _ := GetUser("bob", "foobar")
// // 	u1, _ := GetUser("alice", "fubar")
// // 	u1.StoreFile("file11", []byte("AAAAAAAAAAAAa"))
// // 	u1.AppendFile("file11", []byte("BBBB"))
// // 	u1.AppendFile("file11", []byte("BBBBcc"))
// // 	u1.AppendFile("file11", []byte("BBBBdd"))
// // 	v, err := u1.LoadFile("file11")
// // 	if err != nil {
// // 		t.Log(err)
// // 	}
// // 	t.Log("Final file :", string(v))
// // 	sharing, _ := u1.ShareFile("file11", "bob")
// // 	u2.ReceiveFile("file22", "alice", sharing)

// // 	u2.StoreFile("file22", []byte("updated"))
// // 	v, err = u1.LoadFile("file11")
// // 	if err != nil {
// // 		t.Log(err)
// // 	}
// // 	v11, _ := u2.LoadFile("file22")
// // 	t.Log("File at bob : ", string(v11))

// // }

func TestMultiUser(t *testing.T) {
	userlib.KeystoreClear()
	userlib.DatastoreClear()
	userlib.DebugPrint = true
	_, _ = InitUser("alice", "fubar")
	// t.Log("user: ", u)
	u1, _ := GetUser("alice", "fubar")
	u2, _ := GetUser("alice", "fubar")
	text := []byte("hello world")
	u1.StoreFile("myfile", text)
	// u2, _ = GetUser("alice", "fubar")
	v, err := u2.LoadFile("myfile")
	if err != nil {
		t.Log(err)
	}
	for i := 0; i < 10; i++ {
		// now := time.Now()
		err = u2.AppendFile("myfile", []byte("Helloo again"))
		if err != nil {
			t.Log("Append error")
		}
		// end := time.Now()
		// t.Log("Time taken for append:", (end.Sub(now)).Nanoseconds())
	}

	v, err = u2.LoadFile("myfile")
	if err != nil {
		t.Log(err)
	}
	// t.Log("U1:", u1)
	// t.Log("U2:", u2)

	t.Log("Contents:", string(v))
}
