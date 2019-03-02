package assn1

import "github.com/fenilfadadu/CS628-assn1/userlib"
import "testing"
import "reflect"

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	//	someUsefulThings()

	// userlib.DebugPrint = false
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// You probably want many more tests here.
}

// func TestSome(t *testing.T){
// 	t.Log("Something test")
// 	userlib.DebugPrint = true
// 	someUsefulThings()
// 	// if err != nil {
// 	// 	// t.Error says the test fails
// 	// 	t.Error("Failed to initialize user", err)
// 	// }
// 	// t.Log("Got user", u)
// }

func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	userlib.DebugPrint = true
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}

	t.Log("file1: ", v)
	t.Log("file2: ", v2)
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}

	// v3 := []byte("This is a testyyyy")
	// u.StoreFile("file22", v3)
	// v2, err2 = u.LoadFile("file1")
	// if err2 != nil {
	// 	t.Error("Failed to upload and download", err2)
	// }

	// t.Log("file1: " , v)
	// t.Log("file2: " , v2)
	// if !reflect.DeepEqual(v, v2) {
	// 	t.Error("Downloaded file is not the same", v, v2)
	// }

}

func TestShare(t *testing.T) {
	userlib.DebugPrint = true

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}

	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	//
	// v5 := []byte("This is a test")
	// u.StoreFile("file1", v5)

	//

	var v, v2 []byte
	var msgid string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}

	msgid, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	t.Log("please")
	t.Log(msgid)
	err = u2.ReceiveFile("file2", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}

}

func TestAppend(t *testing.T) {
	userlib.DebugPrint = true
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	v := []byte("Appended here")
	err = u.AppendFile("file1", v)
	v = []byte("Appended here again")
	err = u.AppendFile("file1", v)
	v2, err := u.LoadFile("file1")
	t.Log(" Content : ", string(v2))
}

func TestRevoke(t *testing.T){
	userlib.DebugPrint = true

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}

	err = u.RevokeFile("file1")
	if err!=nil {
		t.Log("Error in revoke")
	}

	u2, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to reload user", err)
	}

	_, err3 := u2.LoadFile("file2")
	if err3 == nil {
		t.Error("Not revoked", err)
	}
	// if !reflect.DeepEqual(v, v2) {
	// 	t.Error("Shared file is not the same", v, v2)
	// }

}
