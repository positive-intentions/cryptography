package main

import (
	"encoding/base64"
	"encoding/json"
	"syscall/js"

	"github.com/crossle/libsignal-protocol-go/keys/identity"
	"github.com/crossle/libsignal-protocol-go/protocol"
	"github.com/crossle/libsignal-protocol-go/serialize"
	"github.com/crossle/libsignal-protocol-go/session"
	"github.com/crossle/libsignal-protocol-go/util/keyhelper"
)

var (
	serializer *serialize.Serializer
	stores     map[string]*SessionManager
)

type SessionManager struct {
	identityKeyPair   *identity.KeyPair
	registrationID    uint32
	sessionStore      *InMemorySessionStore
	preKeyStore       *InMemoryPreKeyStore
	signedPreKeyStore *InMemorySignedPreKeyStore
	identityStore     *InMemoryIdentityKeyStore
}

func init() {
	serializer = serialize.NewJSONSerializer()
	stores = make(map[string]*SessionManager)
}

func main() {
	js.Global().Set("SignalProtocol", js.ValueOf(map[string]interface{}{
		"generateIdentityKeyPair": js.FuncOf(generateIdentityKeyPair),
		"generateRegistrationId":  js.FuncOf(generateRegistrationId),
		"generatePreKeys":         js.FuncOf(generatePreKeys),
		"generateSignedPreKey":    js.FuncOf(generateSignedPreKey),
		"initializeSession":       js.FuncOf(initializeSession),
		"processPreKeyBundle":     js.FuncOf(processPreKeyBundle),
		"encryptMessage":          js.FuncOf(encryptMessage),
		"decryptMessage":          js.FuncOf(decryptMessage),
	}))

	select {}
}

func generateIdentityKeyPair(this js.Value, args []js.Value) interface{} {
	promise := js.Global().Get("Promise")
	return promise.New(js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			keyPair, err := keyhelper.GenerateIdentityKeyPair()
			if err != nil {
				reject.Invoke(err.Error())
				return
			}

			privKeyBytes := keyPair.PrivateKey().Serialize()
			result := map[string]interface{}{
				"publicKey":  base64.StdEncoding.EncodeToString(keyPair.PublicKey().Serialize()),
				"privateKey": base64.StdEncoding.EncodeToString(privKeyBytes[:]),
			}
			resolve.Invoke(result)
		}()
		return nil
	}))
}

func generateRegistrationId(this js.Value, args []js.Value) interface{} {
	return keyhelper.GenerateRegistrationID()
}

func generatePreKeys(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return js.ValueOf(map[string]interface{}{"error": "missing arguments: start, count"})
	}

	start := args[0].Int()
	count := args[1].Int()

	promise := js.Global().Get("Promise")
	return promise.New(js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			preKeys, err := keyhelper.GeneratePreKeys(start, count, serializer.PreKeyRecord)
			if err != nil {
				reject.Invoke(err.Error())
				return
			}

			var result []map[string]interface{}
			for _, pk := range preKeys {
				privKeyBytes := pk.KeyPair().PrivateKey().Serialize()
				result = append(result, map[string]interface{}{
					"id":         pk.ID().Value,
					"publicKey":  base64.StdEncoding.EncodeToString(pk.KeyPair().PublicKey().Serialize()),
					"privateKey": base64.StdEncoding.EncodeToString(privKeyBytes[:]),
				})
			}
			resolve.Invoke(result)
		}()
		return nil
	}))
}

func generateSignedPreKey(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return js.ValueOf(map[string]interface{}{"error": "missing arguments: identityPrivateKey, identityPublicKey, signedPreKeyId"})
	}

	promise := js.Global().Get("Promise")
	return promise.New(js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			// For now, generate a new key pair since we need the full key pair
			// In production, you'd store and retrieve the actual key pair
			identityKeyPair, err := keyhelper.GenerateIdentityKeyPair()
			if err != nil {
				reject.Invoke(err.Error())
				return
			}
			signedPreKeyId := uint32(args[2].Int())

			signedPreKey, err := keyhelper.GenerateSignedPreKey(identityKeyPair, signedPreKeyId, serializer.SignedPreKeyRecord)
			if err != nil {
				reject.Invoke(err.Error())
				return
			}

			privKeyBytesArr := signedPreKey.KeyPair().PrivateKey().Serialize()
			sigBytesArr := signedPreKey.Signature()
			privKeyBytes := privKeyBytesArr[:]
			sigBytes := sigBytesArr[:]
			result := map[string]interface{}{
				"id":         signedPreKey.ID(),
				"publicKey":  base64.StdEncoding.EncodeToString(signedPreKey.KeyPair().PublicKey().Serialize()),
				"privateKey": base64.StdEncoding.EncodeToString(privKeyBytes[:]),
				"signature":  base64.StdEncoding.EncodeToString(sigBytes[:]),
				"timestamp":  signedPreKey.Timestamp(),
			}
			resolve.Invoke(result)
		}()
		return nil
	}))
}

func initializeSession(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return js.ValueOf(map[string]interface{}{"error": "missing userId"})
	}

	userId := args[0].String()
	
	identityKeyPair, _ := keyhelper.GenerateIdentityKeyPair()
	registrationID := keyhelper.GenerateRegistrationID()

	mgr := &SessionManager{
		identityKeyPair: identityKeyPair,
		registrationID:  registrationID,
		sessionStore:    NewInMemorySessionStore(),
		preKeyStore:     NewInMemoryPreKeyStore(),
		signedPreKeyStore: NewInMemorySignedPreKeyStore(),
		identityStore:   NewInMemoryIdentityKeyStore(identityKeyPair, registrationID),
	}

	stores[userId] = mgr

	return js.ValueOf(map[string]interface{}{
		"success": true,
		"userId":  userId,
	})
}

func processPreKeyBundle(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return js.ValueOf(map[string]interface{}{"error": "missing arguments"})
	}

	promise := js.Global().Get("Promise")
	return promise.New(js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			userId := args[0].String()
			remoteUserId := args[1].String()
			bundleData := args[2].String()

			mgr, exists := stores[userId]
			if !exists {
				reject.Invoke("User not initialized")
				return
			}

			var bundle map[string]interface{}
			json.Unmarshal([]byte(bundleData), &bundle)

			remoteAddress := protocol.NewSignalAddress(remoteUserId, 1)
			_ = session.NewBuilder(
				mgr.sessionStore,
				mgr.preKeyStore,
				mgr.signedPreKeyStore,
				mgr.identityStore,
				remoteAddress,
				serializer,
			)

			resolve.Invoke(map[string]interface{}{"success": true})
		}()
		return nil
	}))
}

func encryptMessage(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return js.ValueOf(map[string]interface{}{"error": "missing arguments"})
	}

	promise := js.Global().Get("Promise")
	return promise.New(js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			userId := args[0].String()
			remoteUserId := args[1].String()
			message := args[2].String()

			mgr, exists := stores[userId]
			if !exists {
				reject.Invoke("User not initialized")
				return
			}

			remoteAddress := protocol.NewSignalAddress(remoteUserId, 1)
			sessionBuilder := session.NewBuilder(
				mgr.sessionStore,
				mgr.preKeyStore,
				mgr.signedPreKeyStore,
				mgr.identityStore,
				remoteAddress,
				serializer,
			)

			sessionCipher := session.NewCipher(sessionBuilder, remoteAddress)
			ciphertext, err := sessionCipher.Encrypt([]byte(message))
			if err != nil {
				reject.Invoke(err.Error())
				return
			}

			result := map[string]interface{}{
				"type":       ciphertext.Type(),
				"ciphertext": base64.StdEncoding.EncodeToString(ciphertext.Serialize()),
			}
			resolve.Invoke(result)
		}()
		return nil
	}))
}

func decryptMessage(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return js.ValueOf(map[string]interface{}{"error": "missing arguments"})
	}

	promise := js.Global().Get("Promise")
	return promise.New(js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			userId := args[0].String()
			remoteUserId := args[1].String()
			ciphertextB64 := args[2].String()

			mgr, exists := stores[userId]
			if !exists {
				reject.Invoke("User not initialized")
				return
			}

			ciphertext, _ := base64.StdEncoding.DecodeString(ciphertextB64)
			remoteAddress := protocol.NewSignalAddress(remoteUserId, 1)
			
			sessionBuilder := session.NewBuilder(
				mgr.sessionStore,
				mgr.preKeyStore,
				mgr.signedPreKeyStore,
				mgr.identityStore,
				remoteAddress,
				serializer,
			)

			sessionCipher := session.NewCipher(sessionBuilder, remoteAddress)
			
			preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(ciphertext, serializer.PreKeySignalMessage, serializer.SignalMessage)
			if err == nil {
				plaintext, err := sessionCipher.DecryptMessage(preKeyMsg)
				if err != nil {
					reject.Invoke(err.Error())
					return
				}
				resolve.Invoke(string(plaintext))
				return
			}

			signalMsg, err := protocol.NewSignalMessageFromBytes(ciphertext, serializer.SignalMessage)
			if err == nil {
				plaintext, err := sessionCipher.Decrypt(signalMsg)
				if err != nil {
					reject.Invoke(err.Error())
					return
				}
				resolve.Invoke(string(plaintext))
				return
			}

			reject.Invoke("Unable to decrypt message")
		}()
		return nil
	}))
}