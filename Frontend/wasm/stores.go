package main

import (
	"github.com/crossle/libsignal-protocol-go/keys/identity"
	"github.com/crossle/libsignal-protocol-go/protocol"
	"github.com/crossle/libsignal-protocol-go/state/record"
)

type InMemorySessionStore struct {
	sessions map[string]*record.Session
}

func NewInMemorySessionStore() *InMemorySessionStore {
	return &InMemorySessionStore{
		sessions: make(map[string]*record.Session),
	}
}

func (s *InMemorySessionStore) LoadSession(address *protocol.SignalAddress) *record.Session {
	if session, ok := s.sessions[address.String()]; ok {
		return session
	}
	return record.NewSession(serializer.Session, serializer.State)
}

func (s *InMemorySessionStore) GetSubDeviceSessions(name string) []uint32 {
	return []uint32{}
}

func (s *InMemorySessionStore) StoreSession(remoteAddress *protocol.SignalAddress, record *record.Session) {
	s.sessions[remoteAddress.String()] = record
}

func (s *InMemorySessionStore) ContainsSession(remoteAddress *protocol.SignalAddress) bool {
	_, exists := s.sessions[remoteAddress.String()]
	return exists
}

func (s *InMemorySessionStore) DeleteSession(remoteAddress *protocol.SignalAddress) {
	delete(s.sessions, remoteAddress.String())
}

func (s *InMemorySessionStore) DeleteAllSessions() {
	s.sessions = make(map[string]*record.Session)
}

type InMemoryPreKeyStore struct {
	store map[uint32]*record.PreKey
}

func NewInMemoryPreKeyStore() *InMemoryPreKeyStore {
	return &InMemoryPreKeyStore{
		store: make(map[uint32]*record.PreKey),
	}
}

func (s *InMemoryPreKeyStore) LoadPreKey(preKeyID uint32) *record.PreKey {
	return s.store[preKeyID]
}

func (s *InMemoryPreKeyStore) StorePreKey(preKeyID uint32, preKeyRecord *record.PreKey) {
	s.store[preKeyID] = preKeyRecord
}

func (s *InMemoryPreKeyStore) ContainsPreKey(preKeyID uint32) bool {
	_, exists := s.store[preKeyID]
	return exists
}

func (s *InMemoryPreKeyStore) RemovePreKey(preKeyID uint32) {
	delete(s.store, preKeyID)
}

type InMemorySignedPreKeyStore struct {
	store map[uint32]*record.SignedPreKey
}

func NewInMemorySignedPreKeyStore() *InMemorySignedPreKeyStore {
	return &InMemorySignedPreKeyStore{
		store: make(map[uint32]*record.SignedPreKey),
	}
}

func (s *InMemorySignedPreKeyStore) LoadSignedPreKey(signedPreKeyID uint32) *record.SignedPreKey {
	return s.store[signedPreKeyID]
}

func (s *InMemorySignedPreKeyStore) LoadSignedPreKeys() []*record.SignedPreKey {
	var keys []*record.SignedPreKey
	for _, key := range s.store {
		keys = append(keys, key)
	}
	return keys
}

func (s *InMemorySignedPreKeyStore) StoreSignedPreKey(signedPreKeyID uint32, record *record.SignedPreKey) {
	s.store[signedPreKeyID] = record
}

func (s *InMemorySignedPreKeyStore) ContainsSignedPreKey(signedPreKeyID uint32) bool {
	_, exists := s.store[signedPreKeyID]
	return exists
}

func (s *InMemorySignedPreKeyStore) RemoveSignedPreKey(signedPreKeyID uint32) {
	delete(s.store, signedPreKeyID)
}

type InMemoryIdentityKeyStore struct {
	trustedKeys         map[string]*identity.Key
	identityKeyPair     *identity.KeyPair
	localRegistrationID uint32
}

func NewInMemoryIdentityKeyStore(identityKey *identity.KeyPair, localRegistrationID uint32) *InMemoryIdentityKeyStore {
	return &InMemoryIdentityKeyStore{
		trustedKeys:         make(map[string]*identity.Key),
		identityKeyPair:     identityKey,
		localRegistrationID: localRegistrationID,
	}
}

func (s *InMemoryIdentityKeyStore) GetIdentityKeyPair() *identity.KeyPair {
	return s.identityKeyPair
}

func (s *InMemoryIdentityKeyStore) GetLocalRegistrationId() uint32 {
	return s.localRegistrationID
}

func (s *InMemoryIdentityKeyStore) SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) {
	s.trustedKeys[address.String()] = identityKey
}

func (s *InMemoryIdentityKeyStore) IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key) bool {
	trusted, exists := s.trustedKeys[address.String()]
	return !exists || trusted.Fingerprint() == identityKey.Fingerprint()
}