package wg

// kat_test.go — детерминированные хелперы межъязыкового KAT (Go ↔ Kotlin):
// фиксированные ключи/метка времени/индексы дают байт-в-байт воспроизводимые
// векторы для Kotlin-теста WgKATTest.

import (
	"golang.org/x/crypto/curve25519"
)

func curve255X(priv []byte) ([]byte, error) {
	return curve25519.X25519(priv, curve25519.Basepoint)
}

func katClientHandshake(server, clientStatic, eph *KeyPair, psk *[KeySize]byte, stamp *[StampSize]byte, sender uint32) ([]byte, *ClientHandshake, error) {
	return clientHandshakeCore(&server.Pub, *clientStatic, *eph, sender, stamp, psk)
}

func katServerHandshake(server *KeyPair, psk *[KeySize]byte, msg1 []byte, sender uint32, lastStamp *[StampSize]byte) ([]byte, *ServerHandshake, error) {
	return serverHandshakeCore(&server.Priv, &server.Pub, psk, msg1, lastStamp, sender)
}
