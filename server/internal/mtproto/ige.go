// ige.go — AES-256-IGE поверх ECB: без внешних зависимостей и без
// зависимости от провайдеров (на Go — stdlib, на Kotlin — тот же алгоритм
// по байтам). Режим канона MTProto.
package mtproto

import (
	"crypto/aes"
	"crypto/cipher"
)

// igeCrypt — состояние IGE для одного направления.
type igeCrypt struct {
	block cipher.Block
}

func newIGE(key []byte) (*igeCrypt, error) {
	b, err := aes.NewCipher(key) // AES-256: key 32 байта
	if err != nil {
		return nil, err
	}
	return &igeCrypt{block: b}, nil
}

// encryptIGE: c_i = E(p_i ⊕ c_{i-1}) ⊕ p_{i-1}.
// iv[0:16] — инициализация c-цепочки, iv[16:32] — p-цепочки.
func (c *igeCrypt) encryptIGE(data, iv []byte) []byte {
	if len(data)%aes.BlockSize != 0 {
		return nil
	}
	x := make([]byte, aes.BlockSize) // c-цепочка
	copy(x, iv[:aes.BlockSize])
	y := make([]byte, aes.BlockSize) // p-цепочка
	copy(y, iv[aes.BlockSize:])
	out := make([]byte, len(data))
	buf := make([]byte, aes.BlockSize)
	for i := 0; i < len(data); i += aes.BlockSize {
		blk := data[i : i+aes.BlockSize]
		for j := 0; j < aes.BlockSize; j++ {
			buf[j] = blk[j] ^ x[j]
		}
		c.block.Encrypt(buf, buf)
		for j := 0; j < aes.BlockSize; j++ {
			out[i+j] = buf[j] ^ y[j]
		}
		copy(x, out[i:i+aes.BlockSize])
		copy(y, blk)
	}
	return out
}

// decryptIGE: p_i = D(c_i ⊕ p_{i-1}) ⊕ c_{i-1}.
// iv[0:16] — c-цепочка, iv[16:32] — p-цепочка (та же раскладка IV).
func (c *igeCrypt) decryptIGE(data, iv []byte) []byte {
	if len(data)%aes.BlockSize != 0 {
		return nil
	}
	x := make([]byte, aes.BlockSize) // c-цепочка (c_{i-1})
	copy(x, iv[:aes.BlockSize])
	y := make([]byte, aes.BlockSize) // p-цепочка (p_{i-1})
	copy(y, iv[aes.BlockSize:])
	out := make([]byte, len(data))
	buf := make([]byte, aes.BlockSize)
	for i := 0; i < len(data); i += aes.BlockSize {
		blk := data[i : i+aes.BlockSize]
		for j := 0; j < aes.BlockSize; j++ {
			buf[j] = blk[j] ^ y[j]
		}
		c.block.Decrypt(buf, buf)
		for j := 0; j < aes.BlockSize; j++ {
			out[i+j] = buf[j] ^ x[j]
		}
		copy(x, blk)
		copy(y, out[i:i+aes.BlockSize])
	}
	return out
}
