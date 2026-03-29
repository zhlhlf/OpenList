package crypt2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/rclone/rclone/fs/config/obscure"
)

const (
	fileEncryptionFalse  = "false"
	fileEncryptionRclone = "rclone"
	fileEncryptionAESECB = "aes_ecb"
	fileEncryptionAESCTR = "aes_ctr"
	aesBlockSize         = aes.BlockSize
)

type aesCTR struct {
	block cipher.Block
	iv    []byte
}

func newAESCTR(password, salt string) (*aesCTR, error) {
	plainPassword, err := obscure.Reveal(password)
	if err != nil {
		return nil, fmt.Errorf("failed to reveal password: %w", err)
	}
	plainSalt := ""
	if salt != "" {
		plainSalt, err = obscure.Reveal(salt)
		if err != nil {
			return nil, fmt.Errorf("failed to reveal salt: %w", err)
		}
	}
	key := sha256.Sum256([]byte(plainPassword + ":" + plainSalt))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	ivSeed := sha256.Sum256([]byte("iv:" + plainPassword + ":" + plainSalt))
	iv := make([]byte, aes.BlockSize)
	copy(iv, ivSeed[:aes.BlockSize])
	return &aesCTR{block: block, iv: iv}, nil
}

func (a *aesCTR) EncryptBytes(plain []byte) []byte {
	result := make([]byte, len(plain))
	stream := cipher.NewCTR(a.block, a.iv)
	stream.XORKeyStream(result, plain)
	return result
}

func (a *aesCTR) DecryptBytes(cipherText []byte) ([]byte, error) {
	result := make([]byte, len(cipherText))
	stream := cipher.NewCTR(a.block, a.iv)
	stream.XORKeyStream(result, cipherText)
	return result, nil
}

func (a *aesCTR) XORKeyStreamAt(dst, src []byte, offset int64) error {
	if offset < 0 {
		return fmt.Errorf("invalid offset: %d", offset)
	}
	counter := uint64(offset / aesBlockSize)
	blockOffset := int(offset % aesBlockSize)
	iv := make([]byte, len(a.iv))
	copy(iv, a.iv)
	addCounter(iv, counter)
	stream := cipher.NewCTR(a.block, iv)
	if blockOffset > 0 {
		discard := make([]byte, blockOffset)
		stream.XORKeyStream(discard, discard)
	}
	stream.XORKeyStream(dst, src)
	return nil
}

func (a *aesCTR) EncryptReader(r io.Reader) (io.Reader, int64, error) {
	size := int64(-1)
	if s, ok := r.(interface{ GetSize() int64 }); ok {
		size = s.GetSize()
	}
	return &cipher.StreamReader{S: cipher.NewCTR(a.block, cloneBytes(a.iv)), R: r}, size, nil
}

func (a *aesCTR) DecryptReader(r io.Reader) (io.ReadCloser, int64, error) {
	size := int64(-1)
	if s, ok := r.(interface{ GetSize() int64 }); ok {
		size = s.GetSize()
	}
	if rc, ok := r.(io.ReadCloser); ok {
		return &streamReadCloser{
			Reader: &cipher.StreamReader{S: cipher.NewCTR(a.block, cloneBytes(a.iv)), R: rc},
			Closer: rc,
		}, size, nil
	}
	return io.NopCloser(&cipher.StreamReader{S: cipher.NewCTR(a.block, cloneBytes(a.iv)), R: r}), size, nil
}

func (a *aesCTR) DecryptReaderAt(r io.ReadCloser, offset int64) (io.ReadCloser, error) {
	if offset < 0 {
		return nil, fmt.Errorf("invalid offset: %d", offset)
	}
	counter := uint64(offset / aesBlockSize)
	blockOffset := int(offset % aesBlockSize)
	iv := cloneBytes(a.iv)
	addCounter(iv, counter)
	stream := cipher.NewCTR(a.block, iv)
	if blockOffset > 0 {
		discard := make([]byte, blockOffset)
		stream.XORKeyStream(discard, discard)
	}
	return &streamReadCloser{
		Reader: &cipher.StreamReader{S: stream, R: r},
		Closer: r,
	}, nil
}

func encryptedSizeByPlainSize(size int64) int64 {
	return size
}

func addCounter(iv []byte, counter uint64) {
	for i := len(iv) - 1; i >= 0 && counter > 0; i-- {
		sum := uint64(iv[i]) + (counter & 0xff)
		iv[i] = byte(sum)
		counter = (counter >> 8) + (sum >> 8)
	}
}

func bytesReader(data []byte) io.Reader {
	return &sliceReader{data: data}
}

func cloneBytes(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

type streamReadCloser struct {
	io.Reader
	io.Closer
}

type sliceReader struct {
	data []byte
	off  int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}