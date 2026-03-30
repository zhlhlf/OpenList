package crypt2

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"

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

type openRangeSeek func(ctx context.Context, offset, limit int64) (io.ReadCloser, error)

type aesCTRReadSeekCloser interface {
	io.ReadCloser
	io.Seeker
	RangeSeek(ctx context.Context, offset int64, whence int, limit int64) (int64, error)
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

func (a *aesCTR) DecryptDataSeek(ctx context.Context, open openRangeSeek, offset, limit int64) (aesCTRReadSeekCloser, error) {
	if open == nil {
		return nil, errors.New("missing open func")
	}
	d := &aesCTRDecrypter{
		ctx:   ctx,
		cipher: a,
		open:  open,
		limit: limit,
		size:  -1,
	}
	if err := d.reopen(offset, limit); err != nil {
		return nil, err
	}
	return d, nil
}

type aesCTRDecrypter struct {
	mu     sync.Mutex
	ctx    context.Context
	cipher *aesCTR
	open   openRangeSeek
	rc     io.ReadCloser
	stream cipher.Stream
	offset int64
	limit  int64
	size   int64
	closed bool
}

func (d *aesCTRDecrypter) reopen(offset, limit int64) error {
	if offset < 0 {
		return fmt.Errorf("invalid offset: %d", offset)
	}
	if d.rc != nil {
		_ = d.rc.Close()
		d.rc = nil
	}
	rc, err := d.open(d.ctx, offset, limit)
	if err != nil {
		return err
	}
	stream, err := d.cipher.newStreamAt(offset)
	if err != nil {
		_ = rc.Close()
		return err
	}
	d.rc = rc
	d.stream = stream
	d.offset = offset
	d.limit = limit
	if limit >= 0 {
		d.size = offset + limit
	}
	d.closed = false
	return nil
}

func (d *aesCTRDecrypter) Read(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return 0, io.EOF
	}
	if d.limit == 0 {
		return 0, io.EOF
	}
	if d.limit > 0 && int64(len(p)) > d.limit {
		p = p[:d.limit]
	}
	n, err := d.rc.Read(p)
	if n > 0 {
		d.stream.XORKeyStream(p[:n], p[:n])
		d.offset += int64(n)
		if d.limit > 0 {
			d.limit -= int64(n)
			if d.limit == 0 && err == nil {
				return n, io.EOF
			}
		}
	}
	return n, err
}

func (d *aesCTRDecrypter) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	if d.rc != nil {
		return d.rc.Close()
	}
	return nil
}

func (d *aesCTRDecrypter) Seek(offset int64, whence int) (int64, error) {
	return d.RangeSeek(d.ctx, offset, whence, -1)
}

func (d *aesCTRDecrypter) RangeSeek(ctx context.Context, offset int64, whence int, limit int64) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var target int64
	switch whence {
	case io.SeekStart:
		target = offset
	case io.SeekCurrent:
		target = d.offset + offset
	case io.SeekEnd:
		if d.size < 0 {
			return 0, errors.New("seek end requires known size")
		}
		target = d.size + offset
	default:
		return 0, errors.New("unsupported whence")
	}
	if target < 0 {
		return 0, errors.New("negative position")
	}
	if ctx != nil {
		d.ctx = ctx
	}
	if err := d.reopen(target, limit); err != nil {
		return 0, err
	}
	return target, nil
}

func (a *aesCTR) newStreamAt(offset int64) (cipher.Stream, error) {
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
	return stream, nil
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