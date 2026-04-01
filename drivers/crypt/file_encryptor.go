package crypt2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	rcCrypt "github.com/rclone/rclone/backend/crypt"
)

type fileEncryptor interface {
	Enabled() bool
	DecryptSize(ctx context.Context, encryptedSize int64, openRange func(ctx context.Context, start, length int64) (io.ReadCloser, error)) (int64, error)
	EncryptStream(streamer model.FileStreamer) (io.Reader, int64, error)
	WrapLink(ctx context.Context, remoteLink *model.Link, remoteFile model.Obj) (*model.Link, error)
}

type noopFileEncryptor struct{}

func (e *noopFileEncryptor) Enabled() bool {
	return false
}

func (e *noopFileEncryptor) DecryptSize(ctx context.Context, encryptedSize int64, openRange func(ctx context.Context, start, length int64) (io.ReadCloser, error)) (int64, error) {
	return encryptedSize, nil
}

func (e *noopFileEncryptor) EncryptStream(streamer model.FileStreamer) (io.Reader, int64, error) {
	return streamer, streamer.GetSize(), nil
}

func (e *noopFileEncryptor) WrapLink(ctx context.Context, remoteLink *model.Link, remoteFile model.Obj) (*model.Link, error) {
	return remoteLink, nil
}

type rcloneFileEncryptor struct {
	cipher *rcCrypt.Cipher
}

func (e *rcloneFileEncryptor) Enabled() bool {
	return true
}

func (e *rcloneFileEncryptor) DecryptSize(ctx context.Context, encryptedSize int64, openRange func(ctx context.Context, start, length int64) (io.ReadCloser, error)) (int64, error) {
	return e.cipher.DecryptedSize(encryptedSize)
}

func (e *rcloneFileEncryptor) EncryptStream(streamer model.FileStreamer) (io.Reader, int64, error) {
	wrappedIn, err := e.cipher.EncryptData(streamer)
	if err != nil {
		return nil, 0, err
	}
	return wrappedIn, e.cipher.EncryptedSize(streamer.GetSize()), nil
}

func (e *rcloneFileEncryptor) WrapLink(ctx context.Context, remoteLink *model.Link, remoteFile model.Obj) (*model.Link, error) {
	remoteSize := remoteLink.ContentLength
	if remoteSize <= 0 {
		remoteSize = remoteFile.GetSize()
	}
	rrf, err := stream.GetRangeReaderFromLink(remoteSize, remoteLink)
	if err != nil {
		_ = remoteLink.Close()
		return nil, fmt.Errorf("the remote storage driver need to be enhanced to support encrytion")
	}

	mu := &sync.Mutex{}
	var fileHeader []byte
	rangeReaderFunc := func(ctx context.Context, offset, limit int64) (io.ReadCloser, error) {
		length := limit
		if offset == 0 && limit > 0 {
			mu.Lock()
			if limit <= fileHeaderSize {
				defer mu.Unlock()
				if fileHeader != nil {
					return io.NopCloser(bytes.NewReader(fileHeader[:limit])), nil
				}
				length = fileHeaderSize
			} else if fileHeader == nil {
				defer mu.Unlock()
			} else {
				mu.Unlock()
			}
		}

		remoteReader, err := rrf.RangeRead(ctx, http_range.Range{Start: offset, Length: length})
		if err != nil {
			return nil, err
		}

		if offset == 0 && limit > 0 {
			fileHeader = make([]byte, fileHeaderSize)
			n, err := io.ReadFull(remoteReader, fileHeader)
			if n != fileHeaderSize {
				fileHeader = nil
				return nil, fmt.Errorf("failed to read all data: (expect =%d, actual =%d) %w", fileHeaderSize, n, err)
			}
			if limit <= fileHeaderSize {
				remoteReader.Close()
				return io.NopCloser(bytes.NewReader(fileHeader[:limit])), nil
			}
			remoteReader = utils.ReadCloser{
				Reader: io.MultiReader(bytes.NewReader(fileHeader), remoteReader),
				Closer: remoteReader,
			}
		}
		return remoteReader, nil
	}

	return &model.Link{
		RangeReader: stream.RangeReaderFunc(func(ctx context.Context, httpRange http_range.Range) (io.ReadCloser, error) {
			readSeeker, err := e.cipher.DecryptDataSeek(ctx, rangeReaderFunc, httpRange.Start, httpRange.Length)
			if err != nil {
				return nil, err
			}
			return readSeeker, nil
		}),
		SyncClosers:      utils.NewSyncClosers(remoteLink),
		RequireReference: remoteLink.RequireReference,
	}, nil
}

type aesCTRFileEncryptor struct {
	cipher *aesCTR
}

func (e *aesCTRFileEncryptor) Enabled() bool {
	return true
}

func (e *aesCTRFileEncryptor) DecryptSize(ctx context.Context, encryptedSize int64, openRange func(ctx context.Context, start, length int64) (io.ReadCloser, error)) (int64, error) {
	return encryptedSize, nil
}

func (e *aesCTRFileEncryptor) EncryptStream(streamer model.FileStreamer) (io.Reader, int64, error) {
	return e.cipher.EncryptReader(streamer)
}

func (e *aesCTRFileEncryptor) WrapLink(ctx context.Context, remoteLink *model.Link, remoteFile model.Obj) (*model.Link, error) {
	remoteSize := remoteLink.ContentLength
	if remoteSize <= 0 {
		remoteSize = remoteFile.GetSize()
	}
	rrf, err := stream.GetRangeReaderFromLink(remoteSize, remoteLink)
	if err != nil {
		_ = remoteLink.Close()
		return nil, fmt.Errorf("the remote storage driver need to be enhanced to support encrytion")
	}
	decryptedSize, err := e.DecryptSize(ctx, remoteSize, func(ctx context.Context, start, length int64) (io.ReadCloser, error) {
		return rrf.RangeRead(ctx, http_range.Range{Start: start, Length: length})
	})
	if err != nil {
		return nil, err
	}

	return &model.Link{
		RangeReader: stream.RangeReaderFunc(func(ctx context.Context, httpRange http_range.Range) (io.ReadCloser, error) {
			start := httpRange.Start
			if start < 0 {
				start = 0
			}
			length := httpRange.Length
			if length < 0 || start+length > decryptedSize {
				length = decryptedSize - start
			}
			if length <= 0 {
				return io.NopCloser(bytes.NewReader(nil)), nil
			}
			reader, err := e.cipher.DecryptDataSeek(ctx, func(ctx context.Context, offset, limit int64) (io.ReadCloser, error) {
				return rrf.RangeRead(ctx, http_range.Range{Start: offset, Length: limit})
			}, start, length)
			if err != nil {
				return nil, err
			}
			if seeker, ok := reader.(*aesCTRDecrypter); ok && seeker.size < 0 {
				seeker.size = decryptedSize
			}
			return reader, nil
		}),
		SyncClosers:      utils.NewSyncClosers(remoteLink),
		RequireReference: remoteLink.RequireReference,
		ContentLength:    decryptedSize,
	}, nil
}
