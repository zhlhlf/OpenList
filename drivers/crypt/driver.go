package crypt

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	stdpath "path"
	"strconv"
	"strings"

	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/fs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/internal/sign"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	rcCrypt "github.com/rclone/rclone/backend/crypt"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/obscure"
	log "github.com/sirupsen/logrus"
)

type Crypt struct {
	model.Storage
	Addition
	cipher        *rcCrypt.Cipher
	fileEncryptor fileEncryptor
	remoteStorage driver.Driver
	config        driver.Config
}

const obfuscatedPrefix = "___Obfuscated___"

func (d *Crypt) Config() driver.Config {
	if d.config.Name == "" {
		d.config = driver.Config{
			Name:        "Crypt",
			LocalSort:   true,
			OnlyProxy:   false,
			NoCache:     true,
			NoLinkURL:   d.fileEncryptor != nil && d.fileEncryptor.Enabled(),
			DefaultRoot: "/",
		}
	}
	return d.config
}

func (d *Crypt) GetAddition() driver.Additional {
	return &d.Addition
}

func (Addition) GetRootPath() string {
	return "/"
}

func (d *Crypt) Init(ctx context.Context) error {
	//obfuscate credentials if it's updated or just created
	err := d.updateObfusParm(&d.Password)
	if err != nil {
		return fmt.Errorf("failed to obfuscate password: %w", err)
	}
	err = d.updateObfusParm(&d.Salt)
	if err != nil {
		return fmt.Errorf("failed to obfuscate salt: %w", err)
	}

	d.FileNameEncoding = utils.GetNoneEmpty(d.FileNameEncoding, "base64")
	d.EncryptFile = utils.GetNoneEmpty(d.EncryptFile, fileEncryptionFalse)

	op.MustSaveDriverStorage(d)

	//need remote storage exist
	storage, err := fs.GetStorage(d.RemotePath, &fs.GetStoragesArgs{})
	if err != nil {
		return fmt.Errorf("can't find remote storage: %w", err)
	}
	d.remoteStorage = storage

	p, _ := strings.CutPrefix(d.Password, obfuscatedPrefix)
	p2, _ := strings.CutPrefix(d.Salt, obfuscatedPrefix)
	Rconfig := configmap.Simple{
		"password":                  p,
		"password2":                 p2,
		"filename_encryption":       d.FileNameEnc,
		"directory_name_encryption": strconv.FormatBool(d.EncryptDirName),
		"filename_encoding":         d.FileNameEncoding,
		"pass_bad_blocks":           "",
	}
	c, err := rcCrypt.NewCipher(Rconfig)
	if err != nil {
		return fmt.Errorf("failed to create Cipher: %w", err)
	}
	d.cipher = c
	d.fileEncryptor, err = d.initFileEncryptor(p, p2)
	if err != nil {
		return err
	}
	d.config = driver.Config{}
	return nil
}

func (d *Crypt) initFileEncryptor(password, salt string) (fileEncryptor, error) {
	switch d.EncryptFile {
	case fileEncryptionFalse:
		return &noopFileEncryptor{}, nil
	case fileEncryptionRclone:
		return &rcloneFileEncryptor{cipher: d.cipher}, nil
	case fileEncryptionAESCTR:
		aesCipher, err := newAESCTR(password, salt)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES stream cipher: %w", err)
		}
		return &aesCTRFileEncryptor{cipher: aesCipher}, nil
	default:
		return nil, fmt.Errorf("unsupported encrypted_file mode: %s", d.EncryptFile)
	}
}

func (d *Crypt) updateObfusParm(str *string) error {
	temp := *str
	if !strings.HasPrefix(temp, obfuscatedPrefix) {
		temp, err := obscure.Obscure(temp)
		if err != nil {
			return err
		}
		temp = obfuscatedPrefix + temp
		*str = temp
	}
	return nil
}

func (d *Crypt) Drop(ctx context.Context) error {
	return nil
}

func (d *Crypt) getDecryptedFileSize(ctx context.Context, remoteMountPath string, encryptedSize int64) (int64, error) {
	if d.fileEncryptor == nil || !d.fileEncryptor.Enabled() {
		return encryptedSize, nil
	}
	return d.fileEncryptor.DecryptSize(ctx, encryptedSize, func(ctx context.Context, start, length int64) (io.ReadCloser, error) {
		remoteLink, _, err := fs.Link(ctx, remoteMountPath, model.LinkArgs{})
		if err != nil {
			return nil, err
		}
		remoteSize := remoteLink.ContentLength
		if remoteSize <= 0 {
			remoteSize = encryptedSize
		}
		rrf, err := stream.GetRangeReaderFromLink(remoteSize, remoteLink)
		if err != nil {
			_ = remoteLink.Close()
			return nil, err
		}
		rc, err := rrf.RangeRead(ctx, streamRange(start, length))
		if err != nil {
			_ = remoteLink.Close()
			return nil, err
		}
		return utils.NewReadCloser(rc, func() error {
			closers := utils.NewClosers(rc, remoteLink)
			return (&closers).Close()
		}), nil
	})
}

func streamRange(start, length int64) http_range.Range {
	return http_range.Range{Start: start, Length: length}
}

func (d *Crypt) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {

	path := dir.GetPath()
	//return d.list(ctx, d.RemotePath, path)
	//remoteFull

	objs, err := fs.List(ctx, d.getPathForRemote(path, true), &fs.ListArgs{NoLog: true, Refresh: args.Refresh})
	// the obj must implement the model.SetPath interface
	// return objs, err
	if err != nil {
		return nil, err
	}

	var result []model.Obj
	for _, obj := range objs {
		size := obj.GetSize()
		if obj.IsDir() {
			name, err := d.getDecryptedName(obj.GetName(), true)
			if err != nil {
				//filter illegal files
				continue
			}
			if !d.ShowHidden && strings.HasPrefix(name, ".") {
				continue
			}

			objRes := &model.Object{
				Name:     name,
				Size:     size,
				Modified: obj.ModTime(),
				IsFolder: obj.IsDir(),
				Ctime:    obj.CreateTime(),
				// discarding hash as it's encrypted
			}
			result = append(result, d.wrapDirectTransferObj(objRes, stdpath.Join(d.getPathForRemote(path, true), obj.GetName())))
		} else {
			thumb, ok := model.GetThumb(obj)
			// 如果进行加密文件 读取的大小应该进行解密
			if d.fileEncryptor != nil && d.fileEncryptor.Enabled() {
				remoteMountPath := stdpath.Join(d.getPathForRemote(path, true), obj.GetName())
				size, err = d.getDecryptedFileSize(ctx, remoteMountPath, obj.GetSize())
				if err != nil {
					log.Warnf("DecryptSize failed for %s ,will use original size, err:%s", path, err)
					size = obj.GetSize()
				}
			}
			name, err := d.getDecryptedName(obj.GetName(), false)
			if err != nil {
				//filter illegal files
				continue
			}
			if !d.ShowHidden && strings.HasPrefix(name, ".") {
				continue
			}
			objRes := &model.Object{
				Name:     name,
				Size:     size,
				Modified: obj.ModTime(),
				IsFolder: obj.IsDir(),
				Ctime:    obj.CreateTime(),
				// discarding hash as it's encrypted
			}
			if d.Thumbnail && thumb == "" {
				thumbPath := stdpath.Join(args.ReqPath, ".thumbnails", name+".webp")
				thumb = fmt.Sprintf("%s/d%s?sign=%s",
					common.GetApiUrl(ctx),
					utils.EncodePath(thumbPath, true),
					sign.Sign(thumbPath))
			}
			if !ok && !d.Thumbnail {
				result = append(result, d.wrapDirectTransferObj(objRes, stdpath.Join(d.getPathForRemote(path, true), obj.GetName())))
			} else {
				objWithThumb := model.ObjThumb{
					Object: *objRes,
					Thumbnail: model.Thumbnail{
						Thumbnail: thumb,
					},
				}
				result = append(result, d.wrapDirectTransferObj(&objWithThumb, stdpath.Join(d.getPathForRemote(path, true), obj.GetName())))
			}
		}
	}

	return result, nil
}

func (d *Crypt) Get(ctx context.Context, path string) (model.Obj, error) {
	if utils.PathEqual(path, "/") {
		return &model.Object{
			Name:     "Root",
			IsFolder: true,
			Path:     "/",
		}, nil
	}
	remoteFullPath := ""
	var remoteObj model.Obj
	var err, err2 error
	firstTryIsFolder, secondTry := guessPath(path)
	remoteFullPath = d.getPathForRemote(path, firstTryIsFolder)
	remoteObj, err = fs.Get(ctx, remoteFullPath, &fs.GetArgs{NoLog: true})
	if err != nil {
		if errs.IsObjectNotFound(err) && secondTry {
			//try the opposite
			remoteFullPath = d.getPathForRemote(path, !firstTryIsFolder)
			remoteObj, err2 = fs.Get(ctx, remoteFullPath, &fs.GetArgs{NoLog: true})
			if err2 != nil {
				return nil, err2
			}
		} else {
			return nil, err
		}
	}
	var size int64 = 0
	name := ""
	if !remoteObj.IsDir() {
		// 如果不进行加密文件 读取的大小应该不进行解密
		if d.fileEncryptor != nil && d.fileEncryptor.Enabled() {
			size, err = d.getDecryptedFileSize(ctx, remoteFullPath, remoteObj.GetSize())
			if err != nil {
				log.Warnf("DecryptSize failed for %s ,will use original size, err:%s", path, err)
				size = remoteObj.GetSize()
			}
		} else {
			size = remoteObj.GetSize()
		}

		name, err = d.getDecryptedName(remoteObj.GetName(), false)

		if err != nil {
			log.Warnf("DecryptFileName failed for %s ,will use original name, err:%s", path, err)
			name = remoteObj.GetName()
		}
	} else {
		name, err = d.getDecryptedName(remoteObj.GetName(), true)
		if err != nil {
			log.Warnf("DecryptDirName failed for %s ,will use original name, err:%s", path, err)
			name = remoteObj.GetName()
		}
	}
	obj := &model.Object{
		Path:     path,
		Name:     name,
		Size:     size,
		Modified: remoteObj.ModTime(),
		IsFolder: remoteObj.IsDir(),
	}
	return d.wrapDirectTransferObj(obj, d.getPathForRemote(path, remoteObj.IsDir())), nil
	//return nil, errs.ObjectNotFound
}

// https://github.com/rclone/rclone/blob/v1.67.0/backend/crypt/cipher.go#L37
const fileHeaderSize = 32

func (d *Crypt) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {

	dstDirActualPath, err := d.getActualPathForRemote(file.GetPath(), false)
	if err != nil {
		return nil, fmt.Errorf("failed to convert path to remote path: %w", err)
	}
	remoteLink, remoteFile, err := op.Link(ctx, d.remoteStorage, dstDirActualPath, args)
	if err != nil {
		return nil, err
	}
	return d.fileEncryptor.WrapLink(ctx, remoteLink, remoteFile)
}

func (d *Crypt) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) error {
	dstDirActualPath, err := d.getActualPathForRemote(parentDir.GetPath(), true)
	if err != nil {
		return fmt.Errorf("failed to convert path to remote path: %w", err)
	}
	dir, err := d.getEncryptedName(dirName, true)
	return op.MakeDir(ctx, d.remoteStorage, stdpath.Join(dstDirActualPath, dir))
}

func (d *Crypt) Move(ctx context.Context, srcObj, dstDir model.Obj) error {
	srcRemoteActualPath, err := d.getActualPathForRemote(srcObj.GetPath(), srcObj.IsDir())
	if err != nil {
		return fmt.Errorf("failed to convert path to remote path: %w", err)
	}
	dstRemoteActualPath, err := d.getActualPathForRemote(dstDir.GetPath(), dstDir.IsDir())
	if err != nil {
		return fmt.Errorf("failed to convert path to remote path: %w", err)
	}
	return op.Move(ctx, d.remoteStorage, srcRemoteActualPath, dstRemoteActualPath)
}

func (d *Crypt) Rename(ctx context.Context, srcObj model.Obj, newName string) error {
	remoteActualPath, err := d.getActualPathForRemote(srcObj.GetPath(), srcObj.IsDir())
	if err != nil {
		return fmt.Errorf("failed to convert path to remote path: %w", err)
	}
	newEncryptedName, err := d.getEncryptedName(newName, srcObj.IsDir())
	if err != nil {
		return fmt.Errorf("failed to get encrypted name: %w", err)
	}
	return op.Rename(ctx, d.remoteStorage, remoteActualPath, newEncryptedName)
}

func (d *Crypt) Copy(ctx context.Context, srcObj, dstDir model.Obj) error {
	srcRemoteActualPath, err := d.getActualPathForRemote(srcObj.GetPath(), srcObj.IsDir())
	if err != nil {
		return fmt.Errorf("failed to convert path to remote path: %w", err)
	}
	dstRemoteActualPath, err := d.getActualPathForRemote(dstDir.GetPath(), dstDir.IsDir())
	if err != nil {
		return fmt.Errorf("failed to convert path to remote path: %w", err)
	}
	return op.Copy(ctx, d.remoteStorage, srcRemoteActualPath, dstRemoteActualPath)

}

func (d *Crypt) Remove(ctx context.Context, obj model.Obj) error {
	remoteActualPath, err := d.getActualPathForRemote(obj.GetPath(), obj.IsDir())
	if err != nil {
		return fmt.Errorf("failed to convert path to remote path: %w", err)
	}
	return op.Remove(ctx, d.remoteStorage, remoteActualPath)
}

func (d *Crypt) Put(ctx context.Context, dstDir model.Obj, streamer model.FileStreamer, up driver.UpdateProgress) error {

	dstDirActualPath, err := d.getActualPathForRemote(dstDir.GetPath(), true)
	if err != nil {
		return fmt.Errorf("failed to convert path to remote path: %w", err)
	}
	if err = d.tryDirectTransfer(ctx, streamer, dstDirActualPath); err == nil {
		return nil
	} else if !stderrors.Is(err, errs.NotSupport) {
		return err
	}

	name, err := d.getEncryptedName(streamer.GetName(), false)
	if err != nil {
		return fmt.Errorf("failed to get encrypted name: %w", err)
	}

	reader, size, err := d.fileEncryptor.EncryptStream(streamer)
	if err != nil {
		return fmt.Errorf("failed to encrypt stream: %w", err)
	}

	// doesn't support seekableStream, since rapid-upload is not working for encrypted data
	streamOut := &stream.FileStream{
		Obj: &model.Object{
			ID:       streamer.GetID(),
			Path:     streamer.GetPath(),
			Name:     name,
			Size:     size,
			Modified: streamer.ModTime(),
			IsFolder: streamer.IsDir(),
		},
		Reader:            reader,
		Mimetype:          "application/octet-stream",
		WebPutAsTask:      streamer.NeedStore(),
		ForceStreamUpload: true,
		Exist:             streamer.GetExist(),
	}

	return op.Put(ctx, d.remoteStorage, dstDirActualPath, streamOut, up)
}

func (d *Crypt) GetDetails(ctx context.Context) (*model.StorageDetails, error) {
	if d.remoteStorage == nil {
		return nil, errs.NotImplement
	}
	return op.GetStorageDetails(ctx, d.remoteStorage)
}

var _ driver.Driver = (*Crypt)(nil)
