package crypt

import (
	"context"
	"encoding/base64"
	stdpath "path"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/rclone/rclone/fs/config/obscure"
	log "github.com/sirupsen/logrus"
)

const cryptDirectTransferPrefix = "crypt-direct:"

type cryptDirectTransferInfo struct {
	CryptMountPath   string `json:"crypt_mount_path"`
	RemoteActualPath string `json:"remote_actual_path"`
}

type cryptDirectTransferObj struct {
	model.Obj
	directID string
}

func (o *cryptDirectTransferObj) GetID() string {
	return o.directID
}

func (o *cryptDirectTransferObj) Unwrap() model.Obj {
	return o.Obj
}

func (d *Crypt) wrapDirectTransferObj(obj model.Obj, remoteFullPath string) model.Obj {
	directID := d.makeDirectTransferID(remoteFullPath)
	if directID == "" {
		return obj
	}
	return &cryptDirectTransferObj{Obj: obj, directID: directID}
}

func (d *Crypt) makeDirectTransferID(remoteFullPath string) string {
	_, remoteActualPath, err := op.GetStorageAndActualPath(remoteFullPath)
	if err != nil {
		return ""
	}
	payload, err := utils.Json.Marshal(cryptDirectTransferInfo{
		CryptMountPath:   d.GetStorage().MountPath,
		RemoteActualPath: remoteActualPath,
	})
	if err != nil {
		return ""
	}
	return cryptDirectTransferPrefix + base64.RawURLEncoding.EncodeToString(payload)
}

func parseDirectTransferID(id string) (*cryptDirectTransferInfo, error) {
	raw, ok := strings.CutPrefix(id, cryptDirectTransferPrefix)
	if !ok {
		return nil, errs.NotSupport
	}
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var info cryptDirectTransferInfo
	if err = utils.Json.Unmarshal(payload, &info); err != nil {
		return nil, err
	}
	if info.CryptMountPath == "" || info.RemoteActualPath == "" {
		return nil, errs.NotSupport
	}
	return &info, nil
}

func (d *Crypt) tryDirectTransfer(ctx context.Context, streamer model.FileStreamer, dstDirActualPath string) error {
	info, err := parseDirectTransferID(streamer.GetID())
	if err != nil {
		return err
	}
	srcDriver, err := op.GetStorageByMountPath(info.CryptMountPath)
	if err != nil {
		return err
	}
	srcCrypt, ok := srcDriver.(*Crypt)
	if !ok {
		return errs.NotSupport
	}
	if reason := srcCrypt.directTransferIncompatibleReason(d); reason != "" {
		log.Debugf("crypt direct copy skipped: incompatible from %s to %s: %s",
			srcCrypt.GetStorage().MountPath,
			d.GetStorage().MountPath,
			reason)
		return errs.NotSupport
	}
	dstName, err := d.getEncryptedName(streamer.GetName(), false)
	if err != nil {
		return err
	}
	log.Debugf("crypt direct copy: [%s]%s -> [%s]%s",
		srcCrypt.remoteStorage.GetStorage().MountPath,
		info.RemoteActualPath,
		d.remoteStorage.GetStorage().MountPath,
		dstDirActualPath)
	if err = op.Copy(ctx, d.remoteStorage, info.RemoteActualPath, dstDirActualPath); err != nil {
		return err
	}
	srcName := stdpath.Base(info.RemoteActualPath)
	if srcName != dstName {
		return d.renameDirectCopiedFile(ctx, dstDirActualPath, srcName, dstName)
	}
	return nil
}

func (d *Crypt) renameDirectCopiedFile(ctx context.Context, dstDirActualPath, srcName, dstName string) error {
	srcPath := stdpath.Join(dstDirActualPath, srcName)
	var err error
	for i := 0; i < 5; i++ {
		err = op.Rename(ctx, d.remoteStorage, srcPath, dstName)
		if err == nil {
			log.Debugf("crypt direct copy rename: %s -> %s", srcName, dstName)
			return nil
		}
		if ctx.Err() != nil || !errs.IsObjectNotFound(err) {
			return err
		}
		time.Sleep(300 * time.Millisecond)
		op.Cache.DeleteDirectory(d.remoteStorage, dstDirActualPath)
		_, _ = op.List(ctx, d.remoteStorage, dstDirActualPath, model.ListArgs{Refresh: true})
	}
	d.removeDirectCopiedFile(ctx, dstDirActualPath, srcName)
	log.Debugf("crypt direct copy rename failed: %s -> %s: %v", srcName, dstName, err)
	return err
}

func (d *Crypt) removeDirectCopiedFile(ctx context.Context, dstDirActualPath, srcName string) {
	srcPath := stdpath.Join(dstDirActualPath, srcName)
	var err error
	for i := 0; i < 5; i++ {
		err = op.Remove(ctx, d.remoteStorage, srcPath)
		if err == nil {
			log.Debugf("crypt direct copy cleanup: removed %s", srcPath)
			return
		}
		if ctx.Err() != nil || !errs.IsObjectNotFound(err) {
			break
		}
		time.Sleep(300 * time.Millisecond)
		op.Cache.DeleteDirectory(d.remoteStorage, dstDirActualPath)
		_, _ = op.List(ctx, d.remoteStorage, dstDirActualPath, model.ListArgs{Refresh: true})
	}
	log.Debugf("crypt direct copy cleanup failed: %s: %v", srcPath, err)
}

func (d *Crypt) directTransferIncompatibleReason(dst *Crypt) string {
	if d == nil || dst == nil || d.remoteStorage == nil || dst.remoteStorage == nil {
		return "nil crypt or remote storage"
	}
	if d.remoteStorage.GetStorage() != dst.remoteStorage.GetStorage() {
		return "different remote storage"
	}
	if d.EncryptFile != dst.EncryptFile {
		return "different file encryption mode"
	}
	if d.EncryptFile != fileEncryptionFalse && !d.sameSecret(dst) {
		return "different file encryption secret"
	}
	return ""
}

func (d *Crypt) sameSecret(dst *Crypt) bool {
	srcPassword, err := revealCryptSecret(d.Password)
	if err != nil {
		return false
	}
	dstPassword, err := revealCryptSecret(dst.Password)
	if err != nil {
		return false
	}
	srcSalt, err := revealCryptSecret(d.Salt)
	if err != nil {
		return false
	}
	dstSalt, err := revealCryptSecret(dst.Salt)
	if err != nil {
		return false
	}
	return srcPassword == dstPassword && srcSalt == dstSalt
}

func revealCryptSecret(secret string) (string, error) {
	raw, ok := strings.CutPrefix(secret, obfuscatedPrefix)
	if !ok {
		return secret, nil
	}
	return obscure.Reveal(raw)
}
