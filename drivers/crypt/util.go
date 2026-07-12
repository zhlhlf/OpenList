package crypt

import (
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	stdpath "path"
	"path/filepath"
	"strings"
)

// will give the best guessing based on the path
func guessPath(path string) (isFolder, secondTry bool) {
	if strings.HasSuffix(path, "/") {
		//confirmed a folder
		return true, false
	}
	lastSlash := strings.LastIndex(path, "/")
	if strings.Index(path[lastSlash:], ".") < 0 {
		//no dot, try folder then try file
		return true, true
	}
	return false, true
}

func (d *Crypt) getPathForRemote(path string, isFolder bool) (remoteFullPath string) {
	if isFolder && !strings.HasSuffix(path, "/") {
		path = path + "/"
	}
	dir, fileName := filepath.Split(path)

	remoteDir, err := d.getEncryptedName(dir, true)
	remoteFileName := ""
	if len(strings.TrimSpace(fileName)) > 0 {
		remoteFileName, err = d.getEncryptedName(fileName, false)
	}
	if err != nil {
		return stdpath.Join(d.RemotePath, remoteDir, "")
	}
	return stdpath.Join(d.RemotePath, remoteDir, remoteFileName)

}

// actual path is used for internal only. any link for user should come from remoteFullPath
func (d *Crypt) getActualPathForRemote(path string, isFolder bool) (string, error) {
	_, remoteActualPath, err := op.GetStorageAndActualPath(d.getPathForRemote(path, isFolder))
	return remoteActualPath, err
}

// 加密文件名或文件夹名
// isDir: true 表示文件夹，false 表示文件（保留扩展名不变）
func (d *Crypt) getEncryptedName(name string, isDir bool) (string, error) {

	switch {

	case !d.EncryptDirName:
		return name, nil
	case isDir:
		return d.cipher.EncryptDirName(name), nil
	case d.Suffix != "":
		return d.cipher.EncryptDirName(name) + d.Suffix, nil
	default:
		ext := filepath.Ext(name)
		encrypted := d.cipher.EncryptFileName(name[:len(name)-len(ext)])
		return encrypted + ext, nil
	}
}

// 解密文件名or文件夹名（文件保留扩展名不变）
func (d *Crypt) getDecryptedName(filename string, isDir bool) (string, error) {

	switch {

	case !d.EncryptDirName:
		return filename, nil
	case isDir:
		return d.cipher.DecryptDirName(filename)
	case d.Suffix != "":
		return d.cipher.DecryptDirName(filename[:len(filename)-len(d.Suffix)])
	default:
		// 只获取一次扩展名
		ext := filepath.Ext(filename)
		decrypted, err := d.cipher.DecryptFileName(filename[:len(filename)-len(ext)])
		return decrypted + ext, err
	}
}
