package crypt2

import (
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

type Addition struct {
	// Usually one of two
	//driver.RootPath
	//driver.RootID
	// define other

	RemotePath  string `json:"remote_path" required:"true" help:"This is where the encrypted data stores"`

	Password         string `json:"password" required:"true" confidential:"true" help:"the main password"`
	Salt             string `json:"salt" confidential:"true"  help:"If you don't know what is salt, treat it as a second password. Optional but recommended"`
	FileNameEnc string `json:"filename_encryption" type:"select" required:"true" options:"off,standard,obfuscate" default:"off"`
	FileNameEncoding string `json:"filename_encoding" type:"select" required:"true" options:"base64,base32,base32768" default:"base64" help:"for advanced user only!"`

	Thumbnail bool `json:"thumbnail" required:"true" default:"false" help:"enable thumbnail which pre-generated under .thumbnails folder"`
	ShowHidden bool `json:"show_hidden"  default:"true" required:"false" help:"show hidden directories and files"`
	EncryptDirName bool   `json:"directory_name_encryption"  default:"true"`
	EncryptFile string   `json:"encrypted_file" type:"select" required:"true" options:"false,rclone,aes_ctr" default:"false"`
	Suffix string   `json:"suffix"  required:"false" default:"" help:"The suffix of the encrypted file, blank is to keep the original suffix."`
}

func init() {
	op.RegisterDriver(func() driver.Driver {
		return &Crypt{}
	})
}
