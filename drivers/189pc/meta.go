package _189pc

import (
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

type Addition struct {
	Username    string `json:"username" required:"false"`
	Password    string `json:"password" required:"false"`
	AccessToken string `json:"access_token" required:"false"`
	VCode       string `json:"validate_code"`
	driver.RootID
	OrderBy        string `json:"order_by" type:"select" options:"filename,filesize,lastOpTime" default:"filename"`
	OrderDirection string `json:"order_direction" type:"select" options:"asc,desc" default:"asc"`
	Type           string `json:"type" type:"select" options:"personal,family" default:"personal"`
	FamilyID       string `json:"family_id"`
	UploadMethod   string `json:"upload_method" type:"select" options:"rapid" default:"rapid"`
	UploadThread   string `json:"upload_thread" default:"3" help:"1<=thread<=32"`
	FamilyTransfer bool   `json:"family_transfer"`
	EnableCAS      bool   `json:"enable_cas" help:"Upload real file data and keep a small .bin CAS placeholder"`
	NoUseOcr       bool   `json:"no_use_ocr"`
}

var config = driver.Config{
	Name:        "189CloudPC",
	DefaultRoot: "-11",
	CheckStatus: true,
}

func init() {
	op.RegisterDriver(func() driver.Driver {
		return &Cloud189PC{}
	})
}
