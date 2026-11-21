package _189pc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/go-resty/resty/v2"
	"gorm.io/gorm"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/db"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
)

type hostRewrite struct{ host string }

func (h hostRewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	n := r.Clone(r.Context())
	n.URL.Scheme = "http"
	n.URL.Host = h.host
	n.Host = h.host
	return http.DefaultTransport.RoundTrip(n)
}

// 端到端：模拟 189 全部接口，验证 result 为字符串时能登录，且 access_token 落库
func TestAppLoginSavesAccessToken(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(der)

	var gotPlain, gotEpKey bool
	mux := http.NewServeMux()
	mux.HandleFunc("/api/logbox/config/encryptConf.do", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"result": "0", // 关键：字符串形态
			"data":   map[string]string{"pre": "{NRP}", "pubKey": pubB64},
		})
	})
	mux.HandleFunc("/api/logbox/oauth2/oAuth2SdkLoginByPassword.do", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if !strings.HasPrefix(r.PostFormValue("userName"), "{NRP}") {
			t.Errorf("userName 没有 {NRP} 前缀: %s", r.PostFormValue("userName"))
		}
		if r.PostFormValue("deviceInfo") == "" {
			t.Errorf("deviceInfo 为空")
		}
		paras := xxteaEncryptHex([]byte("accessToken=TESTTOKEN123456&nickName=tester"))
		json.NewEncoder(w).Encode(map[string]any{
			"result":      "0", // 关键：字符串形态
			"msg":         "",
			"returnParas": url.QueryEscape("paras=" + paras),
		})
	})
	mux.HandleFunc("/security/generateRsaKey.action", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"res_code": "0", "pkId": "PID123", "pubKey": pubB64, "ver": "2",
		})
	})
	mux.HandleFunc("/login4MergedClient.action", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		raw, err := base64.StdEncoding.DecodeString(r.Header.Get("epkey"))
		if err != nil {
			t.Errorf("epkey base64 错: %v", err)
			return
		}
		key, err := rsa.DecryptPKCS1v15(rand.Reader, priv, raw)
		if err != nil {
			t.Errorf("epkey 解密失败: %v", err)
			return
		}
		gotEpKey = true
		plain, err := aesCBCDecryptB64(r.PostFormValue("param"), key, []byte(APP_LOGIN_AES_IV))
		if err != nil {
			t.Errorf("param 解密失败: %v", err)
			return
		}
		gotPlain = strings.Contains(plain, "accessToken=TESTTOKEN123456")
		xmlText := "<userSession><loginName>u</loginName><sessionKey>SK-1</sessionKey>" +
			"<sessionSecret>SS-1</sessionSecret><familySessionKey>FK-1</familySessionKey>" +
			"<eAccessToken>TESTTOKEN123456</eAccessToken></userSession>"
		ct, _ := aesCBCEncryptB64(url.QueryEscape(xmlText), key, []byte(APP_LOGIN_AES_IV))
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><encrypt><ciphertext>%s</ciphertext></encrypt>`, ct)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	conf.Conf = &conf.Config{Database: conf.Database{Type: "sqlite3"}}
	g, err := gorm.Open(sqlite.Open("file:189e2e?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	db.Init(g)
	st := model.Storage{MountPath: "/t189e2e", Driver: "189CloudPC",
		Addition: `{"username":"13300000000","password":"p"}`}
	if err := g.Create(&st).Error; err != nil {
		t.Fatal(err)
	}

	y := &Cloud189PC{}
	y.SetStorage(st)
	if err := json.Unmarshal([]byte(st.Addition), y.GetAddition()); err != nil {
		t.Fatal(err)
	}
	y.client = resty.New().SetTransport(hostRewrite{host: host})

	if err := y.login(); err != nil {
		t.Fatalf("login 失败: %v", err)
	}
	if !gotEpKey || gotPlain != true {
		t.Fatalf("merged 请求内容不符 epkey=%v plain=%v", gotEpKey, gotPlain)
	}
	if y.AccessToken != "TESTTOKEN123456" {
		t.Fatalf("内存 access_token 未更新: %q", y.AccessToken)
	}
	if y.tokenInfo.SessionKey != "SK-1" {
		t.Fatalf("sessionKey 不符: %q", y.tokenInfo.SessionKey)
	}
	var got model.Storage
	if err := g.First(&got, st.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.Addition, `"access_token":"TESTTOKEN123456"`) {
		t.Fatalf("DB 里 access_token 未更新: %s", got.Addition)
	}
	t.Logf("OK access_token 落库, addition=%s", got.Addition)
}

// 回归：access_token 失效时，即使 App/PC 换 session 都失败，也必须用账号密码重新登录。
func TestRefreshSessionFallsBackToLogin(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(der)

	var (
		mergedCalls int
		loginCalls  int
		pcCalls     int
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/logbox/config/encryptConf.do", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"result": "0",
			"data":   map[string]string{"pre": "{NRP}", "pubKey": pubB64},
		})
	})
	mux.HandleFunc("/api/logbox/oauth2/oAuth2SdkLoginByPassword.do", func(w http.ResponseWriter, r *http.Request) {
		loginCalls++
		paras := xxteaEncryptHex([]byte("accessToken=NEWTOKEN123456&nickName=tester"))
		json.NewEncoder(w).Encode(map[string]any{
			"result":      "0",
			"msg":         "",
			"returnParas": url.QueryEscape("paras=" + paras),
		})
	})
	mux.HandleFunc("/security/generateRsaKey.action", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"res_code": "0", "pkId": "PID123", "pubKey": pubB64, "ver": "2",
		})
	})
	mux.HandleFunc("/login4MergedClient.action", func(w http.ResponseWriter, r *http.Request) {
		mergedCalls++
		if mergedCalls == 1 {
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><error><code>UserInvalidOpenToken</code><message>token expired</message></error>`)
			return
		}
		r.ParseForm()
		raw, err := base64.StdEncoding.DecodeString(r.Header.Get("epkey"))
		if err != nil {
			t.Errorf("epkey base64 错: %v", err)
			return
		}
		key, err := rsa.DecryptPKCS1v15(rand.Reader, priv, raw)
		if err != nil {
			t.Errorf("epkey 解密失败: %v", err)
			return
		}
		plain, err := aesCBCDecryptB64(r.PostFormValue("param"), key, []byte(APP_LOGIN_AES_IV))
		if err != nil {
			t.Errorf("param 解密失败: %v", err)
			return
		}
		if !strings.Contains(plain, "accessToken=NEWTOKEN123456") {
			t.Errorf("重新登录后没有使用新 token: %s", plain)
		}
		xmlText := "<userSession><loginName>u</loginName><sessionKey>SK-NEW</sessionKey>" +
			"<sessionSecret>SS-NEW</sessionSecret><familySessionKey>FK-NEW</familySessionKey>" +
			"<eAccessToken>NEWTOKEN123456</eAccessToken></userSession>"
		ct, _ := aesCBCEncryptB64(url.QueryEscape(xmlText), key, []byte(APP_LOGIN_AES_IV))
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><encrypt><ciphertext>%s</ciphertext></encrypt>`, ct)
	})
	mux.HandleFunc("/getSessionForPC.action", func(w http.ResponseWriter, r *http.Request) {
		pcCalls++
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><error><code>UserInvalidOpenToken</code><message>token expired</message></error>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	conf.Conf = &conf.Config{Database: conf.Database{Type: "sqlite3"}}
	g, err := gorm.Open(sqlite.Open("file:189refresh?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	db.Init(g)
	st := model.Storage{MountPath: "/t189refresh", Driver: "189CloudPC",
		Addition: `{"username":"13300000000","password":"p","access_token":"OLDTOKEN123456"}`}
	if err := g.Create(&st).Error; err != nil {
		t.Fatal(err)
	}

	y := &Cloud189PC{}
	y.SetStorage(st)
	if err := json.Unmarshal([]byte(st.Addition), y.GetAddition()); err != nil {
		t.Fatal(err)
	}
	y.client = resty.New().SetTransport(hostRewrite{host: host})
	y.tokenInfo = &AppSessionResp{AccessToken: y.AccessToken}

	if err := y.refreshSession(); err != nil {
		t.Fatalf("refreshSession 失败: %v", err)
	}
	if loginCalls != 1 {
		t.Fatalf("未触发账号密码登录, loginCalls=%d", loginCalls)
	}
	if pcCalls != 1 {
		t.Fatalf("未回落 PC 方案, pcCalls=%d", pcCalls)
	}
	if mergedCalls != 2 {
		t.Fatalf("App 换 session 调用次数不符: %d", mergedCalls)
	}
	if y.AccessToken != "NEWTOKEN123456" || y.tokenInfo.AccessToken != "NEWTOKEN123456" {
		t.Fatalf("token 未更新: addition=%q tokenInfo=%q", y.AccessToken, y.tokenInfo.AccessToken)
	}
	if y.tokenInfo.SessionKey != "SK-NEW" {
		t.Fatalf("sessionKey 不符: %q", y.tokenInfo.SessionKey)
	}
}
