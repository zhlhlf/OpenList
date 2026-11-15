package _189pc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

// App 端（天翼云盘 Android 10.3.12）登录参数。
// 与 Web/PC 端的区别：不需要 unifyLoginForPC 的 lt/paramId，
// 靠 deviceInfo + guid 做设备绑定，登录成功直接拿到 accessToken。
const (
	APP_LOGIN_APP_ID      = "cloud"
	APP_LOGIN_APP_KEY     = "600100885"
	APP_LOGIN_SIGN_KEY    = "fe5734c74c2f96a38157f420b32dc995"
	APP_LOGIN_CLIENT_TYPE = "TELEANDROID"
	APP_LOGIN_VERSION     = "10.3.12"
	APP_LOGIN_MODEL       = "PKG110"
	APP_LOGIN_OS_FAMILY   = "Android"
	APP_LOGIN_OS_VERSION  = "37"
	APP_LOGIN_JOINT_VER   = "v4.7.1"
	APP_LOGIN_PKG         = "com.cn21.ecloud"
	APP_LOGIN_UA          = "Ecloud/10.3.12 (PKG110; ; nearme) Android/37"
	APP_LOGIN_AES_IV      = "Zx8dG46ax3Mc8Mj2"

	// XXTEA 密钥（deviceInfo / paras 共用，实际只用前 16 字节）
	XXTEA_KEY = "g7qP45TVkQ5G6iNbbhaU5nXlAelGcAs"
)

const xxteaDelta = 0x9e3779b9

// ---------- XXTEA（189 变体：明文 + 4 字节小端长度，再整块加密） ----------

func xxteaWords(b []byte) []uint32 {
	n := (len(b) + 3) / 4
	v := make([]uint32, n)
	for i := 0; i < n; i++ {
		var w [4]byte
		copy(w[:], b[i*4:])
		v[i] = binary.LittleEndian.Uint32(w[:])
	}
	return v
}

func xxteaBytes(v []uint32) []byte {
	out := make([]byte, len(v)*4)
	for i, w := range v {
		binary.LittleEndian.PutUint32(out[i*4:], w)
	}
	return out
}

func xxteaKeyWords(key string) []uint32 {
	return xxteaWords([]byte(key))[:4]
}

func xxteaEncrypt(data []byte, key string) []byte {
	v := xxteaWords(data)
	k := xxteaKeyWords(key)
	n := len(v)
	if n == 0 {
		return nil
	}
	rounds := 6 + 52/n
	var sum uint32
	z := v[n-1]
	for ; rounds > 0; rounds-- {
		sum += xxteaDelta
		e := int((sum >> 2) & 3)
		for p := 0; p < n-1; p++ {
			y := v[p+1]
			mx := ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[(p&3)^e] ^ z))
			v[p] += mx
			z = v[p]
		}
		y := v[0]
		mx := ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[((n-1)&3)^e] ^ z))
		v[n-1] += mx
		z = v[n-1]
	}
	return xxteaBytes(v)
}

func xxteaDecrypt(data []byte, key string) []byte {
	v := xxteaWords(data)
	k := xxteaKeyWords(key)
	n := len(v)
	if n == 0 {
		return nil
	}
	rounds := 6 + 52/n
	sum := uint32(rounds) * xxteaDelta
	y := v[0]
	for ; rounds > 0; rounds-- {
		e := int((sum >> 2) & 3)
		for p := n - 1; p > 0; p-- {
			z := v[p-1]
			mx := ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[(p&3)^e] ^ z))
			v[p] -= mx
			y = v[p]
		}
		z := v[n-1]
		mx := ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[e] ^ z))
		v[0] -= mx
		y = v[0]
		sum -= xxteaDelta
	}
	return xxteaBytes(v)
}

func xxteaEncryptHex(plain []byte) string {
	buf := make([]byte, len(plain)+4)
	copy(buf, plain)
	binary.LittleEndian.PutUint32(buf[len(plain):], uint32(len(plain)))
	return strings.ToUpper(hex.EncodeToString(xxteaEncrypt(buf, XXTEA_KEY)))
}

func xxteaDecryptHex(s string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	out := xxteaDecrypt(raw, XXTEA_KEY)
	if len(out) >= 4 {
		if n := int(binary.LittleEndian.Uint32(out[len(out)-4:])); n > 0 && n <= len(out)-4 {
			return out[:n], nil
		}
	}
	return bytes.TrimRight(out, "\x00"), nil
}

// ---------- AES / RSA 小工具 ----------

func aesCBCEncryptB64(plain string, key, iv []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	padded := PKCS7Padding([]byte(plain), block.BlockSize())
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return base64.StdEncoding.EncodeToString(out), nil
}

func aesCBCDecryptB64(s string, key, iv []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(raw) == 0 || len(raw)%block.BlockSize() != 0 {
		return "", fmt.Errorf("189 app: 密文长度非法 %d", len(raw))
	}
	out := make([]byte, len(raw))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, raw)
	n := int(out[len(out)-1])
	if n <= 0 || n > block.BlockSize() || n > len(out) {
		return "", fmt.Errorf("189 app: padding 非法")
	}
	return string(out[:len(out)-n]), nil
}

func rsaEncryptB64(pubKeyB64 string, data []byte) (string, error) {
	der, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return "", err
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("189 app: 不是 RSA 公钥")
	}
	enc, err := rsa.EncryptPKCS1v15(crand.Reader, rsaPub, data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(enc), nil
}

func randAppKey(n int) ([]byte, error) {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		return nil, err
	}
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return b, nil
}

// ---------- App 登录 ----------

type appDeviceInfo struct {
	Imei         string `json:"imei"`
	Imsi         string `json:"imsi"`
	DeviceID     string `json:"deviceId"`
	TerminalInfo string `json:"terminalInfo"`
	OsInfo       string `json:"osInfo"`
	MobileBrand  string `json:"mobileBrand"`
	MobileModel  string `json:"mobileModel"`
}

type appEncryptConfResp struct {
	Result int    `json:"result"`
	Msg    string `json:"msg"`
	Data   struct {
		Pre    string `json:"pre"`
		PubKey string `json:"pubKey"`
	} `json:"data"`
}

type appLoginResp struct {
	Result      int    `json:"result"`
	Msg         string `json:"msg"`
	ReturnParas string `json:"returnParas"`
}

type appUserSessionResp struct {
	XMLName             xml.Name `xml:"userSession"`
	LoginName           string   `xml:"loginName"`
	SessionKey          string   `xml:"sessionKey"`
	SessionSecret       string   `xml:"sessionSecret"`
	FamilySessionKey    string   `xml:"familySessionKey"`
	FamilySessionSecret string   `xml:"familySessionSecret"`
	EAccessToken        string   `xml:"eAccessToken"`
}

func (y *Cloud189PC) appDeviceID() string {
	return fmt.Sprintf("%x", md5.Sum([]byte("189:"+y.Username)))
}

func (y *Cloud189PC) appDeviceInfo(guid string) string {
	info := appDeviceInfo{
		DeviceID:     guid,
		TerminalInfo: APP_LOGIN_MODEL,
		OsInfo:       APP_LOGIN_OS_FAMILY + ":" + APP_LOGIN_OS_VERSION,
		MobileBrand:  "OnePlus",
		MobileModel:  APP_LOGIN_MODEL,
	}
	b, err := json.Marshal(info)
	if err != nil {
		return ""
	}
	return xxteaEncryptHex(b)
}

// loginByApp 用 App 端接口拿 accessToken（替代 Web 的 lt/paramId + loginSubmit）
func (y *Cloud189PC) loginByApp() (string, error) {
	var encConf appEncryptConfResp
	_, err := y.client.R().
		ForceContentType("application/json;charset=UTF-8").
		SetResult(&encConf).
		SetFormData(map[string]string{"appId": APP_LOGIN_APP_ID}).
		Post(AUTH_URL + "/api/logbox/config/encryptConf.do")
	if err != nil {
		return "", err
	}
	if encConf.Data.PubKey == "" {
		return "", fmt.Errorf("189 app login: encryptConf 未返回公钥")
	}
	pubPem := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", encConf.Data.PubKey)

	guid := y.appDeviceID()
	var resp appLoginResp
	_, err = y.client.R().
		ForceContentType("application/json;charset=UTF-8").
		SetResult(&resp).
		SetHeader("X-Requested-With", APP_LOGIN_PKG).
		SetFormData(map[string]string{
			"appKey":         APP_LOGIN_APP_ID,
			"deviceInfo":     y.appDeviceInfo(guid),
			"apptype":        "wap",
			"loginType":      "1",
			"dynamicCheck":   "false",
			"userName":       encConf.Data.Pre + RsaEncrypt(pubPem, y.Username),
			"password":       encConf.Data.Pre + RsaEncrypt(pubPem, y.Password),
			"validateCode":   "",
			"captchaToken":   "",
			"jointWay":       "1|2",
			"jointVersion":   APP_LOGIN_JOINT_VER,
			"operator":       "",
			"nwc":            "5G",
			"nws":            "0",
			"guid":           guid,
			"reqId":          "undefined",
			"headerDeviceId": guid,
		}).
		Post(AUTH_URL + "/api/logbox/oauth2/oAuth2SdkLoginByPassword.do")
	if err != nil {
		return "", err
	}
	if resp.Result != 0 {
		return "", fmt.Errorf("189 app login 失败: result=%d msg=%s", resp.Result, resp.Msg)
	}

	// returnParas 是 urlencoded，里面 paras 是 XXTEA hex
	unescaped, err := url.QueryUnescape(resp.ReturnParas)
	if err != nil {
		return "", err
	}
	q, err := url.ParseQuery(unescaped)
	if err != nil {
		return "", err
	}
	paras := q.Get("paras")
	if paras == "" {
		return "", fmt.Errorf("189 app login: returnParas 里没有 paras 字段")
	}
	plain, err := xxteaDecryptHex(paras)
	if err != nil {
		return "", err
	}
	info, err := url.ParseQuery(string(plain))
	if err != nil {
		return "", err
	}
	token := info.Get("accessToken")
	if token == "" {
		return "", fmt.Errorf("189 app login: paras 里没有 accessToken")
	}
	return token, nil
}

// login 用 App 方式登录并刷新会话
func (y *Cloud189PC) login() (err error) {
	if y.loggingIn {
		return fmt.Errorf("189: 登录正在进行中")
	}
	y.loggingIn = true
	defer func() { y.loggingIn = false }()

	if y.Username == "" || y.Password == "" {
		return fmt.Errorf("189: 用户名或密码为空")
	}

	token, err := y.loginByApp()
	if err != nil {
		return err
	}
	y.tokenInfo = &AppSessionResp{AccessToken: token}
	y.updateValue(&y.AccessToken, token)
	if err = y.refreshSession(); err != nil {
		return err
	}
	op.MustSaveDriverStorage(y)
	return nil
}

// refreshSessionByApp 用 App 端 login4MergedClient 换 sessionKey / sessionSecret。
// accessToken 走 epkey 方案：随机 K + AES-CBC 加密 param，K 用服务端 RSA 公钥包成 epkey。
func (y *Cloud189PC) refreshSessionByApp() error {
	var g struct {
		ResCode    int    `json:"res_code"`
		ResMessage string `json:"res_message"`
		PkID       string `json:"pkId"`
		PubKey     string `json:"pubKey"`
		Ver        string `json:"ver"`
	}
	_, err := y.client.R().
		ForceContentType("application/json;charset=UTF-8").
		SetResult(&g).
		SetQueryParams(map[string]string{
			"clientType": APP_LOGIN_CLIENT_TYPE,
			"version":    APP_LOGIN_VERSION,
			"model":      APP_LOGIN_MODEL,
			"osFamily":   APP_LOGIN_OS_FAMILY,
			"osVersion":  APP_LOGIN_OS_VERSION,
			"clientSn":   y.appDeviceID(),
			"returnType": "JSON",
		}).
		Get(API_URL + "/security/generateRsaKey.action")
	if err != nil {
		return err
	}
	if g.PkID == "" || g.PubKey == "" {
		return fmt.Errorf("189 app: generateRsaKey 失败 res_code=%d msg=%s", g.ResCode, g.ResMessage)
	}

	ts := fmt.Sprintf("%d", time.Now().UnixMilli())
	plain := strings.Join([]string{
		"rand=" + ts,
		"accessToken=" + url.QueryEscape(y.tokenInfo.AccessToken),
		"clientType=" + APP_LOGIN_CLIENT_TYPE,
		"version=" + APP_LOGIN_VERSION,
		"clientSn=" + y.appDeviceID(),
		"model=" + APP_LOGIN_MODEL,
		"osFamily=" + APP_LOGIN_OS_FAMILY,
		"osVersion=" + APP_LOGIN_OS_VERSION,
		"networkAccessMode=WIFI",
		"telecomsOperator=46011",
		"channelId=nearme",
		"isCache=1",
		"deviceModel=" + APP_LOGIN_MODEL,
		"jgOpenId=",
	}, "&")

	key, err := randAppKey(16)
	if err != nil {
		return err
	}
	param, err := aesCBCEncryptB64(plain, key, []byte(APP_LOGIN_AES_IV))
	if err != nil {
		return err
	}
	epkey, err := rsaEncryptB64(g.PubKey, key)
	if err != nil {
		return err
	}
	signSrc := fmt.Sprintf("AppKey=%s&Operate=POST&RequestURI=/login4MergedClient.action&Timestamp=%s",
		APP_LOGIN_APP_KEY, ts)
	mac := hmac.New(sha1.New, []byte(APP_LOGIN_SIGN_KEY))
	mac.Write([]byte(signSrc))
	sign := hex.EncodeToString(mac.Sum(nil))

	res, err := y.client.R().
		SetHeader("content-type", "application/x-www-form-urlencoded").
		SetHeader("epkey", epkey).
		SetHeader("epver", "2").
		SetHeader("epway", "3").
		SetHeader("appkey", APP_LOGIN_APP_KEY).
		SetHeader("timestamp", ts).
		SetHeader("appsignature", sign).
		SetHeader("accept", "*/*").
		SetFormData(map[string]string{"pkId": g.PkID, "param": param}).
		Post(API_URL + "/login4MergedClient.action")
	if err != nil {
		return err
	}
	m := regexp.MustCompile(`(?s)<ciphertext>(.*?)</ciphertext>`).FindStringSubmatch(res.String())
	if len(m) < 2 {
		return fmt.Errorf("189 app: 合并登录失败: %s", truncate(res.String(), 200))
	}
	decrypted, err := aesCBCDecryptB64(strings.TrimSpace(m[1]), key, []byte(APP_LOGIN_AES_IV))
	if err != nil {
		return err
	}
	xmlText, err := url.QueryUnescape(decrypted)
	if err != nil {
		return err
	}
	var us appUserSessionResp
	if err = xml.Unmarshal([]byte(xmlText), &us); err != nil {
		return err
	}
	if us.SessionKey == "" {
		return fmt.Errorf("189 app: 响应里没有 sessionKey")
	}
	y.tokenInfo.UserSessionResp = UserSessionResp{
		LoginName:           us.LoginName,
		SessionKey:          us.SessionKey,
		SessionSecret:       us.SessionSecret,
		FamilySessionKey:    us.FamilySessionKey,
		FamilySessionSecret: us.FamilySessionSecret,
	}
	if us.EAccessToken != "" {
		y.tokenInfo.AccessToken = us.EAccessToken
		y.updateValue(&y.AccessToken, us.EAccessToken)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
