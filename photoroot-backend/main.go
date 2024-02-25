package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// 数据目录
var DATA_DIR = ".data/images"

// 用户信息目录
var USERS_DIR = ".data/users"

// 前端资源目录
var WEBROOT = "webroot"

// 会话持久化保存目录
var SESSIONS_DIR = ".data/sessions"

// 会话过期时间默认一个月
var SessionExpires = 30 * 24 * time.Hour

func WebResponse(w http.ResponseWriter, success bool, data any) {
	jsonData, _ := json.Marshal(map[string]any{
		"success": success,
		"data":    data,
	})
	// 设置响应头部为JSON类型
	w.Header().Set("Content-Type", "application/json")
	// 写入JSON数据到响应
	w.Write(jsonData)
}

type UserInfo struct {
	Name     string `json:"name"`     // 用户名
	Password string `json:"password"` // 密码
}

type UserSession struct {
	SessionId string
	Name      string
	Expires   int64 // session过期时间
}

var user_map = make(map[string]*UserInfo)

var session_map = make(map[string]*UserSession)

func Uuid() string {
	// 创建一个16字节的切片
	b := make([]byte, 16)

	// 从随机源中读取16字节
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("Error:", err)
		return ""
	}

	// 设置UUID版本和变体
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	// 将字节切片转换为UUID格式的字符串并打印
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func GetPathList(paths string, prefix string) []string {
	path := strings.TrimPrefix(paths, prefix)
	return strings.Split(path, "/")
}

// 登录
func login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// 假设认证通过
		type LoginData struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		var data LoginData
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			return
		}
		var usr = user_map[data.Username]
		if usr == nil {
			// 用户不存在
			AuthError(w, r)
		} else {

			if Verify(usr.Password, data.Password) {
				// 认证通过
				var session_id = Uuid()
				// 会话过期时间
				var expires = time.Now().Add(SessionExpires)
				session_map[session_id] = &UserSession{
					SessionId: session_id,
					Name:      data.Username,
					Expires:   expires.Unix(),
				}
				session_save(session_id)
				cookie_session_id := http.Cookie{Name: "session_id", Value: session_id, Expires: expires}
				http.SetCookie(w, &cookie_session_id)
				cookie_username := http.Cookie{Name: "username", Value: data.Username, Expires: expires}
				http.SetCookie(w, &cookie_username)
				WebResponse(w, true, map[string]string{
					"token": session_id,
				})
				return
			} else {
				//认证失败
				AuthError(w, r)
			}
		}

	} else {
		AuthError(w, r)
	}
}

// 登出
func logout(w http.ResponseWriter, r *http.Request) {
	var suc, session = Auth(w, r)
	if !suc {
		return
	}
	delete(session_map, session.SessionId)
	os.Remove(SESSIONS_DIR + "/" + session.SessionId + ".json")
	WebResponse(w, true, "ok")
}

// 修改密码
// /user-password-update
func user_password_update(w http.ResponseWriter, r *http.Request) {
	var suc, session = Auth(w, r)
	if !suc {
		return
	}
	if r.Method != "POST" {
		return
	}
	var oldp = r.PostFormValue("old")
	var newp = r.PostFormValue("new")
	if Verify(user_map[session.Name].Password, oldp) {
		user_map[session.Name].Password = Genpass(newp)
		cache_save(session.Name)
		WebResponse(w, true, "ok")
	} else {
		WebResponse(w, false, "密码验证失败")
	}
}

// 添加用户，仅root账户可以
// /new_user
func new_user(w http.ResponseWriter, r *http.Request) {
	var suc, session = Auth(w, r)
	if !suc {
		return
	}
	if session.Name != "root" {
		return
	}
	if r.Method != "POST" {
		return
	}
	var username = r.PostFormValue("username")
	var password = r.PostFormValue("password")
	if err := AddUser(username, password); err == nil {
		WebResponse(w, true, "ok")
	} else {
		WebResponse(w, false, err.Error())
	}
}

// 查询用户的分组
// /groups
func groups(w http.ResponseWriter, r *http.Request) {
	var suc, session = Auth(w, r)
	if !suc {
		return
	}
	var _dir = DATA_DIR + "/" + session.Name
	entries, err := os.ReadDir(_dir)
	if err != nil {
		// 不存在则新建
		os.MkdirAll(_dir, 0755)
	}
	var res = make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			res = append(res, entry.Name())
		}
	}
	WebResponse(w, true, res)
}

// 用户检测，不存在就创建目录
func user_check(name string) {
	var user_dir = DATA_DIR + "/" + name
	if _, err := os.Stat(user_dir); os.IsNotExist(err) {
		err := os.MkdirAll(user_dir, 0755)
		if err != nil {
			return
		}
	}
}

// 保存缓存
func cache_save(username string) {
	byte, _ := json.MarshalIndent(user_map[username], "", "    ")
	file, err := os.OpenFile(USERS_DIR+"/"+username+".json", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()
	file.Write(byte)
}

// 会话保存
func session_save(session_id string) {
	byte, _ := json.MarshalIndent(session_map[session_id], "", "    ")
	file, err := os.OpenFile(SESSIONS_DIR+"/"+session_id+".json", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()
	file.Write(byte)
}

// 会话加载
func session_load(session_file_name string) {
	content, err := os.ReadFile(SESSIONS_DIR + "/" + session_file_name)
	if err != nil {
		panic(err)
	}
	var session_info UserSession
	if nil != json.Unmarshal(content, &session_info) {
		panic("json parse error " + session_file_name)
	}
	session_map[strings.Split(session_file_name, ".")[0]] = &session_info
}

/*
文件上传
*/
// /upload/{groupname}
func upload(w http.ResponseWriter, r *http.Request) {
	var suc, session = Auth(w, r)
	if !suc {
		return
	}
	user_check(session.Name)

	var groupname = r.PathValue("groupname")

	var work_dir = DATA_DIR + "/" + session.Name + "/" + groupname
	// 文件夹不存在就创建
	if _, err := os.Stat(work_dir); os.IsNotExist(err) {
		err := os.MkdirAll(work_dir, 0755)
		if err != nil {
			return
		}
	}

	err := r.ParseMultipartForm(100 << 20) // 最大100MB
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	files := r.MultipartForm.File["files"]
	for _, file := range files {
		// 从请求中获取文件
		src, err := file.Open()
		if err != nil {
			fmt.Println(err)
			return
		}
		defer src.Close()
		// 创建一个新文件
		dst, err := os.Create(work_dir + "/" + file.Filename)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer dst.Close()
		// 将上传的文件内容复制到新文件中
		_, err = io.Copy(dst, src)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	// 返回上传成功的信息
	WebResponse(w, true, "ok")
}

func AuthError(w http.ResponseWriter, r *http.Request) {
	WebResponse(w, false, "Permission authentication failed")
}

func Auth(w http.ResponseWriter, r *http.Request) (bool, *UserSession) {
	// 需要权限控制的
	// 首先检查token是否存在
	session_id := r.Header.Get("token")
	if session_id == "" {
		// 不存在从cookie里取
		var cookie, err = r.Cookie("session_id")
		if err != nil {
			AuthError(w, r)
			return false, nil
		}
		session_id = cookie.Value
	}
	if session, ok := session_map[session_id]; ok {
		// 校验session是否过期
		if session.Expires < time.Now().Unix() {
			delete(session_map, session_id)
			os.Remove(SESSIONS_DIR + "/" + session_id + ".json")
			return false, nil
		}
		if session == nil {
			// 用户未登录
			AuthError(w, r)
			return false, nil
		} else {
			// 用户已登录
			if strings.HasPrefix(r.URL.Path, "/images/") {
				// 使用images下的资源需要判断权限
				if strings.HasPrefix(r.URL.Path, "/images/"+session.Name+"/") {
					return true, session
				} else {
					// 无权限
					AuthError(w, r)
					return false, nil
				}
			} else {
				// 其余资源有权限
				return true, session
			}
		}
	} else {
		AuthError(w, r)
		return false, nil
	}

}

// 从用户配置文件刷新缓存
func cache_load(user_file_name string) {
	content, err := os.ReadFile(USERS_DIR + "/" + user_file_name)
	if err != nil {
		panic(err)
	}
	var user_info UserInfo
	if nil != json.Unmarshal(content, &user_info) {
		panic("json parse error " + user_file_name)
	}
	user_map[strings.Split(user_file_name, ".")[0]] = &user_info
}

func AddUser(name string, password string) error {
	// 添加用户
	if _, ok := user_map[name]; !ok {
		user_map[name] = &UserInfo{
			Name:     name,
			Password: Genpass(password),
		}
		cache_save(name)
		return nil
	}
	// 用户已经存在
	return errors.New("user exists")
}

func init_work() {
	// 判断webroot目录是否存在，不存在新建
	if _, err := os.Stat(WEBROOT); os.IsNotExist(err) {
		err := os.MkdirAll(WEBROOT, 0755)
		if err != nil {
			return
		}
	}
	// 判断用户目录是否存在，不存在就创建默认的
	if _, err := os.Stat(USERS_DIR); os.IsNotExist(err) {
		err := os.MkdirAll(USERS_DIR, 0755)
		if err != nil {
			return
		}
	}
	f, err := os.Open(USERS_DIR)
	if err != nil {
		fmt.Println("打开目录时出错：", err)
		return
	}
	defer f.Close()
	files, err := f.Readdir(-1)
	if err != nil {
		fmt.Println("读取目录时出错：", err)
		return
	}
	var usefiles []fs.FileInfo
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".json") {
			usefiles = append(usefiles, file)
		}
	}
	if len(usefiles) == 0 {
		// 无任何用户配置，则初始化一个用户
		AddUser("root", "root")
		fmt.Println("初始化用户名: root")
		fmt.Println("初始化密码: root")
	}
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			cache_load(file.Name())
		}
	}
	// 会话目录创建
	if _, err := os.Stat(SESSIONS_DIR); os.IsNotExist(err) {
		err := os.MkdirAll(SESSIONS_DIR, 0755)
		if err != nil {
			return
		}
	}
	// 加载会话
	fsd, err := os.Open(SESSIONS_DIR)
	if err != nil {
		fmt.Println("打开目录时出错：", err)
		return
	}
	defer fsd.Close()
	sfiles, err := fsd.Readdir(-1)
	if err != nil {
		fmt.Println("读取目录时出错：", err)
		return
	}
	var usesfiles []fs.FileInfo
	for _, file := range sfiles {
		if strings.HasSuffix(file.Name(), ".json") {
			usesfiles = append(usesfiles, file)
		}
	}
	if len(usesfiles) != 0 {
		// 加载会话
		for _, fi := range usesfiles {
			session_load(fi.Name())
		}
	}
}

// 定时任务
func Job() {
	var dur = 1 * time.Hour
	t := time.NewTimer(dur)
	for {
		<-t.C
		t.Reset(dur)
		// 把超时的session踢出去
		for k, us := range session_map {
			if us.Expires < time.Now().Unix() {
				// session 超时
				delete(session_map, k)
				os.Remove(SESSIONS_DIR + "/" + k + ".json")
			}
		}
	}
}

func Genpass(passwd string) string {
	// 生成哈希密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(passwd), bcrypt.DefaultCost)
	if err != nil {
		return ""
	}
	return string(hashedPassword)
}

func Verify(hashedPassword string, enteredPassword string) bool {
	// 验证密码
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(enteredPassword))
	if err == nil {
		return true
	} else {
		return false
	}
}

func main() {
	var bind, passwd string
	var genpass bool
	flag.BoolVar(&genpass, "genpass", false, "生成hash密码")
	flag.StringVar(&passwd, "gen-password", "images", "需要加密的密码")
	flag.StringVar(&USERS_DIR, "users", ".data/users", "用户信息存档目录")
	flag.StringVar(&DATA_DIR, "data", ".data/images", "文档存储目录")
	flag.StringVar(&bind, "bind", "127.0.0.1:11990", "绑定host与端口信息")
	flag.StringVar(&SESSIONS_DIR, "sessions", ".data/sessions", "会话持久化目录")
	flag.StringVar(&WEBROOT, "webroot", "webroot", "前端目录")
	flag.Parse()

	if genpass {
		p := Genpass(passwd)
		fmt.Println(p)
		return
	}

	init_work()
	go Job()
	// 设置路由
	http.Handle("/", http.FileServer(http.Dir(WEBROOT)))
	http.HandleFunc("/upload/{groupname}", upload)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/user-password-update", user_password_update)
	http.HandleFunc("/new-user", new_user)
	http.HandleFunc("/groups", groups)

	server := http.Server{Addr: bind}
	fmt.Println("浏览器地址：http://" + bind)
	server.ListenAndServe()
}
