package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	gsm "github.com/bradleypeabody/gorilla-sessions-memcache"
	"github.com/go-chi/chi/v5"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
	"github.com/samber/lo"
)

var (
	db    *sqlx.DB
	store *gsm.MemcacheStore

	fmap = template.FuncMap{
		"imageURL": imageURL,
	}
)

const (
	postsPerPage  = 20
	ISO8601Format = "2006-01-02T15:04:05-07:00"
	UploadLimit   = 10 * 1024 * 1024 // 10mb
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int       `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
}

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	CommentCount int       `db:"comment_count"`
	Comments     []Comment
	User         User
	CSRFToken    string
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	Freshness int       `db:"freshness"`
	User      User
}

type PostHTML struct {
	PostID              int    `db:"post_id"`
	UserID              int    `db:"user_id"`
	HTML                string `db:"html"`
	HTMLWithAllComments string `db:"html_with_all_comments"`
}

var CSRFTokenPlaceholder = "{{.CSRFToken}}"

func prerenderPostHTML(postID int) error {
	var rawPost Post
	err := db.Get(&rawPost, "SELECT `id`, `user_id`, `body`, `mime`, `created_at`, `comment_count` FROM `posts` WHERE `id` = ?", postID)
	if err != nil {
		return err
	}

	posts, err := makePosts([]Post{rawPost}, CSRFTokenPlaceholder, true)
	if err != nil {
		return err
	}

	if len(posts) == 0 {
		return nil
	}
	post := posts[0]

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}
	tmpl := template.Must(template.New("post.html").Funcs(fmap).ParseFiles(
		getTemplPath("post.html"),
	))

	var htmlBuf, htmlWithAllCommentsBuf bytes.Buffer
	err = tmpl.Execute(&htmlWithAllCommentsBuf, post)
	if err != nil {
		return err
	}

	post.Comments = post.Comments[:int(math.Min(3, float64(len(post.Comments))))]
	err = tmpl.Execute(&htmlBuf, post)
	if err != nil {
		return err
	}

	_, err = db.Exec("INSERT INTO `post_htmls` (`post_id`, `user_id`, `html`, `html_with_all_comments`) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE `html` = ?, `html_with_all_comments` = ?", post.ID, post.UserID, htmlBuf.String(), htmlWithAllCommentsBuf.String(), htmlBuf.String(), htmlWithAllCommentsBuf.String())
	if err != nil {
		return err
	}

	return nil
}

func init() {
	memdAddr := os.Getenv("ISUCONP_MEMCACHED_ADDRESS")
	if memdAddr == "" {
		memdAddr = "localhost:11211"
	}
	memcacheClient := memcache.New(memdAddr)
	store = gsm.NewMemcacheStore(memcacheClient, "iscogram_", []byte("sendagaya"))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

func dbInitialize() {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}
}

func tryLogin(accountName, password string) *User {
	u := User{}
	err := db.Get(&u, "SELECT * FROM users WHERE account_name = ? AND del_flg = 0", accountName)
	if err != nil {
		return nil
	}

	if calculatePasshash(u.AccountName, password) == u.Passhash {
		return &u
	} else {
		return nil
	}
}

func validateUser(accountName, password string) bool {
	return regexp.MustCompile(`\A[0-9a-zA-Z_]{3,}\z`).MatchString(accountName) &&
		regexp.MustCompile(`\A[0-9a-zA-Z_]{6,}\z`).MatchString(password)
}

func digest(src string) string {
	h := sha512.New()
	h.Write([]byte(src))
	return hex.EncodeToString(h.Sum(nil))
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isuconp-go.session")

	return session
}

func getSessionUser(r *http.Request) User {
	session := getSession(r)
	uid, ok := session.Values["user_id"]
	if !ok || uid == nil {
		return User{}
	}

	u := User{}

	err := db.Get(&u, "SELECT * FROM `users` WHERE `id` = ?", uid)
	if err != nil {
		return User{}
	}

	return u
}

func getFlash(w http.ResponseWriter, r *http.Request, key string) string {
	session := getSession(r)
	value, ok := session.Values[key]

	if !ok || value == nil {
		return ""
	} else {
		delete(session.Values, key)
		session.Save(r, w)
		return value.(string)
	}
}

func makePosts(results []Post, csrfToken string, allComments bool) ([]Post, error) {
	var posts []Post

	// Post.User 取得, 削除済みユーザーは除外, ページあたりの件数で絞り込み
	{
		var users []User
		userIDs := lo.Map(results, func(p Post, _ int) int { return p.UserID })
		q, args, err := sqlx.In("SELECT * FROM `users` WHERE `id` IN (?)", userIDs)
		if err != nil {
			return nil, err
		}
		err = db.Select(&users, q, args...)
		if err != nil {
			return nil, err
		}
		userByID := lo.KeyBy(users, func(u User) int { return u.ID })
		for _, p := range results {
			p.User = userByID[p.UserID]
			if p.User.DelFlg == 0 {
				posts = append(posts, p)
			}
			if len(posts) >= postsPerPage {
				break
			}
		}
	}

	if len(posts) == 0 {
		return posts, nil
	}

	postIDs := lo.Map(posts, func(p Post, _ int) int { return p.ID })

	// Post.Comments 取得
	var comments []Comment
	{
		q := "SELECT * FROM `comments` WHERE `post_id` IN (?) AND `freshness` < 3 ORDER BY `created_at` DESC"
		if allComments {
			q = "SELECT * FROM `comments` WHERE `post_id` IN (?) ORDER BY `created_at` DESC"
		}
		q, args, err := sqlx.In(q, postIDs)
		if err != nil {
			return nil, err
		}
		err = db.Select(&comments, q, args...)
		if err != nil {
			return nil, err
		}

		// Comment.User 取得
		if len(comments) > 0 {
			userIDs := lo.Map(comments, func(c Comment, _ int) int { return c.UserID })
			var users []User
			q, args, err := sqlx.In("SELECT * FROM `users` WHERE `id` IN (?)", userIDs)
			if err != nil {
				return nil, err
			}
			err = db.Select(&users, q, args...)
			if err != nil {
				return nil, err
			}
			userByUserID := lo.KeyBy(users, func(u User) int { return u.ID })
			for _, c := range comments {
				c.User = userByUserID[c.UserID]
			}
		}
	}

	commentsByPostID := lo.GroupBy(comments, func(c Comment) int { return c.PostID })

	for i, p := range posts {
		p.Comments = commentsByPostID[p.ID]
		p.CSRFToken = csrfToken
		posts[i] = p
	}

	return posts, nil
}

func imageURL(p Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
}

func isLogin(u User) bool {
	return u.ID != 0
}

func getCSRFToken(r *http.Request) string {
	session := getSession(r)
	csrfToken, ok := session.Values["csrf_token"]
	if !ok {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := crand.Read(k); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(w http.ResponseWriter, r *http.Request) {
	dbInitialize()
	w.WriteHeader(http.StatusOK)
}

func getLogin(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	if isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("login.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{me, getFlash(w, r, "notice")})
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.FormValue("account_name"), r.FormValue("password"))

	if u != nil {
		session := getSession(r)
		session.Values["user_id"] = u.ID
		session.Values["csrf_token"] = secureRandomStr(16)
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values["notice"] = "アカウント名かパスワードが間違っています"
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("register.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{User{}, getFlash(w, r, "notice")})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(r)
		session.Values["notice"] = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.Get(&exists, "SELECT 1 FROM users WHERE `account_name` = ?", accountName)

	if exists == 1 {
		session := getSession(r)
		session.Values["notice"] = "アカウント名がすでに使われています"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	query := "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)"
	result, err := db.Exec(query, accountName, calculatePasshash(accountName, password))
	if err != nil {
		log.Print(err)
		return
	}

	session := getSession(r)
	uid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}
	session.Values["user_id"] = uid
	session.Values["csrf_token"] = secureRandomStr(16)
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

var getIndexTmpl = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("index.html"),
))

func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	postHTMLs := []PostHTML{}

	err := db.Select(
		&postHTMLs,
		"SELECT `post_htmls`.`html` FROM `posts` FORCE INDEX (`created_at`) INNER JOIN `users` FORCE INDEX (`idx_id_del_flg`) ON `users`.`id` = `posts`.`user_id` AND `users`.`del_flg` = 0 INNER JOIN `post_htmls` ON `post_htmls`.`post_id` = `posts`.`id` ORDER BY `posts`.`created_at` DESC LIMIT ?",
		postsPerPage,
	)
	if err != nil {
		log.Print(err)
		return
	}

	var buf bytes.Buffer
	buf.WriteString(`<div class="isu-posts">`)
	for _, p := range postHTMLs {
		buf.WriteString(p.HTML)
	}
	buf.WriteString(`</div>`)

	postsHTML := strings.ReplaceAll(buf.String(), CSRFTokenPlaceholder, getCSRFToken(r))

	var buf2 bytes.Buffer
	err = getIndexTmpl.Execute(&buf2, struct {
		Me        User
		CSRFToken string
		PostsHTML string
		Flash     string
	}{me, getCSRFToken(r), "{{.PostsHTML}}", getFlash(w, r, "notice")})
	if err != nil {
		log.Print(err)
		return
	}

	w.Write([]byte(strings.ReplaceAll(buf2.String(), "{{.PostsHTML}}", postsHTML)))
}

var getAccountTmpl = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("user.html"),
))

func getAccountName(w http.ResponseWriter, r *http.Request) {
	accountName := chi.URLParam(r, "accountName")
	user := User{}

	err := db.Get(&user, "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0", accountName)
	if err != nil {
		log.Print(err)
		return
	}

	if user.ID == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	postHTMLs := []PostHTML{}

	err = db.Select(&postHTMLs, "SELECT `html` FROM `posts` INNER JOIN `post_htmls` ON `posts`.`id` = `post_htmls`.`post_id` WHERE `posts`.`user_id` = ? ORDER BY `created_at` DESC", user.ID)
	if err != nil {
		log.Print(err)
		return
	}

	var buf bytes.Buffer
	buf.WriteString(`<div class="isu-posts">`)
	for _, p := range postHTMLs {
		buf.WriteString(p.HTML)
	}
	buf.WriteString(`</div>`)

	commentCount := 0
	err = db.Get(&commentCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}

	postIDs := []int{}
	err = db.Select(&postIDs, "SELECT `id` FROM `posts` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}
	postCount := len(postIDs)

	commentedCount := 0
	if postCount > 0 {
		s := []string{}
		for range postIDs {
			s = append(s, "?")
		}
		placeholder := strings.Join(s, ", ")

		// convert []int -> []interface{}
		args := make([]interface{}, len(postIDs))
		for i, v := range postIDs {
			args[i] = v
		}

		err = db.Get(&commentedCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `post_id` IN ("+placeholder+")", args...)
		if err != nil {
			log.Print(err)
			return
		}
	}

	me := getSessionUser(r)

	var buf2 bytes.Buffer

	err = getAccountTmpl.Execute(&buf2, struct {
		CSRFToken      string
		User           User
		PostCount      int
		CommentCount   int
		CommentedCount int
		Me             User
		PostsHTML      string
	}{getCSRFToken(r), user, postCount, commentCount, commentedCount, me, "{{.PostsHTML}}"})
	if err != nil {
		log.Print(err)
		return
	}

	html := strings.ReplaceAll(buf2.String(), "{{.PostsHTML}}", strings.ReplaceAll(buf.String(), CSRFTokenPlaceholder, getCSRFToken(r)))
	w.Write([]byte(html))
}

func getPosts(w http.ResponseWriter, r *http.Request) {
	m, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Print(err)
		return
	}
	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}

	t, err := time.Parse(ISO8601Format, maxCreatedAt)
	if err != nil {
		log.Print(err)
		return
	}

	postHTMLs := []PostHTML{}
	err = db.Select(
		&postHTMLs,
		"SELECT `html` FROM `posts` FORCE IDNEX (`created_at`) INNER JOIN `users` FORCE INDEX (`idx_id_del_flg`) ON `users`.`id` = `posts`.`user_id` AND `users`.`del_flg` = 0 INNER JOIN `post_htmls` ON `posts`.`id` = `post_htmls`.`post_id` WHERE `posts`.`created_at` <= ? ORDER BY `posts`.`created_at` DESC LIMIT ?",
		t.Format(ISO8601Format), postsPerPage,
	)
	if err != nil {
		log.Print(err)
		return
	}

	if len(postHTMLs) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var buf bytes.Buffer
	buf.WriteString(`<div class="isu-posts">`)
	for _, p := range postHTMLs {
		buf.WriteString(p.HTML)
	}
	buf.WriteString(`</div>`)

	html := strings.ReplaceAll(buf.String(), CSRFTokenPlaceholder, getCSRFToken(r))

	w.Write([]byte(html))
}

var getPostsIDTmpl = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("post_id.html"),
))

func getPostsID(w http.ResponseWriter, r *http.Request) {
	pidStr := chi.URLParam(r, "id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var postHTML PostHTML
	err = db.Get(&postHTML, "SELECT `post_htmls`.`html_with_all_comments` FROM `post_htmls` INNER JOIN `users` ON `users`.`id` = `post_htmls`.`user_id` WHERE `post_id` = ? AND `del_flg` = 0", pid)
	if err != nil {
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		log.Print(err)
		return
	}

	me := getSessionUser(r)

	var buf bytes.Buffer

	err = getPostsIDTmpl.Execute(&buf, struct {
		CSRFToken string
		Me        User
		PostsHTML string
	}{getCSRFToken(r), me, "{{.PostsHTML}}"})
	if err != nil {
		log.Print(err)
		return
	}

	html := strings.ReplaceAll(buf.String(), "{{.PostsHTML}}", postHTML.HTMLWithAllComments)
	w.Write([]byte(html))
}

func postIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		session := getSession(r)
		session.Values["notice"] = "画像が必須です"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	mime := ""
	ext := ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := header.Header["Content-Type"][0]
		if strings.Contains(contentType, "jpeg") {
			ext = ".jpg"
			mime = "image/jpeg"
		} else if strings.Contains(contentType, "png") {
			ext = ".png"
			mime = "image/png"
		} else if strings.Contains(contentType, "gif") {
			ext = "gif"
			mime = "image/gif"
		} else {
			session := getSession(r)
			session.Values["notice"] = "投稿できる画像形式はjpgとpngとgifだけです"
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	filedata, err := io.ReadAll(file)
	if err != nil {
		log.Print(err)
		return
	}

	if len(filedata) > UploadLimit {
		session := getSession(r)
		session.Values["notice"] = "ファイルサイズが大きすぎます"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	query := "INSERT INTO `posts` (`user_id`, `mime`, `body`) VALUES (?,?,?)"
	result, err := db.Exec(
		query,
		me.ID,
		mime,
		r.FormValue("body"),
	)
	if err != nil {
		log.Print(err)
		return
	}

	pid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}

	osFile, err := os.OpenFile(
		filepath.Join("../public/image", fmt.Sprintf("%d%s", pid, ext)),
		os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Print(err)
		return
	}
	defer osFile.Close()
	_, err = osFile.Write(filedata)
	if err != nil {
		log.Print(err)
		return
	}

	err = prerenderPostHTML(int(pid))
	if err != nil {
		log.Print(err)
		return
	}

	http.Redirect(w, r, "/posts/"+strconv.FormatInt(pid, 10), http.StatusFound)
}

func postComment(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	postID, err := strconv.Atoi(r.FormValue("post_id"))
	if err != nil {
		log.Print("post_idは整数のみです")
		return
	}

	tx, err := db.Begin()
	if err != nil {
		log.Print(err)
		return
	}
	defer tx.Rollback()

	_, err = tx.Exec("UPDATE `comments` SET `freshness` = `freshness` + 1 WHERE `post_id` = ?", postID)
	if err != nil {
		log.Print(err)
		return
	}

	query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)"
	_, err = tx.Exec(query, postID, me.ID, r.FormValue("comment"))
	if err != nil {
		log.Print(err)
		return
	}

	_, err = tx.Exec("UPDATE `posts` SET `comment_count` = `comment_count` + 1 WHERE `id` = ?", postID)
	if err != nil {
		log.Print(err)
		return
	}

	err = tx.Commit()
	if err != nil {
		log.Print(err)
		return
	}

	err = prerenderPostHTML(postID)
	if err != nil {
		log.Print(err)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

var getAdminBannedTmpl = template.Must(template.ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("banned.html"),
))

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	users := []User{}
	err := db.Select(&users, "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		log.Print(err)
		return
	}

	getAdminBannedTmpl.Execute(w, struct {
		Users     []User
		Me        User
		CSRFToken string
	}{users, me, getCSRFToken(r)})
}

func postAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	query := "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?"

	err := r.ParseForm()
	if err != nil {
		log.Print(err)
		return
	}

	for _, id := range r.Form["uid[]"] {
		db.Exec(query, 1, id)
	}

	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

func main() {
	host := os.Getenv("ISUCONP_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("ISUCONP_DB_PORT")
	if port == "" {
		port = "3306"
	}
	_, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local&interpolateParams=true",
		user,
		password,
		host,
		port,
		dbname,
	)

	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	defer db.Close()

	r := chi.NewRouter()

	r.Get("/initialize", getInitialize)
	r.Get("/login", getLogin)
	r.Post("/login", postLogin)
	r.Get("/register", getRegister)
	r.Post("/register", postRegister)
	r.Get("/logout", getLogout)
	r.Get("/", getIndex)
	r.Get("/posts", getPosts)
	r.Get("/posts/{id}", getPostsID)
	r.Post("/", postIndex)
	r.Post("/comment", postComment)
	r.Get("/admin/banned", getAdminBanned)
	r.Post("/admin/banned", postAdminBanned)
	r.Get(`/@{accountName:[a-zA-Z]+}`, getAccountName)
	r.Post("/exportImages", func(w http.ResponseWriter, r *http.Request) {
		type Post struct {
			ID      int    `db:"id"`
			Mime    string `db:"mime"`
			Imgdata []byte `db:"imgdata"`
		}
		var posts []Post
		err := db.Select(&posts, "SELECT `id`, `mime`, `imgdata` FROM `posts`")
		if err != nil {
			log.Print(err)
			return
		}
		for _, p := range posts {
			ext := ""
			if p.Mime == "image/jpeg" {
				ext = ".jpg"
			} else if p.Mime == "image/png" {
				ext = ".png"
			} else if p.Mime == "image/gif" {
				ext = ".gif"
			}

			osFile, err := os.OpenFile(
				filepath.Join("../public/image", fmt.Sprintf("%d%s", p.ID, ext)),
				os.O_WRONLY|os.O_CREATE, 0644)
			if err != nil {
				log.Print(err)
				return
			}
			defer osFile.Close()
			_, err = osFile.Write(p.Imgdata)
			if err != nil {
				log.Print(err)
				return
			}
		}

		w.WriteHeader(http.StatusOK)
	})
	r.Post("/initializePostHTMLs", func(w http.ResponseWriter, r *http.Request) {
		posts := []Post{}
		err := db.Select(&posts, "SELECT `id` FROM `posts`")
		if err != nil {
			log.Print(err)
			return
		}
		for _, post := range posts {
			err = prerenderPostHTML(post.ID)
			if err != nil {
				log.Print(err)
				return
			}
		}

		w.WriteHeader(http.StatusOK)
	})
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir("../public")).ServeHTTP(w, r)
	})

	go func() {
		log.Println(http.ListenAndServe(":6060", nil))
	}()

	log.Fatal(http.ListenAndServe(":8080", r))
}
