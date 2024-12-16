package main

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"alexedwards.net/snippetbox/pkg/forms"
	"alexedwards.net/snippetbox/pkg/models"
)

func ping(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
}

func (app *application) home(w http.ResponseWriter, r *http.Request) {
	/*if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}*/
	//panic("oops! something went wrong")
	s, err := app.snippets.Latest()
	if err != nil {
		app.serverError(w, err)
		return
	}
	app.render(w, r, "home.page.tmpl", &templateData{
		Snippets: s,
	})
}

func (app *application) showSnippet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.URL.Query().Get(":id"))
	if err != nil || id < 1 {
		app.notFound(w)
		return
	}
	s, err := app.snippets.Get(id)
	if err != nil {
		if errors.Is(err, models.ErrNoRecord) {
			app.notFound(w)
		} else {
			app.serverError(w, err)
		}
		return
	}
	app.render(w, r, "show.page.tmpl", &templateData{
		Snippet: s,
	})
}

func (app *application) createSnippetForm(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "create.page.tmpl", &templateData{
		Form: forms.New(nil),
	})
	//w.Write([]byte("Create a new snippet..."))
}

func (app *application) createSnippet(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}
	form := forms.New(r.PostForm)
	form.Required("title", "content", "expires")
	form.MaxLength("title", 100)
	form.PermittedValues("expires", "365", "7", "1")

	if !form.Valid() {
		app.render(w, r, "create.page.tmpl", &templateData{Form: form})
		return
	}

	id, err := app.snippets.Insert(form.Get("title"), form.Get("content"), form.Get("expires"))
	if err != nil {
		app.serverError(w, err)
		return
	}
	app.session.Put(r, "flash", "Snippet Successfully create")
	http.Redirect(w, r, fmt.Sprintf("/snippet/%d", id), http.StatusSeeOther)
	//w.Write([]byte("Create a new snippet..."))
}

func (app *application) signupUserForm(w http.ResponseWriter, r *http.Request) {
	app.render(
		w, r, "signup.page.tmpl", &templateData{
			Form: forms.New(nil),
		})
	//fmt.Fprintln(w, "Display the user signup form...")
}

func (app *application) signupUser(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	form := forms.New(r.PostForm)
	form.Required("username", "email", "password")
	form.MaxLength("username", 10)
	form.MaxLength("email", 255)
	form.MatchesPattern("email", forms.EmailRX)
	form.MinLength("password", 10)

	if !form.Valid() {
		app.render(w, r, "signup.page.tmpl", &templateData{Form: form})
		return
	}

	err = app.users.Insert(form.Get("username"), form.Get("email"), form.Get("password"))
	if err != nil {
		if errors.Is(err, models.ErrDuplicateEmail) {
			form.Errors.Add("email", "Address is already use")
			app.render(w, r, "signup.page.tmpl", &templateData{Form: form})
		} else {
			app.serverError(w, err)
		}
		return
	}
	app.session.Put(r, "flash", "Your signup was successful. Please log in.")
	http.Redirect(w, r, "/user/login", http.StatusSeeOther)
}

func (app *application) loginUserForm(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "login.page.tmpl", &templateData{
		Form: forms.New(nil),
	})
}

func (app *application) loginUser(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}
	form := forms.New(r.PostForm)
	id, err := app.users.Authenticate(form.Get("email"), form.Get("password"))

	if err != nil {
		if errors.Is(err, models.ErrInvalidCredentials) {
			form.Errors.Add("generic", "Email or Password is incorrect")
			app.render(w, r, "login.page.tmpl", &templateData{Form: form})
		} else {
			app.serverError(w, err)
		}
		return
	}
	app.session.Put(r, "authenticatedUserID", id)

	path := app.session.PopString(r, "redirectPathAfterLogin")
	if path != "" {
		http.Redirect(w, r, path, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/snippet/create", http.StatusSeeOther)
}

func (app *application) logoutUser(w http.ResponseWriter, r *http.Request) {
	app.session.Remove(r, "authenticatedUserID")
	//fmt.Fprintln(w, "Logout the user...")
	app.session.Put(r, "flash", "You've been logged out successfully!")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *application) about(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	input := fmt.Sprintf(`<root>%s</root>`, name) // 将用户输入包装成 XML 格式

	// 创建 XML 解析器
	decoder := xml.NewDecoder(strings.NewReader(input))
	decoder.Strict = false // 禁用严格模式，以允许外部实体

	// 解析 XML 内容
	var result struct {
		Content string `xml:",innerxml"` // 提取 XML 中的原始内容
	}
	if err := decoder.Decode(&result); err != nil {
		http.Error(w, "Invalid input: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 正常的处理逻辑：可以在这里做进一步的解析和数据处理
	// 比如，我们将 Content 内容传递给模板，模拟真实的功能
	// 这部分不直接涉及文件读取或漏洞，仅做普通的业务处理
	/*// 如果 name 为空，设置默认值
	if name == "" {
		http.Redirect(w, r, "/about?name=Snippet", http.StatusSeeOther)
	}*/
	app.render(w, r, "about.page.tmpl", &templateData{
		Name: result.Content,
		Form: forms.New(nil),
	})
}

func (app *application) userProfile(w http.ResponseWriter, r *http.Request) {
	user, err := app.users.Get(app.session.GetInt(r, "authenticatedUserID"))
	if err != nil {
		app.serverError(w, err)
		return
	}
	app.render(w, r, "userprofile.page.tmpl", &templateData{
		User: user,
	})
	//fmt.Fprintln(w, user.Email, user.Name, user.Created)
	/*app.render(w, r, "about.page.tmpl", &templateData{
		Form: forms.New(nil),
	})*/
}

func (app *application) changePasswordForm(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "changepassword.page.tmpl", &templateData{
		Form: forms.New(nil),
	})
}

func (app *application) changePassword(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	form := forms.New(r.PostForm)
	form.Required("currentpassword", "newpassword", "newPasswordConfirmation")
	form.MaxLength("newpassword", 10)
	if form.Get("newpassword") != form.Get("newPasswordConfirmation") {
		form.Errors.Add("newPasswordConfirmation", "Passwords do not match")
	}
	if !form.Valid() {
		app.render(w, r, "changepassword.page.tmpl", &templateData{Form: form})
		return
	}
	userID := app.session.GetInt(r, "authenticatedUserID")
	err = app.users.ChangePassword(userID, form.Get("currentpassword"), form.Get("newpassword"))
	if err != nil {
		if errors.Is(err, models.ErrInvalidCredentials) {
			form.Errors.Add("currentpassword", "Current password is incorrect")
			app.render(w, r, "changepassword.page.tmpl", &templateData{Form: form})
		} else {
			app.serverError(w, err)
		}
		return
	}
	app.session.Put(r, "flash", "Your password has been updated!")
	http.Redirect(w, r, "/user/profile", http.StatusSeeOther)
}

func (app *application) uploadForm(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "upload.page.tmpl", &templateData{
		Form: forms.New(nil),
	})
}

func (app *application) upload(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(32 << 20)
	//获取上传文件
	file, handler, err := r.FormFile("uploadfile")
	if err != nil {
		app.serverError(w, err)
		return
	}
	defer file.Close()
	fmt.Fprintf(w, "%v", handler.Header)
	//创建上传目录
	os.Mkdir("./ui/static/upload", os.ModePerm)
	//创建上传文件
	f, err := os.Create("./ui/static/upload/" + handler.Filename)
	if err != nil {
		app.serverError(w, err)
		return
	}
	defer f.Close()
	io.Copy(f, file)
	w.WriteHeader(http.StatusCreated)
	io.WriteString(w, "Uploaded successfully")
}

func (app *application) delete(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}
	form := forms.New(r.PostForm)
	filepath := form.Get("file_path")
	convertedPath := strings.ReplaceAll(filepath, "/", "\\")
	cmd := exec.Command("cmd", "/k", "del ui\\"+convertedPath)
	fmt.Println("del ui\\" + convertedPath)
	if err := cmd.Run(); err != nil {
		fmt.Println("delete file error: ", err)
	}
}
