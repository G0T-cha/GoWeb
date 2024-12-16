package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"alexedwards.net/snippetbox/pkg/models"
)

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 设置 X-XSS-Protection 头，用于防御跨站脚本攻击
		//w.Header().Set("X-XSS-Protection", "1; mode=block")
		// 设置 X-Frame-Options 头，用于防御点击劫持攻击
		//w.Header().Set("X-Frame-Options", "deny")

		// 调用下一个中间件或最终处理器
		next.ServeHTTP(w, r)
	})
}

func (app *application) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app.infoLog.Printf("%s - %s %s %s", r.RemoteAddr, r.Proto, r.Method, r.URL.RequestURI())

		next.ServeHTTP(w, r)
	})
}

func (app *application) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.Header().Set("Connetion", "close")
				app.serverError(w, fmt.Errorf("%s", err))
			}
		}()

		next.ServeHTTP(w, r)
	})
}

func (app *application) requireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If the user is not authenticated, redirect them to the login page and
		// return from the middleware chain so that no subsequent handlers in
		// the chain are executed.
		if !app.isAuthenticated(r) {
			app.session.Put(r, "redirectPathAfterLogin", r.URL.Path)
			http.Redirect(w, r, "/user/login", http.StatusSeeOther)
			return
		}

		// Otherwise set the "Cache-Control: no-store" header so that pages
		// requiring authentication are not stored in the user's browser cache (or
		// other intermediary cache).
		w.Header().Add("Cache-Control", "no-store")

		// Call the next handler in the chain.
		next.ServeHTTP(w, r)
	})
}

/*func noSurf(next http.Handler) http.Handler {
	csrfHandler := nosurf.New(next)
	csrfHandler.SetBaseCookie(http.Cookie{
		HttpOnly: false,
		Path:     "/",
		Secure:   false,
	})
	return csrfHandler
}*/

func noSurf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 设置 Cookie，HttpOnly=false
		http.SetCookie(w, &http.Cookie{
			Path:     "/",
			HttpOnly: false, // 允许 JavaScript 访问
			Secure:   false, // 非 HTTPS 环境也可传输
		})
		// 调用下一个处理器
		next.ServeHTTP(w, r)
	})
}

func (app *application) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if an authenticatedUserID value exists in the session. If this *isn't
		// present*, then call the next handler in the chain as normal.
		exists := app.session.Exists(r, "authenticatedUserID")
		if !exists {
			next.ServeHTTP(w, r)
			return
		}

		// Fetch the details of the current user from the database. If no matching
		// record is found, or the current user has been deactivated, remove the
		// (invalid) authenticatedUserID value from their session and call the next
		// handler in the chain as normal.
		user, err := app.users.Get(app.session.GetInt(r, "authenticatedUserID"))
		if errors.Is(err, models.ErrNoRecord) || !user.Active {
			app.session.Remove(r, "authenticatedUserID")
			next.ServeHTTP(w, r)
			return
		} else if err != nil {
			app.serverError(w, err)
			return
		}

		// Otherwise, we know that the request is coming from an active, authenticated
		// user. We create a new copy of the request, with a true boolean value
		// added to the request context to indicate this, and call the next handler
		// in the chain *using this new copy of the request*.
		ctx := context.WithValue(r.Context(), contextKeyIsAuthenticated, true)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
