package main

import (
	"net/http"

	"github.com/bmizerany/pat"
	"github.com/justinas/alice"
)

func (app *application) routes() http.Handler {
	standardMiddleWare := alice.New(app.recoverPanic, app.logRequest, secureHeaders)
	dynamicMiddleWare := alice.New(app.session.Enable, noSurf, app.authenticate)

	mux := pat.New()
	mux.Get("/", dynamicMiddleWare.ThenFunc(app.home))

	mux.Get("/snippet/create", dynamicMiddleWare.Append(app.requireAuthenticatedUser).ThenFunc(app.createSnippetForm))
	mux.Post("/snippet/create", dynamicMiddleWare.Append(app.requireAuthenticatedUser).ThenFunc(app.createSnippet))
	mux.Get("/snippets/:id", dynamicMiddleWare.ThenFunc(app.showSnippet))

	mux.Get("/users/signup", dynamicMiddleWare.ThenFunc(app.signupUserForm))
	mux.Post("/users/signup", dynamicMiddleWare.ThenFunc(app.signupUser))
	mux.Get("/users/login", dynamicMiddleWare.ThenFunc(app.loginUserForm))
	mux.Post("/users/login", dynamicMiddleWare.ThenFunc(app.loginUser))
	mux.Post("/users/logout", dynamicMiddleWare.ThenFunc(app.logoutUser))

	fileServer := http.FileServer(http.Dir("./ui/static"))
	mux.Get("/static/", http.StripPrefix("/static", fileServer))

	return standardMiddleWare.Then(mux)
}
