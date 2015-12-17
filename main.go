package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	//"github.com/steveruckdashel/b2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"
	redistore "gopkg.in/boj/redistore.v1"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
)

var Views *template.Template

var OAuth map[string]*oauth2.Config = map[string]*oauth2.Config{
	"google": {
		Endpoint:     google.Endpoint,
		ClientID:     os.Getenv("OAUTH_GOOGLEID"),
		ClientSecret: os.Getenv("OAUTH_GOOGLESECRET"),
		RedirectURL:  "http://localhost:80/auth/google/callback",
		Scopes: []string{
			"https://www.googleapis.com/auth/plus.login",
			"https://www.googleapis.com/auth/userinfo.email",
		},
	},
	"facebook": {
		Endpoint:     facebook.Endpoint,
		ClientID:     os.Getenv("OAUTH_FACEBOOKID"),
		ClientSecret: os.Getenv("OAUTH_FACEBOOKSECRET"),
		RedirectURL:  "http://localhost:80/auth/facebook/callback",
		Scopes: []string{
			"public_profile,email",
		},
	},
}

// randomString returns a random string with the specified length
func randomString(length int) (str string) {
	b := make([]byte, length)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// store initializes the Gorilla session store.
var store sessions.Store

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	var session *sessions.Session
	s, err := store.Get(r, "session-name")
	if err != nil {
		log.Println("error fetching session:", err)
		s, _ := store.New(r, "session-name")
		session = s
	} else {
		session = s
	}
	state := randomString(64)
	session.Values["state"] = state
	session.Save(r, w)

	if err := Views.Lookup("home.ghtml").Execute(w, struct{}{}); err != nil {
		log.Printf("error executing view template: %v", err)
	}
}

func OauthHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	provider := vars["provider"]

	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	urlStr := OAuth[provider].AuthCodeURL(session.Values["state"].(string), oauth2.AccessTypeOnline)
	urlStrUnesc, err := url.QueryUnescape(urlStr)
	if err != nil {
		log.Println(err)
	}
	log.Printf("Visit the URL for the auth dialog: %v", urlStrUnesc)

	http.Redirect(w, r, urlStrUnesc, 302)
}

func OauthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	provider := vars["provider"]

	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// Use the authorization code that is pushed to the redirect URL.
	// NewTransportWithCode will do the handshake to retrieve
	// an access token and initiate a Transport that is
	// authorized and authenticated by the retrieved token.
	code := r.FormValue("code")

	tok, err := OAuth[provider].Exchange(oauth2.NoContext, code)
	if err != nil {
		log.Fatal(err)
	}
	session.Values["token"] = *tok
	session.Values["xoauth_yahoo_guid"] = r.FormValue("xoauth_yahoo_guid")
	session.Save(r, w)

	http.Redirect(w, r, "/", 302)
}

func main() {
	Views = template.New("Home")
	if _, err := Views.ParseGlob("./views/*.ghtml"); err != nil {
		log.Fatalf("invalid view, %v", err)
	}

	port, err := strconv.Atoi(os.Getenv("PORT"))
	if err != nil {
		log.Fatal("Bad port: '%s'", os.Getenv("PORT"))
	}

	store = sessions.NewCookieStore([]byte(randomString(32)))
	if u, err := url.Parse(os.Getenv("REDIS_URL")); err != nil || u.Host == "" {
		store = sessions.NewCookieStore([]byte(randomString(32)))
	} else {
		address := fmt.Sprintf("%s", u.Host)
		pass, _ := u.User.Password()
		// log.Println(address.String())
		if st, e := redistore.NewRediStore(5, "tcp", address, pass); e != nil {
			log.Fatal("Unable to connect to Redis", e)
		} else {
			store = st
			defer st.Close()
		}
	}

	r := mux.NewRouter()
	r.HandleFunc("/", HomeHandler)

	//yapi := yahooapi.NewYahooConfig(clientid, secret, []string{}, "http://limitless-refuge-3809.herokuapp.com", "/", store)
	//yapi.RegisterRoutes(r)
	r.HandleFunc("/auth/{provider:[a-zA-Z\\.]+}", OauthHandler)
	r.HandleFunc("/auth/{provider:[a-zA-Z\\.]+}/callback", OauthCallbackHandler)

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./wwwroot/")))
	http.Handle("/", r)

	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(port), nil))
}
