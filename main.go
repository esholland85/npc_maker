package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/icza/session"
	"github.com/joho/godotenv"
	"github.com/sashabaranov/go-openai"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	fmt.Println("booting up server")
	r := chi.NewRouter()
	charR := chi.NewRouter()
	loginR := chi.NewRouter()
	corsWrapped := middlewareCors(r)
	httpServer := http.Server{
		Addr:    ":8080",
		Handler: corsWrapped,
	}

	godotenv.Load()
	apiCFG := &apiConfig{}
	//apiCfg.secret = os.Getenv("JWT_SECRET")
	apiCFG.gptKey = os.Getenv("alpha_test_gpt_key")
	apiCFG.secret = os.Getenv("JWT_SECRET")
	apiCFG.context_path = "./resources/.context"
	apiCFG.context_mux = &sync.RWMutex{}
	apiCFG.db_path = "./resources/database.json"
	apiCFG.db_mux = &sync.RWMutex{}

	//apiCFG.sendVerificationEmail("urzathran@gmail.com")

	//apiCFG.LoadDB()
	session.Global.Close()
	session.Global = session.NewCookieManagerOptions(session.NewInMemStore(), &session.CookieMngrOptions{AllowHTTP: true})

	r.Mount("/login", loginR)
	r.Mount("/character", charR)
	charR.Get("/", apiCFG.char_input)
	charR.Post("/sheet", apiCFG.char_sheet)
	loginR.Get("/", apiCFG.login_page)
	loginR.Post("/", apiCFG.LoginHandler)
	loginR.Post("/signup", apiCFG.UserHandler)
	//loginR.Post("/", apiCFG.login_page)
	r.Post("/request-verification", apiCFG.RequestVerificationHandler)
	r.Post("/submit-refresh", apiCFG.RefreshToken)
	r.Get("/verify", apiCFG.VerifyEmailHandler)

	fmt.Println("preparing to listen")
	httpServer.ListenAndServe()
}

func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type apiConfig struct {
	gptKey       string
	secret       string
	context_path string
	context_mux  *sync.RWMutex
	db_path      string
	db_mux       *sync.RWMutex
}

type npc_context struct {
	Character_name         string `json:"char_name"`
	Character_race         string `json:"race"`
	Character_gender       string `json:"gender"`
	Character_income       string `json:"income"`
	Town_size              string `json:"size"`
	Technology_level       string `json:"tech"`
	Magic_level            string `json:"mLevel"`
	Character_identity     string `json:"role"`
	Desired_response_style string `json:"response_style"`
	Anachronism_treatment  string `json:"anachronism"`
}

type Character struct {
	Strength      string
	Dexterity     string
	Constitution  string
	Intelligence  string
	Wisdom        string
	Charisma      string
	Name          string
	Gender        string
	Age           string
	Race          string
	Relationships string
	Motivation    string
	Background    string
	Appearance    string
}

type dbStructure struct {
	Users      map[int]User         `json:"users"`
	Auths      map[string]Auth      `json:"auths"`
	Characters map[string]Character `json:"characters"`
}

type User struct {
	Email            string `json:"email"`
	ID               int    `json:"id"`
	Password         string `json:"password"`
	Is_Subscribed    bool   `json:"is_subscribed"`
	Email_Verified   bool   `json:"email_verified"`
	Verification_Key string
}

type Auth struct {
	Token       string    `json:"token"`
	Revoked     bool      `json:"revoked"`
	TimeRevoked time.Time `json:"timerevoked"`
}

func (apiCFG *apiConfig) Load_context() (npc_context, error) {
	apiCFG.context_mux.RLock()
	defer apiCFG.context_mux.RUnlock()
	contents, err := os.ReadFile(apiCFG.context_path)
	if err != nil {
		if os.IsNotExist(err) {

			saveFile, err2 := json.Marshal(npc_context{
				Character_identity:     "None",
				Technology_level:       "None",
				Magic_level:            "None",
				Desired_response_style: "None",
				Anachronism_treatment:  "None",
			})
			if err2 != nil {
				return npc_context{}, nil
			}
			os.WriteFile(apiCFG.context_path, saveFile, os.ModePerm)
			return npc_context{}, err
		}
		fmt.Println(err)
	}

	dbData := npc_context{}

	err = json.Unmarshal([]byte(contents), &dbData)
	if err != nil {
		fmt.Println("Error:", err)
		return npc_context{}, err
	}

	return dbData, nil
}

func construct_message(myContext npc_context) ([]openai.ChatCompletionMessage, error) {
	//consider changing this setup so the passed object is iterable.
	stringSlice := []string{
		myContext.Character_name,
		myContext.Character_race,
		myContext.Character_gender,
		myContext.Character_income,
		myContext.Town_size,
		myContext.Technology_level,
		myContext.Magic_level,
		myContext.Character_identity,
		myContext.Desired_response_style,
		myContext.Anachronism_treatment,
	}

	contextString := strings.Join(stringSlice, " ")

	myMessage := []openai.ChatCompletionMessage{
		{
			Role:    openai.ChatMessageRoleSystem,
			Content: contextString,
		},
		{
			Role: openai.ChatMessageRoleSystem,
			Content: "Please format information as follows:\n" +
				"Strength: \n" +
				"Dexterity: \n" +
				"Constitution: \n" +
				"Intelligence: \n" +
				"Wisdom: \n" +
				"Charisma: \n" +
				"Name: \n" +
				"Gender: \n" +
				"Age: \n" +
				"Race: \n" +
				"Relationships: \n" +
				"Motivation: \n" +
				"Background: \n" +
				"Appearance: ",
		},
		{
			Role: openai.ChatMessageRoleUser,
			Content: `Please generate information for the following questions:\n
			What is the character's Strength?\n
			What is the character's Dexterity?\n
			What is the character's Constitution?\n
			What is the character's Intelligence?\n
			What is the character's Wisdom?\n
			What is the character's Charisma?\n
			What is the character's Name?\n
			What is the character's Gender?\n
			What is the character's Age?\n
			What is the character's Race?
			Tell me about the character's Relationships.\n
			What motivates the character?\n
			Describe the character's Background.\n
			Please provide details about the character's Appearance.`,
		},
	}

	return myMessage, nil
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type internalError struct {
		Error string `json:"error"`
	}

	errorResponse := internalError{
		Error: msg,
	}

	dat, err := json.Marshal(errorResponse)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	dat, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func respondWithHTML(w http.ResponseWriter, code int, payload string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	w.Write([]byte(payload))
}

func (apiCFG *apiConfig) gen_background(w http.ResponseWriter, r *http.Request) (string, error) {
	myContext, err := apiCFG.Load_context()
	if err != nil {
		return "", nil
	}

	//when you change here, you also have to change the internal string slice at construct message.
	if r.FormValue("fname") != "" {
		myContext.Character_name = "The character's name is " + r.FormValue("fname") + "."
	} else {
		myContext.Character_name = "Please pick a name appropriate to the technology level and the character's background."
	}
	if r.FormValue("race") != "" {
		myContext.Character_race = "The character's race is " + r.FormValue("race") + "."
	} else {
		myContext.Character_race = "The character's race is human."
	}
	if r.FormValue("gender") != "" {
		myContext.Character_gender = "The character's gender is " + r.FormValue("gender") + "."
	} else {
		myContext.Character_gender = "Please pick a gender for the character."
	}
	if r.FormValue("income") != "Random" {
		myContext.Character_income = "The character's income level is " + r.FormValue("income") + "."
	} else {
		myContext.Character_income = "Please pick an income level for the character."
	}
	if r.FormValue("size") != "Random" {
		myContext.Town_size = "The character lives in a town of " + r.FormValue("size") + " people."
	} else {
		myContext.Town_size = "Randomly choose how big a town the character is from."
	}
	if r.FormValue("tech") != "Random" {
		myContext.Technology_level = "The current technology level is " + r.FormValue("tech") + "."
	} else {
		myContext.Technology_level = "Randomly choose what technological age the world is in."
	}
	if r.FormValue("mLevel") != "Random" {
		myContext.Magic_level = "Magic is " + r.FormValue("mLevel") + " in this world."
	} else {
		myContext.Magic_level = "On a scale from 0-100 where zero is no magic at all and 100 is magic is used for every-day tasks, randomly select how accessible magic is in this world."
	}
	if r.FormValue("role") != "" {
		myContext.Character_identity = "The character's role in society is as follows: " + r.FormValue("role")
	} else {
		myContext.Character_identity = "Please choose an appropriate background and role in society given the town the character is in and the technology level of this world."
	}

	myMessage, err := construct_message(myContext)
	if err != nil {
		return "", err
	}
	client := openai.NewClient(apiCFG.gptKey)
	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model:    openai.GPT3Dot5Turbo,
			Messages: myMessage,
		},
	)

	if err != nil {
		return "", err
	}

	return resp.Choices[0].Message.Content, nil
}

/*func (apiCFG *apiConfig) auth_page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	sess := session.Get(r)
	if sess != nil {
		fmt.Println("logged in!")
	} else {
		fmt.Println("not logged in")
	}

	http.ServeFile(w, r, "./index.html")
}*/

func (apiCFG *apiConfig) char_input(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	sess := session.Get(r)
	if sess != nil {
		http.ServeFile(w, r, "./index.html")
	} else {
		http.Redirect(w, r, "./login", http.StatusSeeOther)
	}
}

func (apiCFG *apiConfig) char_sheet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	sess := session.Get(r)
	if sess == nil {
		http.Redirect(w, r, "./login", http.StatusSeeOther)
	}
	fmt.Println("Secure session with token")

	response, err := apiCFG.gen_background(w, r)
	if err != nil {
		respondWithError(w, 500, "Internal Server Error")
		fmt.Println("background generation failed")
		return
	}

	split_resp := strings.Split(response, "\n")
	fields := Character{}
	{
		//make a dictionary of terms, check the response for matches
		fields_dict := map[string]string{}
		for _, row := range split_resp {
			split_row := strings.Split(row, ": ")
			if len(split_row) > 1 {
				fields_dict[split_row[0]] = split_row[1]
				if len(split_row) > 2 {
					fmt.Println("Data lost because it contained an extra colon")
				}
			}
		}
		fields = Character{
			Strength:      fields_dict["Strength"],
			Dexterity:     fields_dict["Dexterity"],
			Constitution:  fields_dict["Constitution"],
			Intelligence:  fields_dict["Intelligence"],
			Wisdom:        fields_dict["Wisdom"],
			Charisma:      fields_dict["Charisma"],
			Name:          fields_dict["Name"],
			Gender:        fields_dict["Gender"],
			Age:           fields_dict["Age"],
			Race:          fields_dict["Race"],
			Relationships: fields_dict["Relationships"],
			Motivation:    fields_dict["Motivation"],
			Background:    fields_dict["Background"],
			Appearance:    fields_dict["Appearance"],
		}
	}

	templateFile := "./resources/character.html"
	tmpl, err := template.ParseFiles(templateFile)
	if err != nil {
		respondWithError(w, 500, "Internal Server Error")
		return
	}
	parseTemplate(w, fields, tmpl)
}

func (apiCFG *apiConfig) login_page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	if r.Method == "GET" {
		templateFile := "./login.html"
		tmpl, err := template.ParseFiles((templateFile))
		if err != nil {
			fmt.Println("failed to parse template")
			respondWithError(w, 500, "Internal server error")
			return
		}

		err = tmpl.Execute(w, map[string]interface{}{})
		if err != nil {
			log.Println("Error:", err)
			respondWithError(w, 500, "Internal server error")
			return
		}
	} else {
		apiCFG.LoginHandler(w, r)
	}
}

func parseTemplate(w http.ResponseWriter, data Character, tmpl *template.Template) {
	err := tmpl.Execute(w, data)
	if err != nil {
		fmt.Println("template not executed")
		respondWithError(w, 500, "Internal Server Error")
	}
}

func (apiCFG *apiConfig) LoadDB() (dbStructure, error) {
	apiCFG.db_mux.RLock()
	defer apiCFG.db_mux.RUnlock()
	contents, err := os.ReadFile(apiCFG.db_path)
	if err != nil {
		if os.IsNotExist(err) {

			saveFile, err2 := json.Marshal(dbStructure{
				Users:      map[int]User{},
				Auths:      map[string]Auth{},
				Characters: map[string]Character{},
			})
			if err2 != nil {
				return dbStructure{}, err2
			}
			err3 := os.WriteFile(apiCFG.db_path, saveFile, os.ModePerm)
			if err3 != nil {
				fmt.Println(err3)
			}
			return dbStructure{}, nil
		}
		fmt.Println(err)
	}

	dbData := dbStructure{}

	err = json.Unmarshal([]byte(contents), &dbData)
	if err != nil {
		fmt.Println("Error: ", err)
		return dbStructure{}, err
	}

	return dbData, nil
}

func (apiCFG *apiConfig) SaveDB(currentDB dbStructure) {
	apiCFG.db_mux.Lock()
	defer apiCFG.db_mux.Unlock()
	saveFile, err := json.Marshal(currentDB)
	if err != nil {
		fmt.Println(err)
	}

	os.WriteFile(apiCFG.db_path, saveFile, os.ModePerm)
}

func (apiCFG *apiConfig) NewUser(newUser User) error {
	currentDB, err := apiCFG.LoadDB()
	if err != nil {
		fmt.Println(err)
		return err
	}

	wholeDB, err2 := apiCFG.LoadDB()
	if err2 != nil {
		fmt.Println("failed to load database")
	}
	allUsers := wholeDB.Users
	exists := false

	for _, user := range allUsers {
		if user.Email == newUser.Email {
			exists = true
			break
		}
	}

	if exists {
		err := errors.New("User already exists")
		return err
	}

	currentDB.Users[newUser.ID] = newUser

	apiCFG.SaveDB(currentDB)

	return nil
}

func (apiCFG *apiConfig) UserHandler(w http.ResponseWriter, r *http.Request) {
	wholeDB, err1 := apiCFG.LoadDB()
	if err1 != nil {
		respondWithError(w, http.StatusInternalServerError, "Server experienced an error")
		return
	}
	userCount := len(wholeDB.Users)

	decoder := json.NewDecoder(r.Body)
	params := User{}
	err2 := decoder.Decode(&params)
	if err2 != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		return
	}

	if len(params.Email) == 0 {
		respondWithError(w, 400, "No email detected")
		return
	}
	if len(params.Password) == 0 {
		respondWithError(w, 400, "No password detected")
		return
	}

	isEmail := isEmail(params.Email)
	if !isEmail {
		respondWithError(w, 400, "Not a valid email address")
		return
	}

	hashedPassword, err3 := bcrypt.GenerateFromPassword([]byte(params.Password), 0)
	if err3 != nil {
		fmt.Println("failed to hash password")
		return
	}

	userToSave := User{
		Email:          params.Email,
		ID:             userCount + 1,
		Password:       string(hashedPassword),
		Is_Subscribed:  false,
		Email_Verified: false,
	}

	err4 := apiCFG.NewUser(userToSave)
	if err4 != nil {
		respondWithError(w, 500, err4.Error())
		return
	}

	//not actually an error; templating fits desired use case.
	//update the login page to accept wider feedback, then update this handler
	respondWithError(w, 500, "User created, please log in")
}

func (apiCFG *apiConfig) LoginHandler(w http.ResponseWriter, r *http.Request) {
	m := map[string]interface{}{}

	sess := session.Get(r)
	if sess != nil {
		// Already logged in
		if r.FormValue("Logout") != "" {
			session.Remove(sess, w) // Logout user
			sess = nil
		}
	} else {
		userEmail := r.FormValue("email")
		userPassword := r.FormValue("password")
		isErr := false
		m["UserEmail"] = userEmail
		errMsg := apiCFG.errorMessageHelper(userEmail, userPassword)
		if errMsg == "Email not yet verified" {
			m["InvalidLogin"] = true
			m["NotVerified"] = true
			isErr = true
			m["ErrorMessage"] = errMsg
		} else if errMsg != "" {
			m["InvalidLogin"] = true
			isErr = true
			m["ErrorMessage"] = errMsg
		}

		if !isErr {
			sess = session.NewSessionOptions(&session.SessOptions{
				CAttrs: map[string]interface{}{"email": userEmail},
			})
			session.Add(sess, w)
		}
	}

	if sess != nil {
		m["UserName"] = sess.CAttr("email")
	}

	templateFile := "./login.html"
	tmpl, err := template.ParseFiles((templateFile))
	if err != nil {
		fmt.Println("failed to parse template")
		respondWithError(w, 500, "Internal server error")
		return
	}

	if err := tmpl.Execute(w, m); err != nil {
		log.Println("Error:", err)
		respondWithError(w, 500, "Internal server error")
		return
	}
}

func (apiCFG *apiConfig) errorMessageHelper(userEmail string, userPassword string) string {
	if len(userEmail) == 0 {
		return "No email detected"
	}
	if len(userPassword) == 0 {
		return "No password detected"
	}
	currentUser, err := apiCFG.getUser(userEmail)
	if err != nil {
		return "Email and password combination not found"
	}
	err = bcrypt.CompareHashAndPassword([]byte(currentUser.Password), []byte(userPassword))
	if err != nil {
		return "Email and password combination not found"
	}
	if !currentUser.Email_Verified {
		return "Email not yet verified"
	}
	return ""
}

func (apiCFG *apiConfig) VerifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.URL.Query().Get("token")

	type MyCustomClaims struct {
		jwt.RegisteredClaims
	}

	localFunc := func(token *jwt.Token) (interface{}, error) {
		return []byte(apiCFG.secret), nil
	}

	tokenValid := true
	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, localFunc)
	if err != nil {
		fmt.Println(err)
		errIntro := err.Error()[:18]
		if errIntro == "token is malformed" {
			respondWithError(w, 401, "Unauthorized")
			return
		}
		if !token.Valid {
			tokenValid = false
		} else {
			respondWithError(w, 401, "Unauthorized")
			return
		}
	}

	wholeDB, err := apiCFG.LoadDB()
	if err != nil {
		fmt.Println("Failed to load database")
		respondWithError(w, 500, "Internal server error")
		return
	}
	userID, err := token.Claims.GetSubject()
	if err != nil {
		fmt.Println("Failed to parse token")
		respondWithError(w, 500, "Internal server error")
		return
	}
	intID, err := strconv.Atoi(userID)
	if err != nil {
		fmt.Println("Failed to convert ID to int")
		respondWithError(w, 500, "Internal server error")
		return
	}

	currentUser := wholeDB.Users[intID]
	if currentUser.Email_Verified {
		respondWithError(w, 401, "Already verified, please log in")
		return
	}
	if !tokenValid {
		apiCFG.sendVerificationEmail(currentUser.Email)
		respondWithError(w, 401, "Token expired, new email sent")
		return
	}

	if tokenString != currentUser.Verification_Key {
		fmt.Println("tokens don't match")
		respondWithError(w, 401, "Unauthorized")
		return
	}

	currentUser.Email_Verified = true
	wholeDB.Users[currentUser.ID] = currentUser
	apiCFG.SaveDB(wholeDB)
	respondWithError(w, 500, "email verified, please log in")
}

func (apiCFG *apiConfig) AuthenticateUser(w http.ResponseWriter, r *http.Request) (userID int, isAuthenticated bool) {

	token, err1 := HeaderToToken(r, apiCFG)
	if err1 != nil {
		fmt.Println(err1)
		errIntro := err1.Error()
		if errIntro == "Unauthorized" {
			respondWithError(w, 401, "Unauthorized")
			return 0, false
		}
		respondWithError(w, 500, "Internal Server Error")
		return 0, false
	}

	issuer, err2 := token.Claims.GetIssuer()
	if err2 != nil {
		respondWithError(w, 500, "Internal Server Error")
		return 0, false
	}
	if issuer == "counterpoint-refresh" {
		respondWithError(w, 401, "Unauthorized")
		return 0, false
	}

	stringID, err3 := token.Claims.GetSubject()
	if err3 != nil {
		respondWithError(w, 500, "Internal Server Error")
		return 0, false
	}

	intID, err4 := strconv.Atoi(stringID)
	if err4 != nil {
		respondWithError(w, 500, "Internal Server Error")
		return 0, false
	}

	return intID, true
}

func (apiCFG *apiConfig) RefreshToken(w http.ResponseWriter, r *http.Request) {
	token, err := HeaderToToken(r, apiCFG)
	if err != nil {
		if err.Error() == "Unauthorized" {
			respondWithError(w, 401, "Unathorized")
			return
		}
		respondWithError(w, 500, "Internal Server Error")
		return
	}

	issuer, err2 := token.Claims.GetIssuer()
	if err2 != nil {
		respondWithError(w, 500, "Internal Server Error")
		return
	}
	if issuer != "counterpoint-refresh" {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	wholeDB, err3 := apiCFG.LoadDB()
	if err3 != nil {
		respondWithError(w, 500, "Internal Server Error")
		return
	}
	refreshTokens := wholeDB.Auths
	token_found := false

	for _, dbToken := range refreshTokens {
		if dbToken.Revoked && dbToken.Token == token.Raw {
			respondWithError(w, 401, "Unauthorized")
			return
		}
		if dbToken.Token == token.Raw {
			token_found = true
		}
	}
	if !token_found {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	type ResponseObject struct {
		Token string `json:"token"`
	}

	expiry := jwt.NewNumericDate(time.Now().Add(time.Hour / 12))

	id, err4 := token.Claims.GetSubject()
	if err4 != nil {
		respondWithError(w, 500, "Internal Server Error")
		return
	}

	accessClaim := jwt.RegisteredClaims{
		Issuer:    "counterpoint-access",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: expiry,
		Subject:   id,
	}

	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaim)
	signedAccessToken, err5 := newAccessToken.SignedString([]byte(apiCFG.secret))
	if err5 != nil {
		fmt.Println(err5)
		respondWithError(w, 500, "token signing failed")
		return
	}

	response := ResponseObject{
		Token: signedAccessToken,
	}

	respondWithJSON(w, 200, response)
}

func (apiCFG *apiConfig) RevokeToken(w http.ResponseWriter, r *http.Request) {
	token, err := HeaderToToken(r, apiCFG)
	if err != nil {
		if err.Error() == "Unauthorized" {
			respondWithError(w, 401, "Unathorized")
			return
		}
		respondWithError(w, 500, "Internal Server Error")
		return
	}

	issuer, err2 := token.Claims.GetIssuer()
	if err2 != nil {
		respondWithError(w, 500, "Internal Server Error")
		return
	}
	if issuer == "counterpoint-access" {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	revokedToken := Auth{
		Token:       token.Raw,
		Revoked:     true,
		TimeRevoked: time.Now(),
	}

	wholeDB, err3 := apiCFG.LoadDB()
	if err3 != nil {
		respondWithError(w, 500, "Internal Server Error")
	}
	wholeDB.Auths[token.Raw] = revokedToken
	apiCFG.SaveDB(wholeDB)

	respondWithJSON(w, 200, []byte{})
}

func HeaderToToken(r *http.Request, apiCFG *apiConfig) (*jwt.Token, error) {
	tokenHeader := r.Header.Get("Authorization")
	tokenString := strings.Replace(tokenHeader, "Bearer ", "", 1)

	type MyCustomClaims struct {
		jwt.RegisteredClaims
	}

	localFunc := func(token *jwt.Token) (interface{}, error) {
		return []byte(apiCFG.secret), nil
	}

	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, localFunc)
	if err != nil {
		fmt.Println(err)
		errIntro := err.Error()[:18]
		if errIntro == "token is malformed" {
			return &jwt.Token{}, errors.New("Unauthorized")
		}
		if !token.Valid {
			return &jwt.Token{}, errors.New("Unauthorized")
		} else {
			return &jwt.Token{}, err
		}
	}
	return token, nil
}

func isEmail(input string) bool {
	c := input[0]
	//if it's inside either range for alphabet (i.e., not outside both) good to move on.\
	//also needs to not be a number, but unless I've misunderstood something, this test should preclude that
	if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') {
		return false
	}

	//must contain @
	if !(strings.Contains(input, "@")) {
		return false
	}

	splitInput := strings.Split(input, "@")
	if len(splitInput) != 2 {
		return false
	}

	if !(strings.Contains(splitInput[1], ".")) {
		return false
	}

	splitDomain := strings.Split(splitInput[1], ".")
	for _, i := range splitDomain {
		if len(i) < 1 {
			return false
		}
	}

	lastC := input[len(input)-1]
	if lastC == '.' {
		return false
	}

	return true
}

func (apiCFG *apiConfig) RequestVerificationHandler(w http.ResponseWriter, r *http.Request) {
	userEmail := r.FormValue("email")
	apiCFG.sendVerificationEmail(userEmail)
}

func (apiCFG *apiConfig) sendVerificationEmail(recipientEmail string) {
	//prepare email headers
	var body bytes.Buffer

	mimeHeaders := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	body.Write([]byte(fmt.Sprintf("Subject: Verify your email \n%s\n\n", mimeHeaders)))
	//attach verification info to user account
	currentUser, err := apiCFG.getUser(recipientEmail)
	if err != nil {
		fmt.Println(err)
		return
	}
	if currentUser.Email_Verified {
		fmt.Println("Already verified")
		return
	}

	expiry := jwt.NewNumericDate(time.Now().Add(time.Hour))

	accessClaim := jwt.RegisteredClaims{
		Issuer:    "counterpoint-verify",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: expiry,
		Subject:   strconv.Itoa(currentUser.ID),
	}

	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaim)
	signedAccessToken, err := newAccessToken.SignedString([]byte(apiCFG.secret))
	if err != nil {
		fmt.Println(err)
		fmt.Println("token signing failed")
		return
	}

	currentUser.Verification_Key = signedAccessToken
	wholeDB, err := apiCFG.LoadDB()
	if err != nil {
		fmt.Println("failed to load database")
		return
	}
	wholeDB.Users[currentUser.ID] = currentUser
	apiCFG.SaveDB(wholeDB)

	//plug inputs into template

	tmpl, _ := template.ParseFiles("./resources/verification_email.html")

	inputs := struct {
		Salutation  string
		Destination string
		LinkText    string
		Message     string
	}{
		Salutation:  "Welcome!",
		Destination: "http://localhost:8080/verify?token=" + signedAccessToken,
		LinkText:    "Click here",
		Message:     "to verify your email account.",
	}

	err = tmpl.Execute(&body, inputs)
	if err != nil {
		fmt.Println("Mismatched HMTL and inputs")
		return
	}

	//send compiled message
	sendHtmlEmail(recipientEmail, body.Bytes())
}

func (apiCFG *apiConfig) getUser(userEmail string) (User, error) {
	wholeDB, err := apiCFG.LoadDB()
	if err != nil {
		fmt.Println(err)
		return User{}, err
	}

	//this seems like a very clumsy way to manage users.
	//it's leftover from where I first implemented this code but looking up users by ID
	//when the most common point of interaction is going to be email login
	//seems like it would process badly.
	allUsers := wholeDB.Users

	var currentUser User
	currentUser.ID = 0

	for _, user := range allUsers {
		if user.Email == userEmail {
			currentUser = user
			break
		}
	}

	if currentUser.ID == 0 {
		return currentUser, errors.New("No user found")
	}

	return currentUser, nil
}
