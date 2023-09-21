package main

import (
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
	"github.com/joho/godotenv"
	"github.com/sashabaranov/go-openai"
	"golang.org/x/crypto/bcrypt"
)

func main() {
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

	//apiCFG.LoadDB()

	r.Mount("/login", loginR)
	r.Mount("/character", charR)
	charR.Get("/", apiCFG.landing_page)
	loginR.Get("/", apiCFG.login_page)
	loginR.Post("/", apiCFG.login_page)
	loginR.Post("/signup", apiCFG.UserHandler)

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
	Character_name         string
	Character_race         string
	Character_gender       string
	Character_income       string
	Town_size              string
	Technology_level       string
	Magic_level            string
	Character_identity     string
	Desired_response_style string
	Anachronism_treatment  string
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
	Email         string `json:"email"`
	ID            int    `json:"id"`
	Password      string `json:"password"`
	Is_Subscribed bool   `json:"is_subscribed"`
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
				"Relationships: ?\n" +
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
	if r.URL.Query().Get("fname") != "" {
		myContext.Character_name = "The character's name is " + r.URL.Query().Get("fname") + "."
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
	if r.FormValue("income") != "" {
		myContext.Character_income = "The character's income level is " + r.FormValue("income") + "."
	} else {
		myContext.Character_income = "Please pick an income level for the character."
	}
	if r.URL.Query().Get("size") != "Random" && r.URL.Query().Get("size") != "" {
		myContext.Town_size = "The character lives in a town of " + r.URL.Query().Get("size") + " people."
	} else if r.URL.Query().Get("size") == "Random" {
		myContext.Town_size = "Randomly choose how big a town the character is from."
	} else {
		fmt.Println("Incompatible size selected")
	}
	if r.URL.Query().Get("tech") != "Random" && r.URL.Query().Get("tech") != "" {
		myContext.Technology_level = "The current technology level is " + r.URL.Query().Get("tech") + "."
	} else if r.URL.Query().Get("tech") == "Random" {
		myContext.Technology_level = "Randomly choose what technological age the world is in."
	} else {
		fmt.Println("Incompatible technology query.")
	}
	if r.FormValue("mLevel") != "Random" {
		myContext.Magic_level = "Magic is " + r.FormValue("mLevel") + " in this world."
	} else {
		myContext.Magic_level = "On a scale from 0-100 where zero is no magic at all and 100 is magic is used for every-day tasks, randomly select how accessible magic is in this world."
	}
	if r.FormValue("role") != "" {
		myContext.Character_identity = "The character's role in society is as follows: " + r.FormValue("role")
	} else {
		myContext.Character_identity = "Please choose an appropriate background and role in society given the town the characters is in and the technology level of this world."
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

func (apiCFG *apiConfig) landing_page(w http.ResponseWriter, r *http.Request) {
	values := r.URL.Query()
	if len(values) == 0 && r.Method == "GET" {
		http.ServeFile(w, r, "./index.html")
	} else {
		response, err := apiCFG.gen_background(w, r)
		if err != nil {
			respondWithError(w, 500, "Internal Server Error")
			return
		}

		split_resp := strings.Split(response, "\n")
		fields := Character{}
		if len(split_resp) == 14 {
			//take each line from the response, split it at the colon, take the second half, remove the leading space.
			fields = Character{
				Strength:      strings.Split(split_resp[0], ":")[1][1:],
				Dexterity:     strings.Split(split_resp[1], ":")[1][1:],
				Constitution:  strings.Split(split_resp[2], ":")[1][1:],
				Intelligence:  strings.Split(split_resp[3], ":")[1][1:],
				Wisdom:        strings.Split(split_resp[4], ":")[1][1:],
				Charisma:      strings.Split(split_resp[5], ":")[1][1:],
				Name:          strings.Split(split_resp[6], ":")[1][1:],
				Gender:        strings.Split(split_resp[7], ":")[1][1:],
				Age:           strings.Split(split_resp[8], ":")[1][1:],
				Race:          strings.Split(split_resp[9], ":")[1][1:],
				Relationships: strings.Split(split_resp[10], ":")[1][1:],
				Motivation:    strings.Split(split_resp[11], ":")[1][1:],
				Background:    strings.Split(split_resp[12], ":")[1][1:],
				Appearance:    strings.Split(split_resp[13], ":")[1][1:],
			}
		} else {
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

		tmpl, err := loadTemplate()
		if err != nil {
			respondWithError(w, 500, "Internal Server Error")
		}
		parseTemplate(w, fields, tmpl)
		//http.ServeFile(w, r, "./resources/character.html")
		//respondWithError(w, 500, "response handled internally")
	}
}

func (apiCFG *apiConfig) login_page(w http.ResponseWriter, r *http.Request) {
	values := r.URL.Query()
	if len(values) == 0 && r.Method == "GET" {
		http.ServeFile(w, r, "./login.html")
	} else {
		apiCFG.LoginHandler(w, r)
	}
}

func loadTemplate() (*template.Template, error) {
	templateFile := "./resources/character.html"
	tmpl, err := template.ParseFiles((templateFile))
	if err != nil {
		return nil, err
	}
	return tmpl, nil
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

	hashedPassword, err3 := bcrypt.GenerateFromPassword([]byte(params.Password), 0)
	if err3 != nil {
		fmt.Println("failed to hash password")
		return
	}

	userToSave := User{
		Email:         params.Email,
		ID:            userCount + 1,
		Password:      string(hashedPassword),
		Is_Subscribed: false,
	}

	type response struct {
		Email         string `json:"email"`
		ID            int    `json:"id"`
		Is_Subscribed bool   `json:"is_subscribed"`
	}

	newResponse := response{
		Email:         userToSave.Email,
		ID:            userToSave.ID,
		Is_Subscribed: userToSave.Is_Subscribed,
	}

	err4 := apiCFG.NewUser(userToSave)
	if err4 != nil {
		respondWithError(w, 500, err4.Error())
		return
	}

	respondWithJSON(w, 201, newResponse)
}

func (apiCFG *apiConfig) LoginHandler(w http.ResponseWriter, r *http.Request) {
	type LoginAttempt struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	decoder := json.NewDecoder(r.Body)
	params := LoginAttempt{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 500, "Can't decode request")
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

	wholeDB, err := apiCFG.LoadDB()
	if err != nil {
		fmt.Println(err)
		return
	}

	//this seems like a very clumsy way to manage users.
	//it's leftover from where I first implemented this code but looking up users by ID
	//when the most common point of interaction is going to be email login
	//seems like it would process badly.
	allUsers := wholeDB.Users

	var currentUser User
	currentUser.ID = 0

	for _, user := range allUsers {
		if user.Email == params.Email {
			currentUser = user
			break
		}
	}

	if currentUser.ID == 0 {
		respondWithError(w, 401, "Email and password combination not found")
		return
	}
	err2 := bcrypt.CompareHashAndPassword([]byte(currentUser.Password), []byte(params.Password))
	if err2 != nil {
		respondWithError(w, 401, "Email and password combination not found")
		return
	}
	type response struct {
		ID            int    `json:"id"`
		Email         string `json:"email"`
		Token         string `json:"token"`
		Refresh_Token string `json:"refresh_token"`
		Is_Subscribed bool   `json:"is_subscribed"`
	}

	expiry := jwt.NewNumericDate(time.Now().Add(time.Hour))
	refreshExpiry := jwt.NewNumericDate(time.Now().Add(time.Hour * 1440))

	accessClaim := jwt.RegisteredClaims{
		Issuer:    "counterpoint-access",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: expiry,
		Subject:   strconv.Itoa(currentUser.ID),
	}
	refreshClaim := jwt.RegisteredClaims{
		Issuer:    "counterpoint-refresh",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: refreshExpiry,
		Subject:   strconv.Itoa(currentUser.ID),
	}

	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaim)
	signedAccessToken, err3 := newAccessToken.SignedString([]byte(apiCFG.secret))
	if err3 != nil {
		fmt.Println(err3)
		respondWithError(w, 500, "token signing failed")
		return
	}
	newRefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaim)
	signedRefreshToken, err4 := newRefreshToken.SignedString([]byte(apiCFG.secret))
	if err4 != nil {
		fmt.Println(err4)
		respondWithError(w, 500, "token signing failed")
		return
	}

	dbToken := Auth{
		Token:   signedRefreshToken,
		Revoked: false,
	}

	wholeDB.Auths[signedRefreshToken] = dbToken
	apiCFG.SaveDB(wholeDB)

	userResponse := response{
		ID:            currentUser.ID,
		Email:         currentUser.Email,
		Token:         signedAccessToken,
		Refresh_Token: signedRefreshToken,
		Is_Subscribed: currentUser.Is_Subscribed,
	}

	respondWithJSON(w, 200, userResponse)
}

func (apiCFG *apiConfig) AuthenticateUser(w http.ResponseWriter, r *http.Request) (int, bool) {

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

	userID, err3 := token.Claims.GetSubject()
	if err3 != nil {
		respondWithError(w, 500, "Internal Server Error")
		return 0, false
	}

	intID, err4 := strconv.Atoi(userID)
	if err4 != nil {
		respondWithError(w, 500, "Internal Server Error")
		return 0, false
	}

	return intID, true
}

func (apiCFG *apiConfig) RefreshToken(w http.ResponseWriter, r *http.Request) {
	//try printing token.raw to make sure it is what I think it is.
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

	wholeDB, err3 := apiCFG.LoadDB()
	if err3 != nil {
		respondWithError(w, 500, "Internal Server Error")
		return
	}
	refreshTokens := wholeDB.Auths

	for _, dbToken := range refreshTokens {
		if dbToken.Revoked && dbToken.Token == token.Raw {
			respondWithError(w, 401, "Unauthorized")
			return
		}
	}

	type ResponseObject struct {
		Token string `json:"token"`
	}

	expiry := jwt.NewNumericDate(time.Now().Add(time.Hour))

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
