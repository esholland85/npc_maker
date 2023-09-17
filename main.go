package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
	"github.com/sashabaranov/go-openai"
)

func main() {
	r := chi.NewRouter()
	char := chi.NewRouter()
	adminR := chi.NewRouter()
	corsWrapped := middlewareCors(r)
	httpServer := http.Server{
		Addr:    "localhost:8080",
		Handler: corsWrapped,
	}

	godotenv.Load()
	apiCFG := &apiConfig{}
	//apiCfg.secret = os.Getenv("JWT_SECRET")
	apiCFG.gptKey = os.Getenv("alpha_test_gpt_key")
	apiCFG.context_path = "./resources/.context"
	apiCFG.mux = &sync.RWMutex{}

	r.Mount("/admin", adminR)
	r.Mount("/character", char)
	adminR.Get("/", apiCFG.gen_background)
	char.Get("/", landing_page)

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
	context_path string
	mux          *sync.RWMutex
}

type npc_context struct {
	Character_name         string
	Town_size              string
	Technology_level       string
	Magic_level            string
	Character_identity     string
	Desired_response_style string
	Anachronism_treatment  string
}

func (apiCFG *apiConfig) Load_context() (npc_context, error) {
	apiCFG.mux.RLock()
	defer apiCFG.mux.RUnlock()
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

func construct_message(myContext npc_context, aiQuery string) ([]openai.ChatCompletionMessage, error) {
	stringSlice := []string{
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
			Role:    openai.ChatMessageRoleUser,
			Content: aiQuery,
		},
	}

	return myMessage, nil
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type chirpError struct {
		Error string `json:"error"`
	}

	errorResponse := chirpError{
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

func (apiCFG *apiConfig) gen_background(w http.ResponseWriter, r *http.Request) {
	myContext, err := apiCFG.Load_context()
	if err != nil {
		respondWithError(w, 500, "Internal Server Error")
		return
	}

	values := r.URL.Query()
	if len(values) == 0 && r.Method == "GET" {
		http.ServeFile(w, r, "./index.html")
		return
	} else {
		//Magic_level            string
		if r.URL.Query().Get("fname") != "" {
			myContext.Character_name = "Your name is " + r.URL.Query().Get("tech") + "."
		} else {
			myContext.Character_name = "Please pick a name appropriate to the technology level."
		}
		if r.URL.Query().Get("size") != "Random" && r.URL.Query().Get("size") != "" {
			myContext.Town_size = "You live in a town of " + r.URL.Query().Get("tech") + " people."
		} else if r.URL.Query().Get("size") == "Random" {
			myContext.Town_size = "Randomly choose how big a town you are from."
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
			myContext.Character_identity = "Your role in society is as follows: " + r.FormValue("role")
		} else {
			myContext.Character_identity = "Please choose an appropriate background and role in society given town you're in and the technology level of this world."
		}
	}

	myMessage, err := construct_message(myContext, "Tell me about your role in the world.")
	if err != nil {
		respondWithError(w, 500, "Internal Server Error")
		return
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
		respondWithError(w, 500, "Internal Server Error")
		return
	}

	respondWithJSON(w, 200, resp.Choices[0].Message.Content)
}

func landing_page(w http.ResponseWriter, r *http.Request) {
	values := r.URL.Query()
	if len(values) == 0 && r.Method == "GET" {
		http.ServeFile(w, r, "./index.html")
	} else {
		fields := templateFields{
			Name: r.URL.Query().Get("fname"),
			Size: r.URL.Query().Get("size"),
		}
		tmpl, err := loadTemplate()
		if err != nil {
			respondWithError(w, 500, "Internal Server Error")
		}
		parseTemplate(w, fields, tmpl)
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

type templateFields struct {
	Name string
	Size string
}

func parseTemplate(w http.ResponseWriter, data templateFields, tmpl *template.Template) {
	err := tmpl.Execute(w, data)
	if err != nil {
		fmt.Println("template not executed")
	}
}
