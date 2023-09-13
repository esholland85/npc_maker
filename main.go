package main

import (
	"context"
	"fmt"
	"os"

	"github.com/joho/godotenv"
	openai "github.com/sashabaranov/go-openai"
)

func main() {
	godotenv.Load()
	apiCfg := &apiConfig{}
	//apiCfg.secret = os.Getenv("JWT_SECRET")
	apiCfg.gptKey = os.Getenv("alpha_test_gpt_key")

	myToken := "getTokenLater"
	client := openai.NewClient(myToken)
	resp, err := client.CreateChatCompletion(
		context.Background(), //find out more about context.background
		openai.ChatCompletionRequest{
			Model: openai.GPT3Dot5Turbo,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleUser,
					Content: "Hello!",
				},
			},
		},
	)

	if err != nil {
		fmt.Printf("ChatCompletion error: %v\n", err)
		return
	}

	fmt.Println(resp.Choices[0].Message.Content)
}

type apiConfig struct {
	gptKey string
}
