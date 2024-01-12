package main

import (
	"fmt"
	"log"
	"net/smtp"
	"os"
)

func sendEmail(recipient string, subject string, body string) {
	// email data
	source_address := os.Getenv("source_email")
	password := os.Getenv("source_email_password")

	// Choose auth method and set it up

	auth := smtp.PlainAuth("", source_address, password, "smtp.gmail.com")

	// Here we do it all: connect to our server, set up a message and send it

	to := []string{recipient}

	message_string := fmt.Sprintf("To: %s\r\n"+
		"Subject: %s\r\n"+
		"\r\n"+
		"%s\r\n", recipient, subject, body)

	msg := []byte(message_string)

	err := smtp.SendMail("smtp.gmail.com:587", auth, source_address, to, msg)

	if err != nil {

		log.Fatal(err)

	}
}

func sendHtmlEmail(recipient string, msg []byte) {
	// set up sender data
	source_address := os.Getenv("source_email")
	password := os.Getenv("source_email_password")

	// Set up smtp auth

	auth := smtp.PlainAuth("", source_address, password, "smtp.gmail.com")

	// Plug recipient data in and send message

	to := []string{recipient}

	err := smtp.SendMail("smtp.gmail.com:587", auth, source_address, to, msg)

	if err != nil {

		log.Fatal(err)

	}
}

//for this to work I need to find a way to transfer in a struct or some other
//piece of data that can be executed on a template. The interface let me pass
//the struct, but something was lost and caused an error on execution
/*
func encodeHTMLforEmail(tmpl *template.Template, subject string, inputs interface{}) ([]byte, error) {
	//prepare email headers
	var body bytes.Buffer

	mimeHeaders := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	body.Write([]byte(fmt.Sprintf("Subject: %s \n%s\n\n", subject, mimeHeaders)))

	//plug struct into template

	err := tmpl.Execute(&body, inputs)
	if err != nil {
		fmt.Println("Mismatched HMTL and inputs")
		return nil, err
	}

	//return ready-to-send message
	return body.Bytes(), nil
}
*/
