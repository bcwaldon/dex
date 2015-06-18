package email

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrorNoTemplate = errors.New("No HTML or Text template found for template name.")
)

// Emailer is an object that sends emails.
type Emailer interface {
	// SendMail queues an email to be sent to 1 or more recipients.
	// At least one of "text" or "html" must not be blank. If text is blank, but
	// html is not, then an html-only email should be sent and vice-versal.
	SendMail(from, subject, text, html string, to ...string) error
}

// FakeEmailer is an Emailer that writes emails to stdout. Should only be used in development.
type FakeEmailer struct{}

func (f FakeEmailer) SendMail(from, subject, text, html string, to ...string) error {
	fmt.Printf("From: %v\n", from)
	fmt.Printf("Subject: %v\n", subject)
	fmt.Printf("To: %v\n", strings.Join(to, ","))
	fmt.Printf("Body(text): %v\n", text)
	fmt.Printf("Body(html): %v\n", html)
	return nil
}
