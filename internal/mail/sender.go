package mail

var defaultFromAddr string

func SetDefaultFromAddress(from string) {
	defaultFromAddr = from
}

type Message struct {
	From        string
	To          []string
	Cc          []string
	Bcc         []string
	Subject     string
	Body        string
	IsHTML      bool
	Embeds      map[string]string
	Attachments []string
}

type MailSender interface {
	Send(message *Message) error
}
