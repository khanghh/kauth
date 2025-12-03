package mail

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	"gopkg.in/gomail.v2"
)

type SMTPMailSender struct {
	*gomail.Dialer
	From string
}

func (s *SMTPMailSender) Send(message *Message) error {
	msg := gomail.NewMessage()
	msg.SetHeader("From", s.From)
	msg.SetHeader("To", message.To...)
	msg.SetHeader("Cc", message.Cc...)
	msg.SetHeader("Subject", message.Subject)
	if message.IsHTML {
		msg.SetBody("text/html", message.Body)
	} else {
		msg.SetBody("text/plain", message.Body)
	}
	for cid, file := range message.Embeds {
		msg.Embed(file, gomail.SetHeader(map[string][]string{
			"Content-ID": {"<" + cid + ">"},
		}))
	}
	for _, file := range message.Attachments {
		msg.Attach(file)
	}
	return s.DialAndSend(msg)
}

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	TLS      bool
	CertFile string
	KeyFile  string
	CAFile   string
}

func dialSMTP(smtpCfg SMTPConfig) (*gomail.Dialer, error) {
	dialer := gomail.NewDialer(smtpCfg.Host, smtpCfg.Port, smtpCfg.Username, smtpCfg.Password)
	dialer.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	if smtpCfg.TLS {
		cert, err := tls.LoadX509KeyPair(smtpCfg.CertFile, smtpCfg.KeyFile)
		if err != nil {
			return nil, err
		}

		caPool := x509.NewCertPool()
		if smtpCfg.CAFile != "" {
			caCert, err := os.ReadFile(smtpCfg.CAFile)
			if err != nil {
				return nil, err
			}
			caPool.AppendCertsFromPEM(caCert)
		}

		dialer.TLSConfig = &tls.Config{
			ServerName:         smtpCfg.Host,
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{cert},
			RootCAs:            caPool,
		}
	}
	return dialer, nil
}

func NewSMTPMailSender(smtpConfig SMTPConfig, from string) (*SMTPMailSender, error) {
	dialer, err := dialSMTP(smtpConfig)
	if err != nil {
		return nil, err
	}
	return &SMTPMailSender{
		Dialer: dialer,
		From:   from,
	}, nil
}
