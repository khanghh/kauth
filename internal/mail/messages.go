package mail

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/kauth/internal/render"
)

func SendOTP(sender MailSender, toEmail string, otpCode string) error {
	params := fiber.Map{
		"otpCode":       otpCode,
		"expireMinutes": 5,
	}
	body, err := render.RenderHTML("mail/otp-code", params)
	if err != nil {
		return err
	}
	return sender.Send(&Message{
		To:      []string{toEmail},
		Subject: fmt.Sprintf("%s is your verification code", otpCode),
		Body:    body,
		IsHTML:  true,
	})
}

func SendRegisterVerification(sender MailSender, toEmail string, verifyURL string) error {
	params := fiber.Map{
		"verifyURL": verifyURL,
	}
	body, err := render.RenderHTML("mail/confirm-register", params)
	if err != nil {
		return err
	}
	return sender.Send(&Message{
		To:      []string{toEmail},
		Subject: "Please verify your email address",
		Body:    body,
		IsHTML:  true,
	})
}

func SendResetPasswordLink(sender MailSender, toEmail string, resetLink string) error {
	params := fiber.Map{
		"resetLink":     resetLink,
		"expireMinutes": 5,
	}
	body, err := render.RenderHTML("mail/reset-password", params)
	if err != nil {
		return err
	}
	return sender.Send(&Message{
		To:      []string{toEmail},
		Subject: "Reset your password",
		Body:    body,
		IsHTML:  true,
	})
}
