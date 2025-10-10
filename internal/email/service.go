package email

import (
	"fmt"

	"go-rest-api/internal/common/logger"
	"go-rest-api/internal/config"

	"gopkg.in/gomail.v2"
)

// Service defines email operations.
type Service interface {
	SendEmail(to, subject, body string) error
	SendResetPasswordEmail(to, token string) error
	SendVerificationEmail(to, token string) error
}

type service struct {
	log    *logger.Logger
	dialer *gomail.Dialer
	from   string
}

// NewService creates a new email service instance.
func NewService(cfg *config.Config) Service {
	return &service{
		log: logger.New(),
		dialer: gomail.NewDialer(
			cfg.SMTP.Host,
			cfg.SMTP.Port,
			cfg.SMTP.Username,
			cfg.SMTP.Password,
		),
		from: cfg.SMTP.From,
	}
}

// SendEmail sends an email to the specified recipient.
func (s *service) SendEmail(to, subject, body string) error {
	mailer := gomail.NewMessage()
	mailer.SetHeader("From", s.from)
	mailer.SetHeader("To", to)
	mailer.SetHeader("Subject", subject)
	mailer.SetBody("text/plain", body)

	if err := s.dialer.DialAndSend(mailer); err != nil {
		s.log.Errorf("Failed to send email: %v", err)
		return fmt.Errorf("send email: %w", err)
	}

	return nil
}

// SendResetPasswordEmail sends a password reset email with token.
func (s *service) SendResetPasswordEmail(to, token string) error {
	subject := "Reset password"

	// TODO: Update this URL to match your frontend reset password page
	resetPasswordURL := fmt.Sprintf("http://link-to-app/reset-password?token=%s", token)
	body := fmt.Sprintf(`Dear user,

To reset your password, click on this link: %s

If you did not request any password resets, then ignore this email.`, resetPasswordURL)

	return s.SendEmail(to, subject, body)
}

// SendVerificationEmail sends an email verification message with token.
func (s *service) SendVerificationEmail(to, token string) error {
	subject := "Email Verification"

	// TODO: Update this URL to match your frontend email verification page
	verificationEmailURL := fmt.Sprintf("http://link-to-app/verify-email?token=%s", token)
	body := fmt.Sprintf(`Dear user,

To verify your email, click on this link: %s

If you did not create an account, then ignore this email.`, verificationEmailURL)

	return s.SendEmail(to, subject, body)
}
