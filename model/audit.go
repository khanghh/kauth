package model

import "time"

type AuditEvent struct {
	ID            uint64    `gorm:"primaryKey;autoIncrement"`
	UserID        uint      `gorm:"index;not null"`         // internal user id
	Username      string    `gorm:"size:64;not null;index"` // snapshot of username at event time
	EventType     string    `gorm:"size:64;not null;index"` // login_success, login_failure...
	AuthMethod    string    `gorm:"size:32;index"`          // password, oauth, totp, etc. (optional)
	ServiceID     uint      `gorm:"index"`                  // service id - only for service authorization events
	ChallengeID   string    `gorm:"size:64"`                // challenge id - only for 2FA events
	ChallengeType string    `gorm:"size:16"`                // challenge type - only for 2FA events
	ServiceName   string    `gorm:"size:128;index"`         // client_id or app name (optional)
	CallbackURL   string    `gorm:"size:512"`               // (optional)
	Reason        string    `gorm:"size:512"`               // failure reason or context
	IP            string    `gorm:"size:45;not null"`       // IPv4/IPv6
	UserAgent     string    `gorm:"size:512;not null"`      // user agent string
	CreatedAt     time.Time `gorm:"autoCreateTime"`
}

func (AuditEvent) TableName() string {
	return "audit"
}
