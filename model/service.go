package model

import (
	"time"

	"gorm.io/gorm"
)

type Service struct {
	ID                uint          `gorm:"primarykey,autoIncrement"`
	Name              string        `gorm:"size:128;not null"`
	ClientID          string        `gorm:"size:64;not null;uniqueIndex"`
	ClientSecret      string        `gorm:"size:128;not null"`
	LoginURL          string        `gorm:"size:1024;not null"`
	LogoutURL         string        `gorm:"size:1024;not null"`
	StripQuery        bool          `gorm:"not null;default:false"`
	AutoLogin         bool          `gorm:"not null;default:false"`
	ChallengeRequired bool          `gorm:"not null;default:false"`
	ChallengeValidity time.Duration `gorm:"not null;default:0"`
	CreatedAt         time.Time
	UpdatedAt         time.Time
	DeletedAt         gorm.DeletedAt `gorm:"index"`
}
