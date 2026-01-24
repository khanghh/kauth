package users

import "time"

type Gender string

const (
	GenderMale               = "male"
	GenderFemale             = "female"
	GenderUnspecified Gender = "unspecified"
)

type PersonalInfoUpdate struct {
	FullName    *string    `json:"fullName"`
	Birthday    *time.Time `json:"birthday"`
	Gender      *Gender    `json:"gender"`
	PhoneNumber *string    `json:"phoneNumber"`
	Country     *string    `json:"country"`
}
