package validation

import (
	"errors"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/khanghh/kauth/params"
)

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]{3,32}$`)
var phoneNumberRegex = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

const maxAgeYears = 100

var validCountryCodes = map[string]bool{
	"AD": true, "AE": true, "AF": true, "AG": true, "AI": true, "AL": true, "AM": true, "AO": true, "AQ": true, "AR": true,
	"AS": true, "AT": true, "AU": true, "AW": true, "AX": true, "AZ": true, "BA": true, "BB": true, "BD": true, "BE": true,
	"BF": true, "BG": true, "BH": true, "BI": true, "BJ": true, "BL": true, "BM": true, "BN": true, "BO": true, "BQ": true,
	"BR": true, "BS": true, "BT": true, "BV": true, "BW": true, "BY": true, "BZ": true, "CA": true, "CC": true, "CD": true,
	"CF": true, "CG": true, "CH": true, "CI": true, "CK": true, "CL": true, "CM": true, "CN": true, "CO": true, "CR": true,
	"CU": true, "CV": true, "CW": true, "CX": true, "CY": true, "CZ": true, "DE": true, "DJ": true, "DK": true, "DM": true,
	"DO": true, "DZ": true, "EC": true, "EE": true, "EG": true, "EH": true, "ER": true, "ES": true, "ET": true, "FI": true,
	"FJ": true, "FK": true, "FM": true, "FO": true, "FR": true, "GA": true, "GB": true, "GD": true, "GE": true, "GF": true,
	"GG": true, "GH": true, "GI": true, "GL": true, "GM": true, "GN": true, "GP": true, "GQ": true, "GR": true, "GS": true,
	"GT": true, "GU": true, "GW": true, "GY": true, "HK": true, "HM": true, "HN": true, "HR": true, "HT": true, "HU": true,
	"ID": true, "IE": true, "IL": true, "IM": true, "IN": true, "IO": true, "IQ": true, "IR": true, "IS": true, "IT": true,
	"JE": true, "JM": true, "JO": true, "JP": true, "KE": true, "KG": true, "KH": true, "KI": true, "KM": true, "KN": true,
	"KP": true, "KR": true, "KW": true, "KY": true, "KZ": true, "LA": true, "LB": true, "LC": true, "LI": true, "LK": true,
	"LR": true, "LS": true, "LT": true, "LU": true, "LV": true, "LY": true, "MA": true, "MC": true, "MD": true, "ME": true,
	"MF": true, "MG": true, "MH": true, "MK": true, "ML": true, "MM": true, "MN": true, "MO": true, "MP": true, "MQ": true,
	"MR": true, "MS": true, "MT": true, "MU": true, "MV": true, "MW": true, "MX": true, "MY": true, "MZ": true, "NA": true,
	"NC": true, "NE": true, "NF": true, "NG": true, "NI": true, "NL": true, "NO": true, "NP": true, "NR": true, "NU": true,
	"NZ": true, "OM": true, "PA": true, "PE": true, "PF": true, "PG": true, "PH": true, "PK": true, "PL": true, "PM": true,
	"PN": true, "PR": true, "PS": true, "PT": true, "PW": true, "PY": true, "QA": true, "RE": true, "RO": true, "RS": true,
	"RU": true, "RW": true, "SA": true, "SB": true, "SC": true, "SD": true, "SE": true, "SG": true, "SH": true, "SI": true,
	"SJ": true, "SK": true, "SL": true, "SM": true, "SN": true, "SO": true, "SR": true, "SS": true, "ST": true, "SV": true,
	"SX": true, "SY": true, "SZ": true, "TC": true, "TD": true, "TF": true, "TG": true, "TH": true, "TJ": true, "TK": true,
	"TL": true, "TM": true, "TN": true, "TO": true, "TR": true, "TT": true, "TV": true, "TW": true, "TZ": true, "UA": true,
	"UG": true, "UM": true, "US": true, "UY": true, "UZ": true, "VA": true, "VC": true, "VE": true, "VG": true, "VI": true,
	"VN": true, "VU": true, "WF": true, "WS": true, "YE": true, "YT": true, "ZA": true, "ZM": true, "ZW": true,
}

func ValidateUsername(username string) error {
	if username == "" {
		return errors.New("Username is required.")
	}
	if len(username) < 4 {
		return errors.New("Username must be at least 4 characters.")
	}
	if len(username) > 32 {
		return errors.New("Username must be less than 32 characters.")
	}
	if first := username[0]; !(('A' <= first && first <= 'Z') || ('a' <= first && first <= 'z')) {
		return errors.New("Username must start with a letter.")
	}
	if !usernameRegex.MatchString(username) {
		return errors.New("Username can only contain letters, numbers, and underscores.")
	}
	return nil
}

func ValidateEmail(email string) error {
	if _, err := mail.ParseAddress(email); err != nil {
		return errors.New("Invalid email address.")
	}
	return nil
}

func ValidatePassword(password string) error {
	if len(password) < 6 {
		return errors.New("Password must be at least 6 characters.")
	}
	return nil
}

func ValidateCountryCode(code string) error {
	if code == "" {
		return errors.New("Country code is required.")
	}
	if len(code) != 2 {
		return errors.New("Country code must be 2 characters.")
	}
	code = strings.ToUpper(code)
	if !validCountryCodes[code] {
		return errors.New("Invalid country code.")
	}
	return nil
}

func ValidateFullName(fullName string) error {
	if len(fullName) == 0 {
		return errors.New("Full name is required.")
	}
	if len(fullName) > params.FullNameMaxLength {
		return errors.New("Full name must be less than 64 characters.")
	}
	return nil
}

func ValidatePhoneNumber(phone string) error {
	if len(phone) == 0 {
		return errors.New("Phone number is required.")
	}
	if len(phone) > 32 {
		return errors.New("Phone number must be less than 32 characters.")
	}
	if !phoneNumberRegex.MatchString(phone) {
		return errors.New("Invalid phone number format.")
	}
	return nil
}

func ValidateBirthday(birthday int64) error {
	if birthday <= 0 {
		return errors.New("invalid birthday")
	}

	birthTime := time.Unix(birthday, 0)
	now := time.Now()

	// Birthday must be in the past
	if birthTime.After(now) {
		return errors.New("birthday cannot be in the future")
	}

	// Too old (likely invalid)
	oldestAllowed := now.AddDate(-maxAgeYears, 0, 0)
	if birthTime.Before(oldestAllowed) {
		return errors.New("birthday is unrealistically old")
	}

	return nil
}
