package cmd

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

var nowFunc = time.Now

func parseExpiry(fromNow string) (time.Time, error) {
	now := nowFunc().UTC()
	re := regexp.MustCompile(`\s*(\d+)\s*(day|month|year|hour|minute|second)s?`)
	matches := re.FindAllStringSubmatch(fromNow, -1)
	addDate := map[string]int{
		"day":    0,
		"month":  0,
		"year":   0,
		"hour":   0,
		"minute": 0,
		"second": 0,
	}
	for _, r := range matches {
		number, err := strconv.ParseInt(r[1], 10, 32)
		if err != nil {
			return now, err
		}
		addDate[r[2]] = int(number)
	}

	// Ensure that we do not overflow time.Duration.
	// Doing so is silent and causes signed integer overflow like issues.
	if _, err := time.ParseDuration(fmt.Sprintf("%dh", addDate["hour"])); err != nil {
		return now, fmt.Errorf("hour unit too large to process")
	} else if _, err = time.ParseDuration(fmt.Sprintf("%dm", addDate["minute"])); err != nil {
		return now, fmt.Errorf("minute unit too large to process")
	} else if _, err = time.ParseDuration(fmt.Sprintf("%ds", addDate["second"])); err != nil {
		return now, fmt.Errorf("second unit too large to process")
	}

	result := now.
		AddDate(addDate["year"], addDate["month"], addDate["day"]).
		Add(time.Duration(addDate["hour"]) * time.Hour).
		Add(time.Duration(addDate["minute"]) * time.Minute).
		Add(time.Duration(addDate["second"]) * time.Second)

	if now == result {
		return now, fmt.Errorf("invalid or empty format")
	}

	// ASN.1 (encoding format used by SSL) only supports up to year 9999
	// https://www.openssl.org/docs/man1.1.0/crypto/ASN1_TIME_check.html
	if result.Year() > 9999 {
		return now, fmt.Errorf("proposed date too far in to the future: %s. Expiry year must be less than or equal to 9999", result)
	}

	return result, nil
}
