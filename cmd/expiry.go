package cmd

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

var nowFunc = time.Now

func parseTime(value string) (map[string]int, error) {
	re := regexp.MustCompile(`\s*(\d+)\s*(day|month|year|hour|minute|second)s?`)
	matches := re.FindAllStringSubmatch(value, -1)
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
			return nil, err
		}
		addDate[r[2]] = int(number)
	}

	// Ensure that we do not overflow time.Duration.
	// Doing so is silent and causes signed integer overflow like issues.
	if _, err := time.ParseDuration(fmt.Sprintf("%dh", addDate["hour"])); err != nil {
		return nil, fmt.Errorf("hour unit too large to process")
	} else if _, err = time.ParseDuration(fmt.Sprintf("%dm", addDate["minute"])); err != nil {
		return nil, fmt.Errorf("minute unit too large to process")
	} else if _, err = time.ParseDuration(fmt.Sprintf("%ds", addDate["second"])); err != nil {
		return nil, fmt.Errorf("second unit too large to process")
	}

	return addDate, nil
}

func parseExpiry(fromNow string) (time.Time, error) {
	now := nowFunc().UTC()
	addDate, err := parseTime(fromNow)
	if err != nil {
		return now, err
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

func parseNotBefore(notBefore string) (time.Time, error) {
	now := nowFunc().UTC()
	tenMinutesAgo := nowFunc().Add(-time.Minute * 10).UTC()

	subDate, err := parseTime(notBefore)
	if err != nil {
		return tenMinutesAgo, err
	}

	for unitOfTime, value := range subDate {
		subDate[unitOfTime] = -value
	}

	result := now.
		AddDate(subDate["year"], subDate["month"], subDate["day"]).
		Add(time.Duration(subDate["hour"]) * time.Hour).
		Add(time.Duration(subDate["minute"]) * time.Minute).
		Add(time.Duration(subDate["second"]) * time.Second)

	if now == result {
		return tenMinutesAgo, fmt.Errorf("invalid or empty format")
	}

	// ASN.1 (encoding format used by SSL) can support down to year 0
	// https://www.openssl.org/docs/man1.1.0/crypto/ASN1_TIME_check.html
	if result.Year() < 0 {
		return tenMinutesAgo, fmt.Errorf("proposed date too far in to the past: %s. Expiry year must be greater than or equal to 0", result)
	}

	return result, nil
}
