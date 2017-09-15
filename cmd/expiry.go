package cmd

import (
	"errors"
	"regexp"
	"strconv"
	"time"
)

var nowFunc = time.Now

func parseExpiry(fromNow string) (time.Time, error) {
	re := regexp.MustCompile("\\s*(\\d+)\\s*(day|month|year|hour)s?")
	matches := re.FindAllStringSubmatch(fromNow, -1)
	addDate := map[string]int{
		"day":   0,
		"month": 0,
		"year":  0,
		"hour":  0,
	}
	for _, r := range matches {
		addDate[r[2]], _ = strconv.Atoi(r[1])
	}

	now := nowFunc().UTC()
	result := now.
		AddDate(addDate["year"], addDate["month"], addDate["day"]).
		Add(time.Hour * time.Duration(addDate["hour"]))

	if now == result {
		return now, errors.New("Invalid expiry format")
	}

	return result, nil
}
