package cmd

import (
	"encoding/asn1"
	"strconv"
	"strings"
)

func parseOid(oid string) (asn1.ObjectIdentifier, error) {
	result := make([]int, 0)
	for _, part := range strings.Split(oid, ".") {
		number, err := strconv.ParseInt(part, 10, 32)
		if err != nil {
			return asn1.ObjectIdentifier{}, err
		}
		result = append(result, int(number))
	}

	return asn1.ObjectIdentifier(result), nil
}
