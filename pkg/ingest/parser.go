package ingest

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type User struct {
	SamAccountName        string
	DistinguishedName     string
	DoesNotRequirePreAuth bool
	UserAccountControl    int
	ServicePrincipalNames []string
	PwdLastSet            time.Time
	LastLogon             time.Time
	MemberOf              []string
	RawFields             map[string]string
}

func ParseAD(path string) ([]User, error) {
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".csv":
		return parseCSV(path)
	case ".json":
		return parseJSON(path)
	case ".ldif":
		return parseLDIF(path)
	default:
		// Try to detect format by content
		return detectAndParse(path)
	}
}

func parseCSV(path string) ([]User, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1 // Variable number of fields
	reader.TrimLeadingSpace = true

	// Read header
	header, err := reader.Read()
	if err != nil {
		return nil, err
	}

	// Normalize header names
	headerMap := make(map[int]string)
	for i, h := range header {
		headerMap[i] = normalizeFieldName(h)
	}

	var users []User

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // Skip malformed rows
		}

		user := User{
			RawFields: make(map[string]string),
		}

		for i, value := range record {
			if i >= len(header) {
				continue
			}

			fieldName := headerMap[i]
			user.RawFields[header[i]] = value

			switch fieldName {
			case "samaccountname":
				user.SamAccountName = value
			case "distinguishedname":
				user.DistinguishedName = value
			case "doesnotrequirepreauth":
				user.DoesNotRequirePreAuth = parseBool(value)
			case "useraccountcontrol":
				user.UserAccountControl, _ = strconv.Atoi(value)
			case "serviceprincipalname", "serviceprincipalnames", "spn":
				user.ServicePrincipalNames = parseSPNs(value)
			case "pwdlastset":
				user.PwdLastSet = parseTime(value)
			case "lastlogon":
				user.LastLogon = parseTime(value)
			case "memberof":
				user.MemberOf = parseGroups(value)
			}
		}

		// Check UAC flags if DoesNotRequirePreAuth not explicitly set
		if !user.DoesNotRequirePreAuth && user.UserAccountControl > 0 {
			user.DoesNotRequirePreAuth = (user.UserAccountControl & 0x400000) != 0
		}

		users = append(users, user)
	}

	return users, nil
}

func parseJSON(path string) ([]User, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var rawUsers []map[string]interface{}
	if err := json.Unmarshal(data, &rawUsers); err != nil {
		return nil, err
	}

	var users []User
	for _, raw := range rawUsers {
		user := User{
			RawFields: make(map[string]string),
		}

		for key, value := range raw {
			normalKey := normalizeFieldName(key)
			strValue := fmt.Sprintf("%v", value)
			user.RawFields[key] = strValue

			switch normalKey {
			case "samaccountname":
				user.SamAccountName = strValue
			case "distinguishedname":
				user.DistinguishedName = strValue
			case "doesnotrequirepreauth":
				user.DoesNotRequirePreAuth = parseBool(strValue)
			case "useraccountcontrol":
				if v, ok := value.(float64); ok {
					user.UserAccountControl = int(v)
				}
			case "serviceprincipalname", "serviceprincipalnames":
				if arr, ok := value.([]interface{}); ok {
					for _, spn := range arr {
						user.ServicePrincipalNames = append(user.ServicePrincipalNames, fmt.Sprintf("%v", spn))
					}
				} else {
					user.ServicePrincipalNames = parseSPNs(strValue)
				}
			case "pwdlastset":
				user.PwdLastSet = parseTime(strValue)
			case "lastlogon":
				user.LastLogon = parseTime(strValue)
			case "memberof":
				if arr, ok := value.([]interface{}); ok {
					for _, group := range arr {
						user.MemberOf = append(user.MemberOf, fmt.Sprintf("%v", group))
					}
				} else {
					user.MemberOf = parseGroups(strValue)
				}
			}
		}

		users = append(users, user)
	}

	return users, nil
}

func parseLDIF(path string) ([]User, error) {
	// Simplified LDIF parser
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var users []User
	lines := strings.Split(string(data), "\n")

	var currentUser *User
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" {
			if currentUser != nil && currentUser.SamAccountName != "" {
				users = append(users, *currentUser)
			}
			currentUser = nil
			continue
		}

		if strings.HasPrefix(line, "dn:") {
			currentUser = &User{
				RawFields:         make(map[string]string),
				DistinguishedName: strings.TrimSpace(strings.TrimPrefix(line, "dn:")),
			}
			continue
		}

		if currentUser == nil {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		currentUser.RawFields[key] = value

		switch normalizeFieldName(key) {
		case "samaccountname":
			currentUser.SamAccountName = value
		case "useraccountcontrol":
			currentUser.UserAccountControl, _ = strconv.Atoi(value)
		case "serviceprincipalname":
			currentUser.ServicePrincipalNames = append(currentUser.ServicePrincipalNames, value)
		case "pwdlastset":
			currentUser.PwdLastSet = parseTime(value)
		case "lastlogon":
			currentUser.LastLogon = parseTime(value)
		case "memberof":
			currentUser.MemberOf = append(currentUser.MemberOf, value)
		}
	}

	if currentUser != nil && currentUser.SamAccountName != "" {
		users = append(users, *currentUser)
	}

	return users, nil
}

func detectAndParse(path string) ([]User, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data[:min(1000, len(data))])

	if strings.Contains(content, "\"samAccountName\"") || strings.HasPrefix(strings.TrimSpace(content), "[") {
		return parseJSON(path)
	} else if strings.Contains(content, "dn:") {
		return parseLDIF(path)
	} else {
		return parseCSV(path)
	}
}

func normalizeFieldName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, " ", "")
	name = strings.ReplaceAll(name, "_", "")
	name = strings.ReplaceAll(name, "-", "")
	return name
}

func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "1" || s == "yes" || s == "y"
}

func parseSPNs(s string) []string {
	if s == "" {
		return nil
	}

	var spns []string
	// Try multiple delimiters
	for _, delim := range []string{";", ",", "|"} {
		if strings.Contains(s, delim) {
			parts := strings.Split(s, delim)
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part != "" {
					spns = append(spns, part)
				}
			}
			return spns
		}
	}

	// Single SPN
	if s != "" {
		return []string{s}
	}

	return nil
}

func parseGroups(s string) []string {
	if s == "" {
		return nil
	}

	var groups []string
	// Try multiple delimiters
	for _, delim := range []string{";", ",", "|"} {
		if strings.Contains(s, delim) {
			parts := strings.Split(s, delim)
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part != "" {
					groups = append(groups, part)
				}
			}
			return groups
		}
	}

	// Single group
	if s != "" {
		return []string{s}
	}

	return nil
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}

	// Try epoch seconds
	if epoch, err := strconv.ParseInt(s, 10, 64); err == nil {
		if epoch > 0 {
			// Check if it's Windows FILETIME (100-nanosecond intervals since 1601)
			if epoch > 116444736000000000 { // Roughly year 1970 in FILETIME
				// Convert Windows FILETIME to Unix timestamp
				return time.Unix((epoch-116444736000000000)/10000000, 0)
			}
			return time.Unix(epoch, 0)
		}
	}

	// Try ISO formats
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t
		}
	}

	return time.Time{}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
