package social

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"

	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/util/errutil"
	"golang.org/x/oauth2"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

type SocialID4me struct {
	*SocialBase
	allowedOrganizations []string
	apiUrl               string
	issuerUrl            string
	emailAttributeName   string
	emailAttributePath   string
	loginAttributePath   string
	nameAttributePath    string
	roleAttributePath    string
	idTokenAttributeName string
	teamIds              []int
}

type ID4meUserInfoJson struct {
	Name        string                     `json:"name"`
	DisplayName string                     `json:"display_name"`
	Login       string                     `json:"login"`
	Username    string                     `json:"username"`
	Email       string                     `json:"email"`
	Upn         string                     `json:"upn"`
	Attributes  map[string][]string        `json:"attributes"`
	ClaimSource map[string]ClaimSourceMeta `json:"_claim_sources,omitempty"`
	rawJSON     []byte
	source      string
}

// ClaimSources struct
//type ClaimSources struct {
//	ClaimSource map[string]ClaimSourceMeta `json:"_claim_sources"`
//}

// ClaimSourceMeta struct
type ClaimSourceMeta struct {
	Endpoint    string `json:"endpoint,omitempty"`
	AccessToken string `json:"access_token,omitempty"`
}

/*
type ID4meClaims struct {
	ID                string `json:"sub"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
}

func (claims *ID4meClaims) extractEmail() string {
	if claims.Email == "" && claims.PreferredUsername != "" {
		return claims.PreferredUsername
	}

	return claims.Email
}
*/

func (s *SocialID4me) Type() int {
	return int(models.ID4ME)
}

func (s *SocialID4me) IsTeamMember(client *http.Client) bool {
	if len(s.teamIds) == 0 {
		return true
	}

	teamMemberships, ok := s.FetchTeamMemberships(client)
	if !ok {
		return false
	}

	for _, teamId := range s.teamIds {
		for _, membershipId := range teamMemberships {
			if teamId == membershipId {
				return true
			}
		}
	}

	return false
}

func (s *SocialID4me) IsOrganizationMember(client *http.Client) bool {
	if len(s.allowedOrganizations) == 0 {
		return true
	}

	organizations, ok := s.FetchOrganizations(client)
	if !ok {
		return false
	}

	for _, allowedOrganization := range s.allowedOrganizations {
		for _, organization := range organizations {
			if organization == allowedOrganization {
				return true
			}
		}
	}

	return false
}

func (info *ID4meUserInfoJson) String() string {
	return fmt.Sprintf(
		"Name: %s, Displayname: %s, Login: %s, Username: %s, Email: %s, Upn: %s, Attributes: %v",
		info.Name, info.DisplayName, info.Login, info.Username, info.Email, info.Upn, info.Attributes)
}

func (s *SocialID4me) UserInfo(client *http.Client, token *oauth2.Token) (*BasicUserInfo, error) {
	s.log.Debug("Getting user info")
	tokenData := s.extractFromToken(token)
	apiData := s.extractFromAPI(client, s.apiUrl)
	distApiData := s.retrieveDistributedClaims(client, apiData)

	userInfo := &BasicUserInfo{}
	for _, data := range append([]*ID4meUserInfoJson{tokenData, apiData}, distApiData...) {
		if data == nil {
			continue
		}

		s.log.Debug("Processing external user info", "source", data.source, "data", data)

		if userInfo.Name == "" {
			userInfo.Name = s.extractUserName(data)
		}

		if userInfo.Login == "" {
			if data.Login != "" {
				s.log.Debug("Setting user info login from login field", "login", data.Login)
				userInfo.Login = data.Login
			} else {
				if s.loginAttributePath != "" {
					s.log.Debug("Searching for login among JSON", "loginAttributePath", s.loginAttributePath)
					login, err := s.searchJSONForAttr(s.loginAttributePath, data.rawJSON)
					if err != nil {
						s.log.Error("Failed to search JSON for login attribute", "error", err)
					} else if login != "" {
						userInfo.Login = login
						s.log.Debug("Setting user info login from login field", "login", login)
					}
				}

				if userInfo.Login == "" && data.Username != "" {
					s.log.Debug("Setting user info login from username field", "username", data.Username)
					userInfo.Login = data.Username
				}
			}
		}

		if userInfo.Email == "" {
			userInfo.Email = s.extractEmail(data)
			if userInfo.Email != "" {
				s.log.Debug("Set user info email from extracted email", "email", userInfo.Email)
			}
		}

		if userInfo.Role == "" {
			role, err := s.extractRole(data)
			if err != nil {
				s.log.Error("Failed to extract role", "error", err)
			} else if role != "" {
				s.log.Debug("Setting user info role from extracted role")
				userInfo.Role = role
			}
		}
	}

	if userInfo.Email == "" {
		var err error
		userInfo.Email, err = s.FetchPrivateEmail(client)
		if err != nil {
			return nil, err
		}
		s.log.Debug("Setting email from fetched private email", "email", userInfo.Email)
	}

	if userInfo.Login == "" {
		s.log.Debug("Defaulting to using email for user info login", "email", userInfo.Email)
		userInfo.Login = userInfo.Email
	}

	if !s.IsTeamMember(client) {
		return nil, errors.New("user not a member of one of the required teams")
	}

	if !s.IsOrganizationMember(client) {
		return nil, errors.New("user not a member of one of the required organizations")
	}

	s.log.Debug("User info result", "result", userInfo)
	return userInfo, nil
}

func (s *SocialID4me) extractFromToken(token *oauth2.Token) *ID4meUserInfoJson {
	s.log.Debug("Extracting user info from OAuth token")

	idTokenAttribute := "id_token"
	if s.idTokenAttributeName != "" {
		idTokenAttribute = s.idTokenAttributeName
		s.log.Debug("Using custom id_token attribute name", "attribute_name", idTokenAttribute)
	}

	idToken := token.Extra(idTokenAttribute)
	if idToken == nil {
		s.log.Debug("No id_token found", "token", token)
		return nil
	}

	jwtRegexp := regexp.MustCompile("^([-_a-zA-Z0-9=]+)[.]([-_a-zA-Z0-9=]+)[.]([-_a-zA-Z0-9=]+)$")
	matched := jwtRegexp.FindStringSubmatch(idToken.(string))
	if matched == nil {
		s.log.Debug("id_token is not in JWT format", "id_token", idToken.(string))
		return nil
	}

	rawJSON, err := base64.RawURLEncoding.DecodeString(matched[2])
	if err != nil {
		s.log.Error("Error base64 decoding id_token", "raw_payload", matched[2], "error", err)
		return nil
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(matched[1])
	if err != nil {
		s.log.Error("Error base64 decoding header", "header", matched[1], "error", err)
		return nil
	}

	var header map[string]string
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		s.log.Error("Error deserializing header", "error", err)
		return nil
	}

	if compression, ok := header["zip"]; ok {
		if compression != "DEF" {
			s.log.Warn("Unknown compression algorithm", "algorithm", compression)
			return nil
		}

		fr, err := zlib.NewReader(bytes.NewReader(rawJSON))
		if err != nil {
			s.log.Error("Error creating zlib reader", "error", err)
			return nil
		}
		defer func() {
			if err := fr.Close(); err != nil {
				s.log.Warn("Failed closing zlib reader", "error", err)
			}
		}()
		rawJSON, err = ioutil.ReadAll(fr)
		if err != nil {
			s.log.Error("Error decompressing payload", "error", err)
			return nil
		}
	}

	var data ID4meUserInfoJson
	if err := json.Unmarshal(rawJSON, &data); err != nil {
		s.log.Error("Error decoding id_token JSON", "raw_json", string(data.rawJSON), "error", err)
		return nil
	}

	data.rawJSON = rawJSON
	data.source = "token"
	s.log.Debug("Received id_token", "raw_json", string(data.rawJSON), "data", data.String())
	return &data
}

func (s *SocialID4me) extractFromAPI(client *http.Client, apiUrl string) *ID4meUserInfoJson {
	s.log.Debug("Getting user info from API", "url", apiUrl)
	rawUserInfoResponse, err := s.httpGet(client, apiUrl)
	if err != nil {
		s.log.Debug("Error getting user info from API", "url", apiUrl, "error", err)
		return nil
	}

	rawJSON := rawUserInfoResponse.Body

	var data ID4meUserInfoJson
	data.ClaimSource = make(map[string]ClaimSourceMeta)
	if err := json.Unmarshal(rawJSON, &data); err != nil {
		s.log.Error("Error decoding user info response", "raw_json", rawJSON, "error", err)
		return nil
	}

	data.rawJSON = rawJSON
	data.source = "API"
	s.log.Debug("Received user info response from API", "raw_json", string(rawJSON), "data", data.String())
	return &data
}

func (s *SocialID4me) extractEmail(data *ID4meUserInfoJson) string {
	if data.Email != "" {
		return data.Email
	}

	if s.emailAttributePath != "" {
		email, err := s.searchJSONForAttr(s.emailAttributePath, data.rawJSON)
		if err != nil {
			s.log.Error("Failed to search JSON for attribute", "error", err)
		} else if email != "" {
			return email
		}
	}

	emails, ok := data.Attributes[s.emailAttributeName]
	if ok && len(emails) != 0 {
		return emails[0]
	}

	if data.Upn != "" {
		emailAddr, emailErr := mail.ParseAddress(data.Upn)
		if emailErr == nil {
			return emailAddr.Address
		}
		s.log.Debug("Failed to parse e-mail address", "error", emailErr.Error())
	}

	return ""
}

func (s *SocialID4me) extractUserName(data *ID4meUserInfoJson) string {
	if s.nameAttributePath != "" {
		name, err := s.searchJSONForAttr(s.nameAttributePath, data.rawJSON)
		if err != nil {
			s.log.Error("Failed to search JSON for attribute", "error", err)
		} else if name != "" {
			s.log.Debug("Setting user info name from nameAttributePath", "nameAttributePath", s.nameAttributePath)
			return name
		}
	}

	if data.Name != "" {
		s.log.Debug("Setting user info name from name field")
		return data.Name
	}

	if data.DisplayName != "" {
		s.log.Debug("Setting user info name from display name field")
		return data.DisplayName
	}

	s.log.Debug("Unable to find user info name")
	return ""
}

func (s *SocialID4me) extractRole(data *ID4meUserInfoJson) (string, error) {
	if s.roleAttributePath == "" {
		return "", nil
	}

	role, err := s.searchJSONForAttr(s.roleAttributePath, data.rawJSON)
	if err != nil {
		return "", err
	}
	return role, nil
}

func (s *SocialID4me) FetchPrivateEmail(client *http.Client) (string, error) {
	type Record struct {
		Email       string `json:"email"`
		Primary     bool   `json:"primary"`
		IsPrimary   bool   `json:"is_primary"`
		Verified    bool   `json:"verified"`
		IsConfirmed bool   `json:"is_confirmed"`
	}

	response, err := s.httpGet(client, fmt.Sprintf(s.apiUrl+"/emails"))
	if err != nil {
		s.log.Error("Error getting email address", "url", s.apiUrl+"/emails", "error", err)
		return "", errutil.Wrap("Error getting email address", err)
	}

	var records []Record

	err = json.Unmarshal(response.Body, &records)
	if err != nil {
		var data struct {
			Values []Record `json:"values"`
		}

		err = json.Unmarshal(response.Body, &data)
		if err != nil {
			s.log.Error("Error decoding email addresses response", "raw_json", string(response.Body), "error", err)
			return "", errutil.Wrap("Error decoding email addresses response", err)
		}

		records = data.Values
	}

	s.log.Debug("Received email addresses", "emails", records)

	var email = ""
	for _, record := range records {
		if record.Primary || record.IsPrimary {
			email = record.Email
			break
		}
	}

	s.log.Debug("Using email address", "email", email)

	return email, nil
}

func (s *SocialID4me) FetchTeamMemberships(client *http.Client) ([]int, bool) {
	type Record struct {
		Id int `json:"id"`
	}

	response, err := s.httpGet(client, fmt.Sprintf(s.apiUrl+"/teams"))
	if err != nil {
		s.log.Error("Error getting team memberships", "url", s.apiUrl+"/teams", "error", err)
		return nil, false
	}

	var records []Record

	err = json.Unmarshal(response.Body, &records)
	if err != nil {
		s.log.Error("Error decoding team memberships response", "raw_json", string(response.Body), "error", err)
		return nil, false
	}

	var ids = make([]int, len(records))
	for i, record := range records {
		ids[i] = record.Id
	}

	s.log.Debug("Received team memberships", "ids", ids)

	return ids, true
}

func (s *SocialID4me) FetchOrganizations(client *http.Client) ([]string, bool) {
	type Record struct {
		Login string `json:"login"`
	}

	response, err := s.httpGet(client, fmt.Sprintf(s.apiUrl+"/orgs"))
	if err != nil {
		s.log.Error("Error getting organizations", "url", s.apiUrl+"/orgs", "error", err)
		return nil, false
	}

	var records []Record

	err = json.Unmarshal(response.Body, &records)
	if err != nil {
		s.log.Error("Error decoding organization response", "response", string(response.Body), "error", err)
		return nil, false
	}

	var logins = make([]string, len(records))
	for i, record := range records {
		logins[i] = record.Login
	}

	s.log.Debug("Received organizations", "logins", logins)

	return logins, true
}

func (s *SocialID4me) CustomAuthCodeURL(state string, loginHint string, opts ...oauth2.AuthCodeOption) (string, error) {

	issuer, err := LookupIssuer(loginHint, "1.1.1.1:53")
	if err != nil {
		return "", err
	}

	if !compareIssuer(issuer, s.issuerUrl) {
		return "", errors.New(fmt.Sprintf("No ID4me registration configured for %s", issuer))
	}

	authCodeUrl := s.AuthCodeURL(state, opts...)

	var buf bytes.Buffer
	buf.WriteString(authCodeUrl)
	v := url.Values{
		"login_hint": {loginHint},
	}

	buf.WriteByte('&')
	buf.WriteString(v.Encode())

	return buf.String(), nil
}

func LookupIssuer(id string, resolver string) (string, error) {
	idtxt := "_openid." + id
	asciiName, err := idna.ToASCII(idtxt)
	if err != nil {
		return "", fmt.Errorf("Could not map %v to ASCII name", asciiName)
	}

	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = dns.Question{Name: dns.Fqdn(asciiName), Qtype: dns.TypeTXT, Qclass: dns.ClassINET}
	in, err := dns.Exchange(m1, resolver)
	if err != nil {
		return "", err
	}

	if in != nil && in.Rcode != dns.RcodeSuccess {
		if in.Rcode == dns.RcodeNameError {
			return "", fmt.Errorf("Record not found: %s (_openid.%s)", id, asciiName)
		}
		return "", fmt.Errorf("Error during DNS lookup: %s", dns.RcodeToString[in.Rcode])
	}

	txtrecord := ""

	for _, record := range in.Answer {
		if t, ok := record.(*dns.TXT); ok {
			for _, line := range t.Txt {
				txtrecord = line
				break
			}
		}
	}

	if !strings.Contains(txtrecord, "iss=") {
		return "", fmt.Errorf("Invalid TXT record for id %s: %s", id, txtrecord)
	}

	parts := strings.Split(txtrecord, ";")
	isspart := strings.Split(parts[1], "=")
	issuer := isspart[1]
	return issuer, nil
}

func (s *SocialID4me) retrieveDistributedClaims(client *http.Client, userinfo *ID4meUserInfoJson) []*ID4meUserInfoJson {
	index := 0
	if len(userinfo.ClaimSource) > 0 {
		var ret = make([]*ID4meUserInfoJson, len(userinfo.ClaimSource))
		for k := range userinfo.ClaimSource {
			resp, err := s.httpGet(client, userinfo.ClaimSource[k].Endpoint)
			if err != nil {
				s.log.Debug("Error getting user info from distributed API", "url", userinfo.ClaimSource[k].Endpoint, "error", err)
				return nil
			}

			rawJSON := resp.Body
			data := new(ID4meUserInfoJson)
			//data.ClaimSource = make(map[string]ClaimSourceMeta)
			if err := json.Unmarshal(rawJSON, &data); err != nil {
				s.log.Error("Error decoding user info response", "raw_json", rawJSON, "error", err)
				return nil
			}

			data.rawJSON = rawJSON
			data.source = "API"
			s.log.Debug("Received user info response from distributed API", "raw_json", string(rawJSON), "data", data.String())
			ret[index] = data
			index++
		}
		return ret
	}
	return nil
}

func compareIssuer(issuer string, compareTo string) bool {
	if slice := strings.Split(issuer, "://"); len(slice) > 1 {
		issuer = slice[1]
	}
	if slice := strings.Split(compareTo, "://"); len(slice) > 1 {
		compareTo = slice[1]
	}

	if issuer == compareTo {
		return true
	} else {
		return false
	}
}
