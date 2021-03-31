package social

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/util/errutil"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

type SocialID4me struct {
	*SocialBase
	issuerUrl         string
	apiUrl            string
	allowedGroups     []string
	roleAttributePath string
}

type ID4meUserInfoJson struct {
	Name        string              `json:"name"`
	DisplayName string              `json:"display_name"`
	Login       string              `json:"login"`
	Username    string              `json:"username"`
	Email       string              `json:"email"`
	Upn         string              `json:"upn"`
	Attributes  map[string][]string `json:"attributes"`
	Groups      []string            `json:"groups"`
	rawJSON     []byte
}

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

func (s *SocialID4me) Type() int {
	return int(models.ID4ME)
}

func (s *SocialID4me) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	LookupIssuer(s.issuerUrl, "1.1.1.1:53")
	return "https://mydomain.de/"
}

func (s *SocialID4me) UserInfo(client *http.Client, token *oauth2.Token) (*BasicUserInfo, error) {
	idToken := token.Extra("id_token")
	if idToken == nil {
		return nil, fmt.Errorf("no id_token found")
	}

	parsedToken, err := jwt.ParseSigned(idToken.(string))
	if err != nil {
		return nil, errutil.Wrapf(err, "error parsing id token")
	}

	var claims ID4meClaims
	if err := parsedToken.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, errutil.Wrapf(err, "error getting claims from id token")
	}

	email := claims.extractEmail()
	if email == "" {
		return nil, errors.New("error getting user info: no email found in access token")
	}

	var data ID4meUserInfoJson
	err = s.extractAPI(&data, client)
	if err != nil {
		return nil, err
	}

	role, err := s.extractRole(&data)
	if err != nil {
		s.log.Error("Failed to extract role", "error", err)
	}

	groups := s.GetGroups(&data)
	if !s.IsGroupMember(groups) {
		return nil, errMissingGroupMembership
	}

	return &BasicUserInfo{
		Id:     claims.ID,
		Name:   claims.Name,
		Email:  email,
		Login:  email,
		Role:   role,
		Groups: groups,
	}, nil
}

func (s *SocialID4me) extractAPI(data *ID4meUserInfoJson, client *http.Client) error {
	rawUserInfoResponse, err := s.httpGet(client, s.apiUrl)
	if err != nil {
		s.log.Debug("Error getting user info response", "url", s.apiUrl, "error", err)
		return errutil.Wrapf(err, "error getting user info response")
	}
	data.rawJSON = rawUserInfoResponse.Body

	err = json.Unmarshal(data.rawJSON, data)
	if err != nil {
		s.log.Debug("Error decoding user info response", "raw_json", data.rawJSON, "error", err)
		data.rawJSON = []byte{}
		return errutil.Wrapf(err, "error decoding user info response")
	}

	s.log.Debug("Received user info response", "raw_json", string(data.rawJSON), "data", data)
	return nil
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

func (s *SocialID4me) GetGroups(data *ID4meUserInfoJson) []string {
	groups := make([]string, 0)
	if len(data.Groups) > 0 {
		groups = data.Groups
	}
	return groups
}

func (s *SocialID4me) IsGroupMember(groups []string) bool {
	if len(s.allowedGroups) == 0 {
		return true
	}

	for _, allowedGroup := range s.allowedGroups {
		for _, group := range groups {
			if group == allowedGroup {
				return true
			}
		}
	}

	return false
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
