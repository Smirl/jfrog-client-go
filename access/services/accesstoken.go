package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/jfrog/jfrog-client-go/artifactory/services/utils"
	"github.com/jfrog/jfrog-client-go/auth"
	"github.com/jfrog/jfrog-client-go/http/jfroghttpclient"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/httputils"
)

// #nosec G101 -- False positive - no hardcoded credentials.
const tokensApi = "api/v1/tokens"

type TokenService struct {
	client         *jfroghttpclient.JfrogHttpClient
	ServiceDetails auth.ServiceDetails
}

type CreateTokenParams struct {
	auth.CommonTokenParams
	Description           string `json:"description,omitempty"`
	IncludeReferenceToken *bool  `json:"include_reference_token,omitempty"`
	Username              string `json:"username,omitempty"`
}

type GetTokensParams struct {
	Description string `json:"description,omitempty"`
	Refreshable *bool  `json:"refreshable,omitempty"`
}

type Token struct {
	Description string `json:"Description,omitempty"`
	Expiry      int    `json:"expiry,omitempty"`
	IssuedAt    int    `json:"issued_at,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
	Refreshable bool   `json:"refreshable,omitempty"`
	Subject     string `json:"subject,omitempty"`
	TokenId     string `json:"token_id,omitempty"`
}

func NewCreateTokenParams(params CreateTokenParams) CreateTokenParams {
	return CreateTokenParams{
		CommonTokenParams:     params.CommonTokenParams,
		Description:           params.Description,
		IncludeReferenceToken: params.IncludeReferenceToken,
		Username:              params.Username,
	}
}

func NewTokenService(client *jfroghttpclient.JfrogHttpClient) *TokenService {
	return &TokenService{client: client}
}

// Create an access token for the JFrog Platform
func (ps *TokenService) CreateAccessToken(params CreateTokenParams) (auth.CreateTokenResponseData, error) {
	return ps.createAccessToken(params)
}

// Refresh an existing access token without having to provide the old token.
// The Refresh Token is the same API endpoint as Create Token, with a specific grant type: refresh_token
func (ps *TokenService) RefreshAccessToken(token CreateTokenParams) (auth.CreateTokenResponseData, error) {
	// Validate provided parameters
	if token.RefreshToken == "" {
		return auth.CreateTokenResponseData{}, errorutils.CheckErrorf("error: trying to refresh token, but 'refresh_token' field wasn't provided. ")
	}
	// Set refresh required parameters
	var trueValue = true
	params := NewCreateTokenParams(token)
	params.GrantType = "refresh_token"
	params.Refreshable = &trueValue

	return ps.createAccessToken(params)
}

// Return token information, based on the authenticated principal and optional filters.
func (ps *TokenService) GetTokens(params GetTokensParams) ([]Token, error) {
	// Create token URL
	url, err := ps.accessTokenURL("")
	if err != nil {
		return nil, err
	}
	q := url.Query()
	if params.Description != "" {
		q.Add("description", params.Description)
	}
	if params.Refreshable != nil {
		q.Add("refreshable", fmt.Sprintf("%b", params.Refreshable))
	}
	url.RawQuery = q.Encode()

	// Send token request and check for errors
	httpDetails := ps.ServiceDetails.CreateHttpClientDetails()
	resp, body, _, err := ps.client.SendGet(url.String(), false, &httpDetails)
	if err != nil {
		return nil, err
	}
	// The case the requested user is not found
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if err = errorutils.CheckResponseStatusWithBody(resp, body, http.StatusOK); err != nil {
		return nil, err
	}

	// Unmarshall the response body and return
	var response struct{ Tokens []Token }
	err = json.Unmarshal(body, &response)
	return response.Tokens, errorutils.CheckError(err)
}

// Return the token information by token ID
// Returning a pointer to the Token so it can be nil
func (ps *TokenService) GetTokenById(tokenId string) (*Token, error) {
	// Create token URL
	url, err := ps.accessTokenURL(tokenId)
	if err != nil {
		return nil, err
	}

	// Send token request and check for errors
	httpDetails := ps.ServiceDetails.CreateHttpClientDetails()
	resp, body, _, err := ps.client.SendGet(url.String(), false, &httpDetails)
	if err != nil {
		return nil, err
	}
	// The case the requested user is not found
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if err = errorutils.CheckResponseStatusWithBody(resp, body, http.StatusOK); err != nil {
		return nil, err
	}

	// Unmarshall the response body and return
	var token Token
	err = json.Unmarshal(body, &token)
	return &token, errorutils.CheckError(err)
}

// Revoke an access token by specifying the token_id
func (ps *TokenService) RevokeToken(tokenId string) error {
	// Create token URL
	url, err := ps.accessTokenURL(tokenId)
	if err != nil {
		return err
	}

	// Send token request and check for errors
	httpDetails := ps.ServiceDetails.CreateHttpClientDetails()
	resp, body, err := ps.client.SendDelete(url.String(), nil, &httpDetails)
	if err != nil {
		return err
	}
	return errorutils.CheckResponseStatusWithBody(resp, body, http.StatusOK)
}

// Return the parsed url.URL for the access token endpoint
// This is /access/api/v1/tokens with an optional /token-id suffix
func (ps *TokenService) accessTokenURL(tokenId string) (*url.URL, error) {
	u, err := url.Parse(ps.ServiceDetails.GetUrl())
	if err != nil {
		return nil, err
	}
	u = u.JoinPath(tokensApi)
	if tokenId != "" {
		u = u.JoinPath(tokenId)
	}
	return u, nil
}

// createAccessToken is used to create & refresh access tokens.
func (ps *TokenService) createAccessToken(params CreateTokenParams) (auth.CreateTokenResponseData, error) {
	// Create output response variable
	tokenInfo := auth.CreateTokenResponseData{}

	// Set the request headers
	httpDetails := ps.ServiceDetails.CreateHttpClientDetails()
	utils.SetContentType("application/json", &httpDetails.Headers)
	err := ps.addAccessTokenAuthorizationHeader(params, &httpDetails)
	if err != nil {
		return tokenInfo, err
	}

	// Marshall the request body
	requestContent, err := json.Marshal(params)
	if errorutils.CheckError(err) != nil {
		return tokenInfo, err
	}

	// Send the Post request to either create or refresh the token
	url, err := ps.accessTokenURL("")
	if err != nil {
		return tokenInfo, err
	}
	resp, body, err := ps.client.SendPost(url.String(), requestContent, &httpDetails)
	if err != nil {
		return tokenInfo, err
	}
	if err = errorutils.CheckResponseStatusWithBody(resp, body, http.StatusOK); err != nil {
		return tokenInfo, err
	}

	// Unmarshall the response body and return
	err = json.Unmarshal(body, &tokenInfo)
	return tokenInfo, errorutils.CheckError(err)
}

// Use AccessToken from ServiceDetails (which is the default behaviour)
// If that is not present then we can use the token we are refreshing as the token
func (ps *TokenService) addAccessTokenAuthorizationHeader(params CreateTokenParams, httpDetails *httputils.HttpClientDetails) error {
	access := ps.ServiceDetails.GetAccessToken()
	if access == "" {
		access = params.AccessToken
	}
	if access == "" {
		return errorutils.CheckErrorf("failed: adding accessToken authorization, but No accessToken was provided. ")
	}
	utils.AddHeader("Authorization", fmt.Sprintf("Bearer %s", access), &httpDetails.Headers)
	return nil
}
