package kiro

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	log "github.com/sirupsen/logrus"
)

const (
	kiroCLICallbackAddr        = "localhost:3128"
	kiroCLITokenRedirectURI    = "http://localhost:3128/oauth/callback?login_option=google"
	kiroCLISignInURLTemplate   = "https://app.kiro.dev/signin?state=%s&code_challenge=%s&code_challenge_method=S256&redirect_uri=http%%3A%%2F%%2Flocalhost%%3A3128&redirect_from=kirocli"
	kiroCLITokenEndpoint       = "https://prod.us-east-1.auth.desktop.kiro.dev/oauth/token"
	kiroCLIRefreshEndpoint     = "https://prod.us-east-1.auth.desktop.kiro.dev/refreshToken"
	kiroCLICognitoEndpoint     = "https://cognito-identity.us-east-1.amazonaws.com/"
	kiroCLITelemetryEndpoint   = "https://client-telemetry.us-east-1.amazonaws.com/metrics"
	kiroCLIIdentityPoolID      = "us-east-1:820fd6d1-95c0-4ca4-bffb-3f01d32da842"
	kiroCLITelemetryEvent      = "codewhispererterminal_userLoggedIn"
	kiroCLIRustUserAgent       = "aws-sdk-rust/1.3.10 os/linux lang/rust/1.92.0"
	kiroCLICognitoAmzUserAgent = "aws-sdk-rust/1.3.10 ua/2.1 api/cognitoidentity/1.91.0 os/linux lang/rust/1.92.0 m/E md/http#hyper-1.x app/AmazonQ-For-CLI"
	kiroCLITelemetryAmzUA      = "aws-sdk-rust/1.3.10 ua/2.1 api/toolkittelemetry/1.0.0 os/linux lang/rust/1.92.0 app/AmazonQ-For-CLI"
	kiroCLIProductName         = "CodeWhisperer for Terminal"
	kiroCLIProductVersion      = "2.0.0"
	kiroCLIAuthTimeout         = 10 * time.Minute
	kiroCLITelemetryTimeout    = 15 * time.Second
	kiroCLITelemetryService    = "execute-api"
	kiroCLITelemetryRegion     = "us-east-1"
	kiroCLITelemetrySignedPath = "/metrics"
)

type KiroCLIOAuth struct {
	httpClient *http.Client
}

type cliCallbackResult struct {
	Code  string
	State string
	Err   string
}

type cliTokenExchangeRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
}

type cognitoGetIDResponse struct {
	IdentityID string `json:"IdentityId"`
}

type cognitoGetCredentialsResponse struct {
	IdentityID  string `json:"IdentityId"`
	Credentials struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretKey       string `json:"SecretKey"`
		SessionToken    string `json:"SessionToken"`
		ExpirationEpoch int64  `json:"Expiration"`
	} `json:"Credentials"`
}

type telemetryTemporaryCredentials struct {
	AccessKeyID  string
	SecretKey    string
	SessionToken string
}

func NewKiroCLIOAuth(cfg *config.Config) *KiroCLIOAuth {
	client := &http.Client{Timeout: 30 * time.Second}
	if cfg != nil {
		client = util.SetProxy(&cfg.SDKConfig, client)
	}
	return &KiroCLIOAuth{httpClient: client}
}

func buildKiroCLISignInURL(state, challenge string) string {
	return fmt.Sprintf(kiroCLISignInURLTemplate, state, challenge)
}

func generateKiroCLIState() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const stateLen = 10

	b := make([]byte, stateLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate state bytes: %w", err)
	}

	out := make([]byte, stateLen)
	for i := range b {
		out[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(out), nil
}

func generateKiroCLIPKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("failed to generate verifier bytes: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}

func (o *KiroCLIOAuth) startCallbackServer(ctx context.Context, expectedState string) (<-chan cliCallbackResult, func(context.Context) error, error) {
	listener, err := net.Listen("tcp", kiroCLICallbackAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to bind callback listener on %s: %w", kiroCLICallbackAddr, err)
	}

	resultCh := make(chan cliCallbackResult, 1)
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		code := strings.TrimSpace(r.URL.Query().Get("code"))
		state := strings.TrimSpace(r.URL.Query().Get("state"))
		errValue := strings.TrimSpace(r.URL.Query().Get("error"))

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if errValue != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "<html><body><h1>Login failed</h1><p>You can close this window.</p></body></html>")
			resultCh <- cliCallbackResult{Err: errValue}
			return
		}

		if state != expectedState {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "<html><body><h1>State mismatch</h1><p>You can close this window.</p></body></html>")
			resultCh <- cliCallbackResult{Err: "state mismatch"}
			return
		}

		if code == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "<html><body><h1>Missing code</h1><p>You can close this window.</p></body></html>")
			resultCh <- cliCallbackResult{Err: "missing code"}
			return
		}

		_, _ = io.WriteString(w, "<html><body><h1>Login successful</h1><p>You can close this window.</p></body></html>")
		resultCh <- cliCallbackResult{Code: code, State: state}
	})
	server.Handler = mux

	go func() {
		if errServe := server.Serve(listener); errServe != nil && errServe != http.ErrServerClosed {
			log.Debugf("kiro-cli oauth callback server error: %v", errServe)
		}
	}()

	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(kiroCLIAuthTimeout):
		}
		_ = server.Shutdown(context.Background())
	}()

	return resultCh, server.Shutdown, nil
}

func (o *KiroCLIOAuth) exchangeCodeForToken(ctx context.Context, code, verifier string) (*KiroTokenData, error) {
	body, err := json.Marshal(cliTokenExchangeRequest{
		Code:         code,
		CodeVerifier: verifier,
		RedirectURI:  kiroCLITokenRedirectURI,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal token exchange payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, kiroCLITokenEndpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to create token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Kiro-CLI")
	req.Header.Set("Accept", "*/*")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token exchange response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed (status %d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var tokenResp KiroTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token exchange response: %w", err)
	}

	expiresIn := tokenResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}

	return &KiroTokenData{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ProfileArn:   tokenResp.ProfileArn,
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second).Format(time.RFC3339),
		AuthMethod:   "kiro-cli",
		Provider:     "Google",
		Region:       "us-east-1",
		Email:        ExtractEmailFromJWT(tokenResp.AccessToken),
	}, nil
}

func (o *KiroCLIOAuth) RefreshToken(ctx context.Context, refreshToken string) (*KiroTokenData, error) {
	payload, err := json.Marshal(map[string]string{"refreshToken": refreshToken})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal refresh payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, kiroCLIRefreshEndpoint, strings.NewReader(string(payload)))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Kiro-CLI")
	req.Header.Set("Accept", "*/*")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh failed (status %d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var tokenResp KiroTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse refresh response: %w", err)
	}

	expiresIn := tokenResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}

	return &KiroTokenData{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ProfileArn:   tokenResp.ProfileArn,
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second).Format(time.RFC3339),
		AuthMethod:   "kiro-cli",
		Provider:     "Google",
		Region:       "us-east-1",
		Email:        ExtractEmailFromJWT(tokenResp.AccessToken),
	}, nil
}

func (o *KiroCLIOAuth) LoginWithCLI(ctx context.Context, noBrowser bool) (*KiroTokenData, error) {
	state, err := generateKiroCLIState()
	if err != nil {
		return nil, err
	}

	verifier, challenge, err := generateKiroCLIPKCE()
	if err != nil {
		return nil, err
	}

	callbackCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	callbackResult, shutdown, err := o.startCallbackServer(callbackCtx, state)
	if err != nil {
		return nil, err
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = shutdown(shutdownCtx)
	}()

	signInURL := buildKiroCLISignInURL(state, challenge)
	if noBrowser {
		fmt.Printf("Open this URL in browser to continue login:\n%s\n", signInURL)
	} else if errOpen := browser.OpenURL(signInURL); errOpen != nil {
		log.Warnf("kiro-cli oauth: failed to open browser: %v", errOpen)
		fmt.Printf("Open this URL in browser to continue login:\n%s\n", signInURL)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(kiroCLIAuthTimeout):
		return nil, fmt.Errorf("kiro-cli oauth login timed out")
	case cb := <-callbackResult:
		if cb.Err != "" {
			return nil, fmt.Errorf("oauth callback error: %s", cb.Err)
		}
		if cb.State != state {
			return nil, fmt.Errorf("oauth state mismatch")
		}

		tokenData, errExchange := o.exchangeCodeForToken(ctx, cb.Code, verifier)
		if errExchange != nil {
			return nil, errExchange
		}

		go func(token string) {
			defer func() {
				if r := recover(); r != nil {
					log.Debugf("recovered from telemetry panic: %v", r)
				}
			}()

			telemetryCtx, telemetryCancel := context.WithTimeout(context.Background(), kiroCLITelemetryTimeout)
			defer telemetryCancel()
			if errTelemetry := o.sendLoginTelemetry(telemetryCtx, token); errTelemetry != nil {
				log.Debugf("kiro-cli telemetry skipped: %v", errTelemetry)
			}
		}(tokenData.AccessToken)

		return tokenData, nil
	}
}

func (o *KiroCLIOAuth) sendLoginTelemetry(ctx context.Context, accessToken string) error {
	creds, err := o.fetchTelemetryCredentials(ctx, accessToken)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	telemetryClientID := uuid.NewString()
	osName := normalizeTelemetryOS(runtime.GOOS)
	osArch := runtime.GOARCH
	if osArch == "amd64" {
		osArch = "x86_64"
	}
	payload := map[string]any{
		"AWSProduct":        kiroCLIProductName,
		"AWSProductVersion": kiroCLIProductVersion,
		"ClientID":          telemetryClientID,
		"MetricData": []map[string]any{
			{
				"MetricName":     kiroCLITelemetryEvent,
				"EpochTimestamp": now.UnixMilli(),
				"Unit":           "None",
				"Value":          1.0,
				"Metadata": []map[string]string{
					{"Key": "credentialStartUrl", "Value": ""},
					{"Key": "codewhispererterminal_inCloudshell", "Value": "false"},
				},
			},
		},
		"OS":             osName,
		"OSArchitecture": osArch,
		"OSVersion":      osName,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal telemetry payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, kiroCLITelemetryEndpoint, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("failed to create telemetry request: %w", err)
	}

	o.signTelemetryRequest(req, body, creds, now)

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("telemetry request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		respBody, _ := io.ReadAll(resp.Body)
		log.Warnf("kiro-cli telemetry returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		return fmt.Errorf("telemetry status %d", resp.StatusCode)
	}

	return nil
}

func (o *KiroCLIOAuth) fetchTelemetryCredentials(ctx context.Context, accessToken string) (*telemetryTemporaryCredentials, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, fmt.Errorf("empty access token")
	}

	var getIDResp cognitoGetIDResponse
	if err := o.callCognitoIdentity(ctx,
		"AWSCognitoIdentityService.GetId",
		map[string]any{
			"IdentityPoolId": kiroCLIIdentityPoolID,
		},
		&getIDResp,
	); err != nil {
		return nil, err
	}

	if strings.TrimSpace(getIDResp.IdentityID) == "" {
		return nil, fmt.Errorf("empty identity id from cognito")
	}

	var credResp cognitoGetCredentialsResponse
	if err := o.callCognitoIdentity(ctx,
		"AWSCognitoIdentityService.GetCredentialsForIdentity",
		map[string]any{
			"IdentityId": getIDResp.IdentityID,
		},
		&credResp,
	); err != nil {
		return nil, err
	}

	if strings.TrimSpace(credResp.Credentials.AccessKeyID) == "" || strings.TrimSpace(credResp.Credentials.SecretKey) == "" {
		return nil, fmt.Errorf("empty temporary credentials from cognito")
	}

	return &telemetryTemporaryCredentials{
		AccessKeyID:  credResp.Credentials.AccessKeyID,
		SecretKey:    credResp.Credentials.SecretKey,
		SessionToken: credResp.Credentials.SessionToken,
	}, nil
}

func (o *KiroCLIOAuth) callCognitoIdentity(ctx context.Context, target string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal cognito payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, kiroCLICognitoEndpoint, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("failed to create cognito request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)
	req.Header.Set("User-Agent", kiroCLIRustUserAgent)
	req.Header.Set("X-Amz-User-Agent", kiroCLICognitoAmzUserAgent)
	req.Header.Set("Amz-Sdk-Request", "attempt=1; max=1")
	req.Header.Set("Amz-Sdk-Invocation-Id", uuid.NewString())
	req.Header.Set("Accept", "*/*")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("cognito request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read cognito response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cognito %s failed (status %d): %s", target, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("failed to parse cognito response for %s: %w", target, err)
	}

	return nil
}

func (o *KiroCLIOAuth) signTelemetryRequest(req *http.Request, body []byte, creds *telemetryTemporaryCredentials, now time.Time) {
	if req == nil || creds == nil {
		return
	}

	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")
	payloadHash := sha256Hex(body)
	host := req.URL.Host
	contentLength := strconv.Itoa(len(body))

	req.Header.Set("Host", host)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", kiroCLIRustUserAgent)
	req.Header.Set("X-Amz-User-Agent", kiroCLITelemetryAmzUA)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	req.ContentLength = int64(len(body))

	canonicalHeaders := strings.Join([]string{
		"content-length:" + contentLength + "\n",
		"content-type:" + req.Header.Get("Content-Type") + "\n",
		"host:" + host + "\n",
		"x-amz-date:" + amzDate + "\n",
		"x-amz-security-token:" + creds.SessionToken + "\n",
		"x-amz-user-agent:" + req.Header.Get("X-Amz-User-Agent") + "\n",
	}, "")
	signedHeaders := "content-length;content-type;host;x-amz-date;x-amz-security-token;x-amz-user-agent"

	canonicalRequest := strings.Join([]string{
		req.Method,
		kiroCLITelemetrySignedPath,
		"",
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, kiroCLITelemetryRegion, kiroCLITelemetryService)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := sigV4SigningKey(creds.SecretKey, dateStamp, kiroCLITelemetryRegion, kiroCLITelemetryService)
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	authorization := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		creds.AccessKeyID,
		credentialScope,
		signedHeaders,
		signature,
	)

	req.Header.Set("Authorization", authorization)
}

func sigV4SigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

func hmacSHA256(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(value))
	return h.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func normalizeTelemetryOS(goos string) string {
	switch strings.ToLower(strings.TrimSpace(goos)) {
	case "darwin":
		return "macos"
	default:
		return strings.ToLower(goos)
	}
}
