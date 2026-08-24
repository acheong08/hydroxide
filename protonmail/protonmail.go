// Package protonmail implements a ProtonMail API client.
package protonmail

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

const Version = 3

const headerAPIVersion = "X-Pm-Apiversion"

type HumanVerificationDetails struct {
	Token   string   `json:"HumanVerificationToken"`
	Methods []string `json:"HumanVerificationMethods"`
	Title   string   `json:"Title"`
}

type resp struct {
	Code    int                       `json:"Code"`
	Details *HumanVerificationDetails `json:"Details"`
	*RawAPIError
}

func (r *resp) Err() error {
	if err := r.RawAPIError; err != nil {
		return &APIError{
			Code:    r.Code,
			Message: err.Message,
			Details: r.Details,
		}
	}
	if r.Code != 1000 && r.Code != 1001 && r.Code != 0 {
		// For 9001 the Error field may be present alongside Details
		if r.Code == 9001 {
			return &APIError{
				Code:    r.Code,
				Message: "Human verification required",
				Details: r.Details,
			}
		}
	}
	return nil
}

type maybeError interface {
	Err() error
}

type RawAPIError struct {
	Message string `json:"Error"`
}

type APIError struct {
	Code    int
	Message string
	Details *HumanVerificationDetails
}

func (err *APIError) Error() string {
	if err.Details != nil && err.Details.Token != "" {
		return fmt.Sprintf("[%v] %v (HV token: %v methods: %v)", err.Code, err.Message, err.Details.Token, err.Details.Methods)
	}
	return fmt.Sprintf("[%v] %v", err.Code, err.Message)
}

const humanVerificationCode = 9001
const hvTokenHeader = "X-Pm-Human-Verification-Token"
const hvTokenTypeHeader = "X-Pm-Human-Verification-Token-Type"

type Timestamp int64

func NewTimestamp(t time.Time) Timestamp {
	return Timestamp(t.Unix())
}

func (t Timestamp) Time() time.Time {
	return time.Unix(int64(t), 0)
}

// Client is a ProtonMail API client.
type Client struct {
	RootURL    string
	AppVersion string
	Debug      bool

	HTTPClient *http.Client
	ReAuth     func() error

	uid         string
	accessToken string
	keyRing     openpgp.EntityList
}

func (c *Client) setRequestAuthorization(req *http.Request) {
	if c.uid != "" && c.accessToken != "" {
		req.Header.Set("X-Pm-Uid", c.uid)
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}
}

func (c *Client) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, c.RootURL+path, body)
	if err != nil {
		return nil, err
	}

	if c.Debug {
		log.Printf(">> %v %v\n", req.Method, req.URL.Path)
	}

	req.Header.Set("X-Pm-Appversion", c.AppVersion)
	req.Header.Set(headerAPIVersion, strconv.Itoa(Version))
	c.setRequestAuthorization(req)
	return req, nil
}

func (c *Client) newJSONRequest(method, path string, body interface{}) (*http.Request, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return nil, err
	}
	b := buf.Bytes()

	req, err := c.newRequest(method, path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	if c.Debug {
		log.Print(string(b))
	}

	req.Header.Set("Content-Type", "application/json")
	req.GetBody = func() (io.ReadCloser, error) {
		return ioutil.NopCloser(bytes.NewReader(b)), nil
	}
	return req, nil
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0")

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return resp, err
	}

	// Check if access token has expired
	_, hasAuth := req.Header["Authorization"]
	canRetry := req.Body == nil || req.GetBody != nil
	if resp.StatusCode == http.StatusUnauthorized && hasAuth && c.ReAuth != nil && canRetry {
		resp.Body.Close()
		c.accessToken = ""
		if err := c.ReAuth(); err != nil {
			return resp, err
		}
		c.setRequestAuthorization(req) // Access token has changed
		if req.Body != nil {
			body, err := req.GetBody()
			if err != nil {
				return resp, err
			}
			req.Body = body
		}
		return c.do(req)
	}

	return resp, nil
}

func (c *Client) doJSON(req *http.Request, respData interface{}) error {
	return c.doJSONWithHVRetry(req, respData, false)
}

func (c *Client) doJSONWithHVRetry(req *http.Request, respData interface{}, retried bool) error {
	req.Header.Set("Accept", "application/json")

	if respData == nil {
		respData = new(resp)
	}

	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Need to buffer body for potential debug + second decode after HV
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(bodyBytes, respData); err != nil {
		return err
	}

	if c.Debug {
		log.Printf("<< %v %v", req.Method, req.URL.Path)
		log.Printf("%#v", respData)
		log.Printf("raw: %s", string(bodyBytes))
	}

	if maybeError, ok := respData.(maybeError); ok {
		if err := maybeError.Err(); err != nil {
			// Handle human verification (CAPTCHA) - free accounts without Sentinel
			if apiErr, ok := err.(*APIError); ok && apiErr.Code == humanVerificationCode && !retried {
				details := apiErr.Details
				// Try to extract Details from raw JSON if not already parsed via resp struct
				if details == nil || details.Token == "" {
					var raw struct {
						Details *HumanVerificationDetails `json:"Details"`
					}
					if json.Unmarshal(bodyBytes, &raw) == nil && raw.Details != nil {
						details = raw.Details
						apiErr.Details = details
					}
				}
				if details != nil && details.Token != "" {
					token := details.Token
					methods := details.Methods
					if len(methods) == 0 {
						methods = []string{"captcha"}
					}
					method := methods[0]
					verifyURL := fmt.Sprintf("https://verify.proton.me/?token=%s&methods=%s", token, strings.Join(methods, ","))
					// Also try embed URL as proton-sdk does
					embedURL := fmt.Sprintf("https://verify.proton.me/?embed=1&methods=%s&token=%s", strings.Join(methods, ","), token)

					// Allow non-interactive override via env
					envHV := os.Getenv("FERROXIDE_HV_TOKEN")
					if envHV == "" {
						envHV = os.Getenv("HYDROXIDE_HV_TOKEN")
					}

					var hvToken, hvType string
					if envHV != "" {
						hvToken = strings.TrimSpace(envHV)
						hvType = method
						fmt.Fprintf(os.Stderr, "\n=== Human Verification Required (CAPTCHA) ===\n")
						fmt.Fprintf(os.Stderr, "Using verification token from environment (%s)\n", hvTokenHeader)
					} else {
						fmt.Fprintf(os.Stderr, "\n=== Human Verification Required (CAPTCHA) ===\n")
						fmt.Fprintf(os.Stderr, "Proton returned code 9001. Free accounts can solve without Sentinel.\n")
						fmt.Fprintf(os.Stderr, "Challenge token: %s (methods: %s)\n", token, strings.Join(methods, ","))
						fmt.Fprintf(os.Stderr, "\nOPTION A - Try challenge token (works if verify.proton.me marks server-side):\n")
						fmt.Fprintf(os.Stderr, "  1) Open in browser and solve CAPTCHA:\n     %s\n", verifyURL)
						fmt.Fprintf(os.Stderr, "     (or embed: %s)\n", embedURL)
						fmt.Fprintf(os.Stderr, "  2) Return here and press ENTER to retry with challenge token.\n")
						fmt.Fprintf(os.Stderr, "\nOPTION B - If OPTION A still returns 9001/1000 CAPTCHA, you need the SOLVED token:\n")
						fmt.Fprintf(os.Stderr, "  1) Open the embed URL above, BEFORE solving open DevTools (F12) -> Console\n")
						fmt.Fprintf(os.Stderr, "  2) Paste and run: window.addEventListener('message', e=>console.log('HV_SOLVED_TOKEN:', e.data))\n")
						fmt.Fprintf(os.Stderr, "  3) Solve CAPTCHA, console will log HV_SOLVED_TOKEN (long string like captcha--...)\n")
						fmt.Fprintf(os.Stderr, "  4) Copy that token and paste it below.\n")
						fmt.Fprintf(os.Stderr, "  Alternatively, after solving check DevTools -> Application -> Local Storage -> https://verify.proton.me\n")
						fmt.Fprintf(os.Stderr, "\nPaste SOLVED token here (or press ENTER to try challenge token):\n> ")

						reader := bufio.NewReader(os.Stdin)
						input, _ := reader.ReadString('\n')
						input = strings.TrimSpace(input)

						hvToken = token
						hvType = method
						if input != "" {
							hvToken = input
							if strings.Contains(input, "--") {
								hvType = "captcha"
							}
							fmt.Fprintf(os.Stderr, "Using pasted SOLVED verification token (type %s)\n", hvType)
						} else {
							fmt.Fprintf(os.Stderr, "Retrying with challenge token (after browser verification)...\n")
							fmt.Fprintf(os.Stderr, "If this still fails with [9001] or [1000] CAPTCHA, re-run and paste the SOLVED token from Console.\n")
						}
					}

					// Clone request for retry - need to reset body
					if req.GetBody == nil && req.Body != nil {
						log.Printf("cannot retry human verification: request has no GetBody")
						return err
					}
					// Set HV headers for retry
					req.Header.Set(hvTokenHeader, hvToken)
					req.Header.Set(hvTokenTypeHeader, hvType)

					// Reset body if needed
					if req.GetBody != nil {
						newBody, err := req.GetBody()
						if err != nil {
							return err
						}
						req.Body = newBody
					}

					// Clear respData to avoid stale fields (json.Unmarshal doesn't clear missing fields)
					if respData != nil {
						rv := reflect.ValueOf(respData)
						if rv.Kind() == reflect.Ptr && !rv.IsNil() {
							rv.Elem().Set(reflect.Zero(rv.Elem().Type()))
						}
					}
					log.Printf("Retrying request with human verification token (type=%s)...", hvType)
					return c.doJSONWithHVRetry(req, respData, true)
				}
			}
			log.Printf("request failed: %v %v: %v", req.Method, req.URL.String(), err)
			return err
		}
	}
	return nil
}
