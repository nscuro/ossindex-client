package ossindex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	DefaultTimeout                    = 10 * time.Second
	DefaultUserAgent                  = "github.com/nscuro/ossindex-client"
	contentTypeComponentReport        = "application/vnd.ossindex.component-report.v1+json"
	contentTypeComponentReportRequest = "application/vnd.ossindex.component-report-request.v1+json"
	urlComponentReports               = "https://ossindex.sonatype.org/api/v3/component-report"
)

type Client struct {
	httpClient *http.Client
	userAgent  string
}

// NewClient creates a new client, optionally applying
func NewClient(options ...ClientOption) (*Client, error) {
	client := Client{
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		userAgent: DefaultUserAgent,
	}

	for _, option := range options {
		if err := option(&client); err != nil {
			return nil, err
		}
	}

	return &client, nil
}

type ClientOption func(*Client) error

// WithAuthentication enables authentication using the given credentials.
func WithAuthentication(username, token string) ClientOption {
	return func(c *Client) error {
		if username == "" {
			return fmt.Errorf("no username provided")
		}
		if token == "" {
			return fmt.Errorf("no token provided")
		}

		currentTransport := c.httpClient.Transport
		if currentTransport == nil {
			currentTransport = http.DefaultTransport
		}

		c.httpClient.Transport = &authenticationTransport{
			username:  username,
			token:     token,
			transport: currentTransport,
		}

		return nil
	}
}

// WithTimeout overrides the default timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) error {
		c.httpClient.Timeout = timeout
		return nil
	}
}

// WithUserAgent overrides the default user agent.
func WithUserAgent(userAgent string) ClientOption {
	return func(c *Client) error {
		c.userAgent = userAgent
		return nil
	}
}

type authenticationTransport struct {
	username  string
	token     string
	transport http.RoundTripper
}

func (t authenticationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqCopy := *req // Shallow copy of req

	// Deep copy of request headers, because we'll modify them
	reqCopy.Header = make(http.Header, len(req.Header))
	for hn, hv := range req.Header {
		reqCopy.Header[hn] = append([]string(nil), hv...)
	}

	reqCopy.SetBasicAuth(t.username, t.token)

	return t.transport.RoundTrip(&reqCopy)
}

type APIError struct {
	StatusCode int    `json:"code"`
	Message    string `json:"message"`
}

func (e APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("api error (status: %d)", e.StatusCode)
	}

	return fmt.Sprintf("%s (status: %d)", e.Message, e.StatusCode)
}

type ComponentReport struct {
	Coordinates     string          `json:"coordinates"`
	Description     string          `json:"description"`
	Reference       string          `json:"reference"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type componentReportsRequest struct {
	Coordinates []string `json:"coordinates"`
}

type Vulnerability struct {
	ID            string   `json:"id"`
	DisplayName   string   `json:"displayName"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	CVSSScore     float64  `json:"cvssScore"`
	CVSSVector    string   `json:"cvssVector"`
	CWE           string   `json:"cwe"`
	CVE           string   `json:"cve"`
	Reference     string   `json:"reference"`
	VersionRanges []string `json:"versionRange"`
}

// MaxCoordinatesCount describes the maximum allowed amount of coordinates per request.
const MaxCoordinatesCount = 128

// GetComponentReports requests vulnerability reports for one or more components.
//
// OSS Index enforces a limit of 128 coordinates per request.
// If the given coordinates slice exceeds this limit, Client will chunk them
// and perform multiple requests.
func (c Client) GetComponentReports(ctx context.Context, coordinates []string) ([]ComponentReport, error) {
	reports := make([]ComponentReport, 0)

	for _, chunk := range chunkCoordinates(coordinates) {
		chunkReports, err := c.getComponentReportsInternal(ctx, chunk)
		if err != nil {
			return nil, err
		}

		reports = append(reports, chunkReports...)
	}

	return reports, nil
}

func (c Client) getComponentReportsInternal(ctx context.Context, coordinates []string) ([]ComponentReport, error) {
	buf := new(bytes.Buffer)
	err := json.NewEncoder(buf).Encode(componentReportsRequest{
		Coordinates: coordinates,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlComponentReports, buf)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", contentTypeComponentReport)
	req.Header.Set("Content-Type", contentTypeComponentReportRequest)
	req.Header.Set("User-Agent", c.userAgent)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	err = c.checkResponse(res, http.StatusOK)
	if err != nil {
		return nil, err
	}

	var componentReports []ComponentReport
	err = json.NewDecoder(res.Body).Decode(&componentReports)
	if err != nil {
		return nil, err
	}

	return componentReports, nil
}

// https://stackoverflow.com/a/35179941
func chunkCoordinates(coordinates []string) [][]string {
	var chunks [][]string

	for i := 0; i < len(coordinates); i += MaxCoordinatesCount {
		j := i + MaxCoordinatesCount

		if j > len(coordinates) {
			j = len(coordinates)
		}

		chunks = append(chunks, coordinates[i:j])
	}

	return chunks
}

func (c Client) checkResponse(res *http.Response, expectedStatus int) error {
	if res.StatusCode >= http.StatusBadRequest && res.StatusCode < http.StatusInternalServerError {
		var apiErr APIError
		if err := json.NewDecoder(res.Body).Decode(&apiErr); err != nil {
			apiErr.StatusCode = res.StatusCode
		}

		return &apiErr
	}
	if res.StatusCode != expectedStatus {
		return fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	return nil
}
