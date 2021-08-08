package ossindex

import (
	"context"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/require"
)

func TestGetComponentReports(t *testing.T) {
	client, err := NewClient()
	require.NoError(t, err)

	httpmock.ActivateNonDefault(client.httpClient)
	defer httpmock.DeactivateAndReset()

	t.Run("Success", func(t *testing.T) {
		defer httpmock.Reset()

		httpmock.RegisterResponder(http.MethodPost, urlComponentReports,
			httpmock.NewStringResponder(http.StatusOK, `[
	{
		"coordinates": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10.7",
		"description": "General data-binding functionality for Jackson: works on core streaming API",
		"reference": "https://ossindex.sonatype.org/component/pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10.7",
		"vulnerabilities": [
			{
				"id": "3d628ad1-1b5a-4b06-aa06-6af9c81524af",
				"displayName": "CVE-2020-35491",
				"title": "[CVE-2020-35491] FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction betwee...",
				"description": "FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.dbcp2.datasources.SharedPoolDataSource.",
				"cvssScore": 8.1,
				"cvssVector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
				"cve": "CVE-2020-35491",
				"reference": "https://ossindex.sonatype.org/vulnerability/3d628ad1-1b5a-4b06-aa06-6af9c81524af"
			}
		]
	}
]`))

		reports, err := client.GetComponentReports(context.Background(), []string{"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10.7"})
		require.NoError(t, err)
		require.Len(t, reports, 1)

		report := reports[0]
		require.Equal(t, "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10.7", report.Coordinates)
		require.Equal(t, "General data-binding functionality for Jackson: works on core streaming API", report.Description)
		require.Equal(t, "https://ossindex.sonatype.org/component/pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10.7", report.Reference)
		require.Len(t, report.Vulnerabilities, 1)

		vulnerability := report.Vulnerabilities[0]
		require.Equal(t, "3d628ad1-1b5a-4b06-aa06-6af9c81524af", vulnerability.ID)
		require.Equal(t, "CVE-2020-35491", vulnerability.DisplayName)
		require.Equal(t, "[CVE-2020-35491] FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction betwee...", vulnerability.Title)
		require.Equal(t, "FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.dbcp2.datasources.SharedPoolDataSource.", vulnerability.Description)
		require.Equal(t, 8.1, vulnerability.CVSSScore)
		require.Equal(t, "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", vulnerability.CVSSVector)
		require.Equal(t, "CVE-2020-35491", vulnerability.CVE)
		require.Equal(t, "https://ossindex.sonatype.org/vulnerability/3d628ad1-1b5a-4b06-aa06-6af9c81524af", vulnerability.Reference)
	})

	t.Run("Bad Request", func(t *testing.T) {
		defer httpmock.Reset()

		httpmock.RegisterResponder(http.MethodPost, urlComponentReports,
			httpmock.NewStringResponder(http.StatusTooManyRequests, `{
	"code": 400,
	"message": "Request for more than 128 components"
}`))

		_, err := client.GetComponentReports(context.TODO(), []string{"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10.7"})
		require.Error(t, err)

		var apiErr *APIError
		require.ErrorAs(t, err, &apiErr)
		require.Equal(t, 400, apiErr.StatusCode)
		require.Equal(t, "Request for more than 128 components", apiErr.Message)
	})

	t.Run("Unexpected Error", func(t *testing.T) {
		defer httpmock.Reset()

		httpmock.RegisterResponder(http.MethodPost, urlComponentReports,
			httpmock.NewStringResponder(http.StatusInternalServerError, ""))

		_, err := client.GetComponentReports(context.TODO(), []string{"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10.7"})
		require.Error(t, err)
		require.Equal(t, "unexpected status code: 500", err.Error())
	})
}
