package ossindex

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIntegrationGetComponentReports(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client, err := NewClient()
	require.NoError(t, err)

	coordinates := []string{"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10.7"}

	reports, err := client.getComponentReportsInternal(context.TODO(), coordinates)
	require.NoError(t, err)
	require.NotEmpty(t, reports)
}
