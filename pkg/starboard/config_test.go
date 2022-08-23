package starboard_test

import (
	"context"
	"testing"

	"github.com/danielpacak/kube-security-manager/pkg/starboard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/fake"
)

func TestConfigData_GetVulnerabilityReportsScanner(t *testing.T) {
	testCases := []struct {
		name            string
		configData      starboard.ConfigData
		expectedError   string
		expectedScanner starboard.Scanner
	}{
		{
			name: "Should return Trivy",
			configData: starboard.ConfigData{
				"vulnerabilityReports.scanner": "Trivy",
			},
			expectedScanner: "Trivy",
		},
		{
			name: "Should return Aqua",
			configData: starboard.ConfigData{
				"vulnerabilityReports.scanner": "Aqua",
			},
			expectedScanner: "Aqua",
		},
		{
			name:          "Should return error when value is not set",
			configData:    starboard.ConfigData{},
			expectedError: "property vulnerabilityReports.scanner not set",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanner, err := tc.configData.GetVulnerabilityReportsScanner()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedScanner, scanner)
			}
		})
	}
}

func TestConfigData_GetConfigAuditReportsScanner(t *testing.T) {
	testCases := []struct {
		name            string
		configData      starboard.ConfigData
		expectedError   string
		expectedScanner starboard.Scanner
	}{
		{
			name: "Should return Polaris",
			configData: starboard.ConfigData{
				"configAuditReports.scanner": "Polaris",
			},
			expectedScanner: "Polaris",
		},
		{
			name: "Should return Conftest",
			configData: starboard.ConfigData{
				"configAuditReports.scanner": "Conftest",
			},
			expectedScanner: "Conftest",
		},
		{
			name:          "Should return error when value is not set",
			configData:    starboard.ConfigData{},
			expectedError: "property configAuditReports.scanner not set",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanner, err := tc.configData.GetConfigAuditReportsScanner()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedScanner, scanner)
			}
		})
	}
}

func TestConfigData_GetScanJobTolerations(t *testing.T) {
	testCases := []struct {
		name        string
		config      starboard.ConfigData
		expected    []corev1.Toleration
		expectError string
	}{
		{
			name:     "no scanJob.tolerations in ConfigData",
			config:   starboard.ConfigData{},
			expected: []corev1.Toleration(nil),
		},
		{
			name:        "scanJob.tolerations value is not json",
			config:      starboard.ConfigData{"scanJob.tolerations": `lolwut`},
			expected:    []corev1.Toleration(nil),
			expectError: "invalid character 'l' looking for beginning of value",
		},
		{
			name:     "empty JSON array",
			config:   starboard.ConfigData{"scanJob.tolerations": `[]`},
			expected: []corev1.Toleration{},
		},
		{
			name: "one valid toleration",
			config: starboard.ConfigData{
				"scanJob.tolerations": `[{"key":"key1","operator":"Equal","value":"value1","effect":"NoSchedule"}]`},
			expected: []corev1.Toleration{{
				Key:      "key1",
				Operator: "Equal",
				Value:    "value1",
				Effect:   "NoSchedule",
			}},
		},
		{
			name: "multiple valid tolerations",
			config: starboard.ConfigData{
				"scanJob.tolerations": `[{"key":"key1","operator":"Equal","value":"value1","effect":"NoSchedule"},
					  {"key":"key2","operator":"Equal","value":"value2","effect":"NoSchedule"}]`},
			expected: []corev1.Toleration{
				{
					Key:      "key1",
					Operator: "Equal",
					Value:    "value1",
					Effect:   "NoSchedule",
				},
				{
					Key:      "key2",
					Operator: "Equal",
					Value:    "value2",
					Effect:   "NoSchedule",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.config.GetScanJobTolerations()
			if tc.expectError != "" {
				assert.Error(t, err, "unexpected end of JSON input", tc.name)
			} else {
				assert.NoError(t, err, tc.name)
			}
			assert.Equal(t, tc.expected, got, tc.name)
		})
	}
}

func TestConfigData_GetScanJobAnnotations(t *testing.T) {
	testCases := []struct {
		name        string
		config      starboard.ConfigData
		expected    map[string]string
		expectError string
	}{
		{
			name: "scan job annotations can be fetched successfully",
			config: starboard.ConfigData{
				"scanJob.annotations": "a.b=c.d/e,foo=bar",
			},
			expected: map[string]string{
				"foo": "bar",
				"a.b": "c.d/e",
			},
		},
		{
			name:     "gracefully deal with unprovided annotations",
			config:   starboard.ConfigData{},
			expected: map[string]string{},
		},
		{
			name: "raise an error on being provided with annotations in wrong format",
			config: starboard.ConfigData{
				"scanJob.annotations": "foo",
			},
			expected:    map[string]string{},
			expectError: "failed parsing incorrectly formatted custom scan job annotations: foo",
		},
		{
			name: "raise an error on being provided with annotations in wrong format",
			config: starboard.ConfigData{
				"scanJob.annotations": "foo=bar,a=b=c",
			},
			expected:    map[string]string{},
			expectError: "failed parsing incorrectly formatted custom scan job annotations: foo=bar,a=b=c",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanJobAnnotations, err := tc.config.GetScanJobAnnotations()
			if tc.expectError != "" {
				assert.EqualError(t, err, tc.expectError, tc.name)
			} else {
				assert.NoError(t, err, tc.name)
				assert.Equal(t, tc.expected, scanJobAnnotations, tc.name)
			}
		})
	}
}

func TestConfigData_GetScanJobPodTemplateLabels(t *testing.T) {
	testCases := []struct {
		name        string
		config      starboard.ConfigData
		expected    labels.Set
		expectError string
	}{
		{
			name: "scan job template labels can be fetched successfully",
			config: starboard.ConfigData{
				"scanJob.podTemplateLabels": "a.b=c.d/e,foo=bar",
			},
			expected: labels.Set{
				"foo": "bar",
				"a.b": "c.d/e",
			},
		},
		{
			name:     "gracefully deal with unprovided annotations",
			config:   starboard.ConfigData{},
			expected: labels.Set{},
		},
		{
			name: "raise an error on being provided with annotations in wrong format",
			config: starboard.ConfigData{
				"scanJob.podTemplateLabels": "foo",
			},
			expected:    labels.Set{},
			expectError: "failed parsing incorrectly formatted custom scan pod template labels: foo",
		},
		{
			name: "raise an error on being provided with template labels in wrong format",
			config: starboard.ConfigData{
				"scanJob.podTemplateLabels": "foo=bar,a=b=c",
			},
			expected:    labels.Set{},
			expectError: "failed parsing incorrectly formatted custom scan pod template labels: foo=bar,a=b=c",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanJobPodTemplateLabels, err := tc.config.GetScanJobPodTemplateLabels()
			if tc.expectError != "" {
				assert.EqualError(t, err, tc.expectError, tc.name)
			} else {
				assert.NoError(t, err, tc.name)
				assert.Equal(t, tc.expected, scanJobPodTemplateLabels, tc.name)
			}
		})
	}
}

func TestConfigData_GetKubeBenchImageRef(t *testing.T) {
	testCases := []struct {
		name             string
		configData       starboard.ConfigData
		expectedError    string
		expectedImageRef string
	}{
		{
			name:          "Should return error",
			configData:    starboard.ConfigData{},
			expectedError: "property kube-bench.imageRef not set",
		},
		{
			name: "Should return image reference from config data",
			configData: starboard.ConfigData{
				"kube-bench.imageRef": "gcr.io/aquasecurity/kube-bench:0.4.0",
			},
			expectedImageRef: "gcr.io/aquasecurity/kube-bench:0.4.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			imageRef, err := tc.configData.GetKubeBenchImageRef()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedImageRef, imageRef)
			}
		})
	}
}

func TestGetVersionFromImageRef(t *testing.T) {
	testCases := []struct {
		imageRef        string
		expectedVersion string
	}{
		{
			imageRef:        "docker.io/aquasec/trivy:0.9.1",
			expectedVersion: "0.9.1",
		},
		{
			imageRef:        "docker.io/aquasec/trivy@sha256:5020dac24a63ef4f24452a0c63ebbfe93a5309e40f6353d1ee8221d2184ee954",
			expectedVersion: "sha256:5020dac24a63ef4f24452a0c63ebbfe93a5309e40f6353d1ee8221d2184ee954",
		},
		{
			imageRef:        "aquasec/trivy:0.9.1",
			expectedVersion: "0.9.1",
		},
		{
			imageRef:        "aquasec/trivy:latest",
			expectedVersion: "latest",
		},
		{
			imageRef:        "aquasec/trivy",
			expectedVersion: "latest",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.imageRef, func(t *testing.T) {
			version, _ := starboard.GetVersionFromImageRef(tc.imageRef)
			assert.Equal(t, tc.expectedVersion, version)
		})
	}
}

func TestConfigManager_Read(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: starboard.NamespaceName,
				Name:      starboard.ConfigMapName,
			},
			Data: map[string]string{
				"foo": "bar",
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: starboard.NamespaceName,
				Name:      starboard.SecretName,
			},
			Data: map[string][]byte{
				"baz": []byte("s3cret"),
			},
		},
	)

	data, err := starboard.NewConfigManager(clientset, starboard.NamespaceName).
		Read(context.TODO())

	require.NoError(t, err)
	assert.Equal(t, starboard.ConfigData{
		"foo": "bar",
		"baz": "s3cret",
	}, data)
}

func TestConfigManager_Delete(t *testing.T) {

	t.Run("Should not return error when ConfigMap and secret do not exist", func(t *testing.T) {
		clientset := fake.NewSimpleClientset()
		err := starboard.NewConfigManager(clientset, starboard.NamespaceName).Delete(context.TODO())
		require.NoError(t, err)
	})

	t.Run("Should delete ConfigMap and secret", func(t *testing.T) {
		clientset := fake.NewSimpleClientset(
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: starboard.NamespaceName,
					Name:      starboard.ConfigMapName,
				},
				Data: map[string]string{
					"foo": "bar",
				},
			},
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: starboard.NamespaceName,
					Name:      starboard.SecretName,
				},
				Data: map[string][]byte{
					"baz": []byte("s3cret"),
				},
			},
		)

		err := starboard.NewConfigManager(clientset, starboard.NamespaceName).Delete(context.TODO())
		require.NoError(t, err)

		_, err = clientset.CoreV1().ConfigMaps(starboard.NamespaceName).
			Get(context.TODO(), starboard.ConfigMapName, metav1.GetOptions{})
		assert.True(t, errors.IsNotFound(err))

		_, err = clientset.CoreV1().Secrets(starboard.NamespaceName).
			Get(context.TODO(), starboard.SecretName, metav1.GetOptions{})
		assert.True(t, errors.IsNotFound(err))
	})
}
