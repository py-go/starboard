package kubebench

import (
	"io"

	"github.com/danielpacak/kube-security-manager/pkg/apis/aquasecurity/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

// Plugin defines the interface between Starboard and Kubernetes configuration
// checker with CIS Kubernetes Benchmarks.
type Plugin interface {

	// GetScanJobSpec describes the pod that will be created by Starboard when
	// it schedules a Kubernetes job to audit the configuration of the specified
	// node.
	GetScanJobSpec(node corev1.Node) (corev1.PodSpec, error)

	// ParseCISKubeBenchReportData is a callback to parse and convert logs of
	// the pod controlled by the scan job to v1alpha1.CISKubeBenchReportData.
	ParseCISKubeBenchReportData(logsStream io.ReadCloser) (v1alpha1.CISKubeBenchReportData, error)

	GetContainerName() string
}
