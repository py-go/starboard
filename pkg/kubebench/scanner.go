package kubebench

import (
	"encoding/json"
	"io"

	"github.com/danielpacak/kube-security-manager/pkg/apis/aquasecurity/v1alpha1"
	"github.com/danielpacak/kube-security-manager/pkg/ext"
	"github.com/danielpacak/kube-security-manager/pkg/starboard"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
)

const (
	kubeBenchContainerName = "kube-bench"
)

type Config interface {
	GetKubeBenchImageRef() (string, error)
}

type kubeBenchPlugin struct {
	clock  ext.Clock
	config Config
}

// NewKubeBenchPlugin constructs a new Plugin, which is using an official
// Kube-Bench container image, with the specified Config.
func NewKubeBenchPlugin(clock ext.Clock, config Config) Plugin {
	return &kubeBenchPlugin{
		clock:  clock,
		config: config,
	}
}

func (k *kubeBenchPlugin) GetScanJobSpec(node corev1.Node) (corev1.PodSpec, error) {
	imageRef, err := k.config.GetKubeBenchImageRef()
	if err != nil {
		return corev1.PodSpec{}, err
	}
	return corev1.PodSpec{
		ServiceAccountName:           starboard.ServiceAccountName,
		AutomountServiceAccountToken: pointer.BoolPtr(true),
		RestartPolicy:                corev1.RestartPolicyNever,
		HostPID:                      true,
		NodeName:                     node.Name,
		SecurityContext: &corev1.PodSecurityContext{
			RunAsUser:  pointer.Int64Ptr(0),
			RunAsGroup: pointer.Int64Ptr(0),
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			},
		},
		Volumes: []corev1.Volume{
			{
				Name: "var-lib-etcd",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/lib/etcd",
					},
				},
			},
			{
				Name: "var-lib-kubelet",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/lib/kubelet",
					},
				},
			},
			{
				Name: "etc-systemd",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/etc/systemd",
					},
				},
			},
			{
				Name: "etc-kubernetes",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/etc/kubernetes",
					},
				},
			},
			{
				Name: "usr-bin",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/usr/bin",
					},
				},
			},
		},
		Containers: []corev1.Container{
			{
				Name:                     kubeBenchContainerName,
				Image:                    imageRef,
				ImagePullPolicy:          corev1.PullIfNotPresent,
				TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
				Command:                  []string{"sh"},
				Args:                     []string{"-c", "kube-bench --json 2> /dev/null"},
				SecurityContext: &corev1.SecurityContext{
					Privileged:               pointer.BoolPtr(false),
					AllowPrivilegeEscalation: pointer.BoolPtr(false),
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"all"},
					},
					ReadOnlyRootFilesystem: pointer.BoolPtr(true),
				},
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("300m"),
						corev1.ResourceMemory: resource.MustParse("300M"),
					},
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("50m"),
						corev1.ResourceMemory: resource.MustParse("50M"),
					},
				},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "var-lib-etcd",
						MountPath: "/var/lib/etcd",
						ReadOnly:  true,
					},
					{
						Name:      "var-lib-kubelet",
						MountPath: "/var/lib/kubelet",
						ReadOnly:  true,
					},
					{
						Name:      "etc-systemd",
						MountPath: "/etc/systemd",
						ReadOnly:  true,
					},
					{
						Name:      "etc-kubernetes",
						MountPath: "/etc/kubernetes",
						ReadOnly:  true,
					},
					{
						Name:      "usr-bin",
						MountPath: "/usr/local/mount-from-host/bin",
						ReadOnly:  true,
					},
				},
			},
		},
	}, nil
}

func (k *kubeBenchPlugin) ParseCISKubeBenchReportData(logsStream io.ReadCloser) (v1alpha1.CISKubeBenchReportData, error) {
	output := &struct {
		Controls []v1alpha1.CISKubeBenchSection `json:"Controls"`
	}{}

	decoder := json.NewDecoder(logsStream)
	err := decoder.Decode(output)
	if err != nil {
		return v1alpha1.CISKubeBenchReportData{}, err
	}

	imageRef, err := k.config.GetKubeBenchImageRef()
	if err != nil {
		return v1alpha1.CISKubeBenchReportData{}, err
	}
	version, err := starboard.GetVersionFromImageRef(imageRef)
	if err != nil {
		return v1alpha1.CISKubeBenchReportData{}, err
	}

	return v1alpha1.CISKubeBenchReportData{
		Scanner: v1alpha1.Scanner{
			Name:    "kube-bench",
			Vendor:  "Aqua Security",
			Version: version,
		},
		Summary:         k.summary(output.Controls),
		UpdateTimestamp: metav1.NewTime(k.clock.Now()),
		Sections:        output.Controls,
	}, nil
}

func (k *kubeBenchPlugin) summary(sections []v1alpha1.CISKubeBenchSection) v1alpha1.CISKubeBenchSummary {
	totalPass := 0
	totalInfo := 0
	totalWarn := 0
	totalFail := 0

	for _, section := range sections {
		totalPass += section.TotalPass
		totalInfo += section.TotalInfo
		totalWarn += section.TotalWarn
		totalFail += section.TotalFail
	}

	return v1alpha1.CISKubeBenchSummary{
		PassCount: totalPass,
		InfoCount: totalInfo,
		WarnCount: totalWarn,
		FailCount: totalFail,
	}
}

func (k *kubeBenchPlugin) GetContainerName() string {
	return kubeBenchContainerName
}
