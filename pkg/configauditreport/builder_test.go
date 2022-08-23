package configauditreport_test

import (
	. "github.com/onsi/gomega"

	"io"
	"testing"

	"github.com/danielpacak/kube-security-manager/pkg/apis/aquasecurity/v1alpha1"
	"github.com/danielpacak/kube-security-manager/pkg/configauditreport"
	"github.com/danielpacak/kube-security-manager/pkg/kube"
	"github.com/danielpacak/kube-security-manager/pkg/starboard"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestReportBuilder(t *testing.T) {

	t.Run("Should build report for namespaced resource", func(t *testing.T) {
		g := NewGomegaWithT(t)

		report, err := configauditreport.NewReportBuilder(scheme.Scheme).
			Controller(&appsv1.ReplicaSet{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ReplicaSet",
					APIVersion: "apps/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-owner",
					Namespace: "qa",
				},
			}).
			ResourceSpecHash("xyz").
			PluginConfigHash("nop").
			Data(v1alpha1.ConfigAuditReportData{}).
			GetReport()

		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(report).To(Equal(v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "replicaset-some-owner",
				Namespace: "qa",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "apps/v1",
						Kind:               "ReplicaSet",
						Name:               "some-owner",
						Controller:         pointer.BoolPtr(true),
						BlockOwnerDeletion: pointer.BoolPtr(false),
					},
				},
				Labels: map[string]string{
					starboard.LabelResourceKind:      "ReplicaSet",
					starboard.LabelResourceName:      "some-owner",
					starboard.LabelResourceNamespace: "qa",
					starboard.LabelResourceSpecHash:  "xyz",
					starboard.LabelPluginConfigHash:  "nop",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{},
		}))
	})

	t.Run("Should build report for cluster scoped resource", func(t *testing.T) {
		g := NewGomegaWithT(t)

		report, err := configauditreport.NewReportBuilder(scheme.Scheme).
			Controller(&rbacv1.ClusterRole{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ClusterRole",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "system:controller:node-controller",
				},
			}).
			ResourceSpecHash("xyz").
			PluginConfigHash("nop").
			Data(v1alpha1.ConfigAuditReportData{}).
			GetClusterReport()

		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(report).To(Equal(v1alpha1.ClusterConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole-6f69bb5b79",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "rbac.authorization.k8s.io/v1",
						Kind:               "ClusterRole",
						Name:               "system:controller:node-controller",
						Controller:         pointer.BoolPtr(true),
						BlockOwnerDeletion: pointer.BoolPtr(false),
					},
				},
				Labels: map[string]string{
					starboard.LabelResourceKind:      "ClusterRole",
					starboard.LabelResourceNameHash:  "6f69bb5b79",
					starboard.LabelResourceNamespace: "",
					starboard.LabelResourceSpecHash:  "xyz",
					starboard.LabelPluginConfigHash:  "nop",
				},
				Annotations: map[string]string{
					starboard.LabelResourceName: "system:controller:node-controller",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{},
		}))
	})
}

type testPlugin struct {
	configHash string
}

func (p *testPlugin) SupportedKinds() []kube.Kind {
	return []kube.Kind{}
}

func (p *testPlugin) IsApplicable(_ starboard.PluginContext, _ client.Object) (bool, string, error) {
	return true, "", nil
}

func (p *testPlugin) Init(_ starboard.PluginContext) error {
	return nil
}

func (p *testPlugin) GetScanJobSpec(_ starboard.PluginContext, obj client.Object) (corev1.PodSpec, []*corev1.Secret, error) {
	return corev1.PodSpec{}, nil, nil
}

func (p *testPlugin) ParseConfigAuditReportData(_ starboard.PluginContext, logsReader io.ReadCloser) (v1alpha1.ConfigAuditReportData, error) {
	return v1alpha1.ConfigAuditReportData{}, nil
}

func (p *testPlugin) GetContainerName() string {
	return ""
}

func (p *testPlugin) ConfigHash(_ starboard.PluginContext, _ kube.Kind) (string, error) {
	return p.configHash, nil
}
