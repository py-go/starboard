// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1alpha1 "github.com/danielpacak/kube-security-manager/pkg/apis/aquasecurity/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeCISKubeBenchReports implements CISKubeBenchReportInterface
type FakeCISKubeBenchReports struct {
	Fake *FakeAquasecurityV1alpha1
}

var ciskubebenchreportsResource = schema.GroupVersionResource{Group: "aquasecurity.github.io", Version: "v1alpha1", Resource: "ciskubebenchreports"}

var ciskubebenchreportsKind = schema.GroupVersionKind{Group: "aquasecurity.github.io", Version: "v1alpha1", Kind: "CISKubeBenchReport"}

// Get takes name of the cISKubeBenchReport, and returns the corresponding cISKubeBenchReport object, and an error if there is any.
func (c *FakeCISKubeBenchReports) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.CISKubeBenchReport, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(ciskubebenchreportsResource, name), &v1alpha1.CISKubeBenchReport{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CISKubeBenchReport), err
}

// List takes label and field selectors, and returns the list of CISKubeBenchReports that match those selectors.
func (c *FakeCISKubeBenchReports) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.CISKubeBenchReportList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(ciskubebenchreportsResource, ciskubebenchreportsKind, opts), &v1alpha1.CISKubeBenchReportList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.CISKubeBenchReportList{ListMeta: obj.(*v1alpha1.CISKubeBenchReportList).ListMeta}
	for _, item := range obj.(*v1alpha1.CISKubeBenchReportList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested cISKubeBenchReports.
func (c *FakeCISKubeBenchReports) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(ciskubebenchreportsResource, opts))
}

// Create takes the representation of a cISKubeBenchReport and creates it.  Returns the server's representation of the cISKubeBenchReport, and an error, if there is any.
func (c *FakeCISKubeBenchReports) Create(ctx context.Context, cISKubeBenchReport *v1alpha1.CISKubeBenchReport, opts v1.CreateOptions) (result *v1alpha1.CISKubeBenchReport, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(ciskubebenchreportsResource, cISKubeBenchReport), &v1alpha1.CISKubeBenchReport{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CISKubeBenchReport), err
}

// Update takes the representation of a cISKubeBenchReport and updates it. Returns the server's representation of the cISKubeBenchReport, and an error, if there is any.
func (c *FakeCISKubeBenchReports) Update(ctx context.Context, cISKubeBenchReport *v1alpha1.CISKubeBenchReport, opts v1.UpdateOptions) (result *v1alpha1.CISKubeBenchReport, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(ciskubebenchreportsResource, cISKubeBenchReport), &v1alpha1.CISKubeBenchReport{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CISKubeBenchReport), err
}

// Delete takes name of the cISKubeBenchReport and deletes it. Returns an error if one occurs.
func (c *FakeCISKubeBenchReports) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(ciskubebenchreportsResource, name, opts), &v1alpha1.CISKubeBenchReport{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeCISKubeBenchReports) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(ciskubebenchreportsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.CISKubeBenchReportList{})
	return err
}

// Patch applies the patch and returns the patched cISKubeBenchReport.
func (c *FakeCISKubeBenchReports) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.CISKubeBenchReport, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(ciskubebenchreportsResource, name, pt, data, subresources...), &v1alpha1.CISKubeBenchReport{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CISKubeBenchReport), err
}
