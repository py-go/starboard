// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	"time"

	v1alpha1 "github.com/danielpacak/kube-security-manager/pkg/apis/aquasecurity/v1alpha1"
	scheme "github.com/danielpacak/kube-security-manager/pkg/generated/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// ClusterConfigAuditReportsGetter has a method to return a ClusterConfigAuditReportInterface.
// A group's client should implement this interface.
type ClusterConfigAuditReportsGetter interface {
	ClusterConfigAuditReports() ClusterConfigAuditReportInterface
}

// ClusterConfigAuditReportInterface has methods to work with ClusterConfigAuditReport resources.
type ClusterConfigAuditReportInterface interface {
	Create(ctx context.Context, clusterConfigAuditReport *v1alpha1.ClusterConfigAuditReport, opts v1.CreateOptions) (*v1alpha1.ClusterConfigAuditReport, error)
	Update(ctx context.Context, clusterConfigAuditReport *v1alpha1.ClusterConfigAuditReport, opts v1.UpdateOptions) (*v1alpha1.ClusterConfigAuditReport, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.ClusterConfigAuditReport, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.ClusterConfigAuditReportList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ClusterConfigAuditReport, err error)
	ClusterConfigAuditReportExpansion
}

// clusterConfigAuditReports implements ClusterConfigAuditReportInterface
type clusterConfigAuditReports struct {
	client rest.Interface
}

// newClusterConfigAuditReports returns a ClusterConfigAuditReports
func newClusterConfigAuditReports(c *AquasecurityV1alpha1Client) *clusterConfigAuditReports {
	return &clusterConfigAuditReports{
		client: c.RESTClient(),
	}
}

// Get takes name of the clusterConfigAuditReport, and returns the corresponding clusterConfigAuditReport object, and an error if there is any.
func (c *clusterConfigAuditReports) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.ClusterConfigAuditReport, err error) {
	result = &v1alpha1.ClusterConfigAuditReport{}
	err = c.client.Get().
		Resource("clusterconfigauditreports").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of ClusterConfigAuditReports that match those selectors.
func (c *clusterConfigAuditReports) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.ClusterConfigAuditReportList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.ClusterConfigAuditReportList{}
	err = c.client.Get().
		Resource("clusterconfigauditreports").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested clusterConfigAuditReports.
func (c *clusterConfigAuditReports) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("clusterconfigauditreports").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a clusterConfigAuditReport and creates it.  Returns the server's representation of the clusterConfigAuditReport, and an error, if there is any.
func (c *clusterConfigAuditReports) Create(ctx context.Context, clusterConfigAuditReport *v1alpha1.ClusterConfigAuditReport, opts v1.CreateOptions) (result *v1alpha1.ClusterConfigAuditReport, err error) {
	result = &v1alpha1.ClusterConfigAuditReport{}
	err = c.client.Post().
		Resource("clusterconfigauditreports").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(clusterConfigAuditReport).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a clusterConfigAuditReport and updates it. Returns the server's representation of the clusterConfigAuditReport, and an error, if there is any.
func (c *clusterConfigAuditReports) Update(ctx context.Context, clusterConfigAuditReport *v1alpha1.ClusterConfigAuditReport, opts v1.UpdateOptions) (result *v1alpha1.ClusterConfigAuditReport, err error) {
	result = &v1alpha1.ClusterConfigAuditReport{}
	err = c.client.Put().
		Resource("clusterconfigauditreports").
		Name(clusterConfigAuditReport.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(clusterConfigAuditReport).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the clusterConfigAuditReport and deletes it. Returns an error if one occurs.
func (c *clusterConfigAuditReports) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("clusterconfigauditreports").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *clusterConfigAuditReports) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("clusterconfigauditreports").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched clusterConfigAuditReport.
func (c *clusterConfigAuditReports) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ClusterConfigAuditReport, err error) {
	result = &v1alpha1.ClusterConfigAuditReport{}
	err = c.client.Patch(pt).
		Resource("clusterconfigauditreports").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
