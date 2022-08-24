package plugin

import (
	"fmt"

	"github.com/danielpacak/kube-security-manager/pkg/ext"
	"github.com/danielpacak/kube-security-manager/pkg/plugin/trivy"
	"github.com/danielpacak/kube-security-manager/pkg/starboard"
	"github.com/danielpacak/kube-security-manager/pkg/vulnerabilityreport"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	Trivy starboard.Scanner = "Trivy"
)

type Resolver struct {
	buildInfo          starboard.BuildInfo
	config             starboard.ConfigData
	namespace          string
	serviceAccountName string
	client             client.Client
}

func NewResolver() *Resolver {
	return &Resolver{}
}

func (r *Resolver) WithBuildInfo(buildInfo starboard.BuildInfo) *Resolver {
	r.buildInfo = buildInfo
	return r
}

func (r *Resolver) WithConfig(config starboard.ConfigData) *Resolver {
	r.config = config
	return r
}

func (r *Resolver) WithNamespace(namespace string) *Resolver {
	r.namespace = namespace
	return r
}

func (r *Resolver) WithServiceAccountName(name string) *Resolver {
	r.serviceAccountName = name
	return r
}

func (r *Resolver) WithClient(client client.Client) *Resolver {
	r.client = client
	return r
}

// GetVulnerabilityPlugin is a factory method that instantiates the vulnerabilityreport.Plugin.
//
// Starboard currently supports Trivy scanner in Standalone and ClientServer
// mode.
//
// You could add your own scanner by implementing the vulnerabilityreport.Plugin interface.
func (r *Resolver) GetVulnerabilityPlugin() (vulnerabilityreport.Plugin, starboard.PluginContext, error) {
	scanner, err := r.config.GetVulnerabilityReportsScanner()
	if err != nil {
		return nil, nil, err
	}

	pluginContext := starboard.NewPluginContext().
		WithName(string(scanner)).
		WithNamespace(r.namespace).
		WithServiceAccountName(r.serviceAccountName).
		WithClient(r.client).
		WithStarboardConfig(r.config).
		Get()

	switch scanner {
	case Trivy:
		return trivy.NewPlugin(ext.NewSystemClock(), ext.NewGoogleUUIDGenerator(), r.client), pluginContext, nil
	}
	return nil, nil, fmt.Errorf("unsupported vulnerability scanner plugin: %s", scanner)
}
