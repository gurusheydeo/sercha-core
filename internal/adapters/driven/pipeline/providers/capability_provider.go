package providers

import (
	"github.com/sercha-oss/sercha-core/internal/core/domain/pipeline"
	pipelineport "github.com/sercha-oss/sercha-core/internal/core/ports/driven/pipeline"
)

// CapabilityProvider wraps a service as a pipeline capability provider.
type CapabilityProvider struct {
	CapType          pipeline.CapabilityType
	ProviderID       string
	Inst             any
	AvailFn          func() bool
	InstanceResolver func() any // Optional: resolve instance dynamically
}

func (p *CapabilityProvider) Type() pipeline.CapabilityType { return p.CapType }
func (p *CapabilityProvider) ID() string                    { return p.ProviderID }

func (p *CapabilityProvider) Instance() any {
	if p.InstanceResolver != nil {
		return p.InstanceResolver()
	}
	return p.Inst
}

func (p *CapabilityProvider) Available() bool {
	if p.AvailFn != nil {
		return p.AvailFn()
	}
	return p.Inst != nil
}

var _ pipelineport.CapabilityProvider = (*CapabilityProvider)(nil)
