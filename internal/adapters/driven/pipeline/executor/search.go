package executor

import (
	"context"
	"fmt"
	"time"

	"github.com/sercha-oss/sercha-core/internal/core/domain/pipeline"
	pipelineport "github.com/sercha-oss/sercha-core/internal/core/ports/driven/pipeline"
)

// SearchExecutor executes search pipelines.
type SearchExecutor struct {
	builder          pipelineport.PipelineBuilder
	pipelineRegistry pipelineport.PipelineRegistry
	capRegistry      pipelineport.CapabilityRegistry
	stageRegistry    pipelineport.StageRegistry
}

// NewSearchExecutor creates a new search executor.
func NewSearchExecutor(
	builder pipelineport.PipelineBuilder,
	pipelineRegistry pipelineport.PipelineRegistry,
	capRegistry pipelineport.CapabilityRegistry,
	stageRegistry pipelineport.StageRegistry,
) *SearchExecutor {
	return &SearchExecutor{
		builder:          builder,
		pipelineRegistry: pipelineRegistry,
		capRegistry:      capRegistry,
		stageRegistry:    stageRegistry,
	}
}

// Execute runs a search pipeline.
func (e *SearchExecutor) Execute(
	ctx context.Context,
	sctx *pipeline.SearchContext,
	input *pipeline.SearchInput,
) (*pipeline.SearchOutput, error) {
	startTime := time.Now()
	stageTimings := make(map[string]int64)

	// Get pipeline definition
	def, ok := e.pipelineRegistry.Get(sctx.PipelineID)
	if !ok {
		return nil, fmt.Errorf("pipeline not found: %s", sctx.PipelineID)
	}

	// Apply preference-based stage filtering
	if sctx.Preferences != nil {
		def = e.applyPreferences(def, sctx.Preferences)
	}

	// Collect required capabilities from all stages
	requiredCaps := e.collectRequiredCapabilities(def)

	// Build capability set
	capabilities, err := e.capRegistry.BuildCapabilitySet(requiredCaps)
	if err != nil {
		return nil, fmt.Errorf("failed to build capability set: %w", err)
	}
	sctx.Capabilities = capabilities

	// Build executable pipeline
	execPipeline, err := e.builder.Build(def, capabilities)
	if err != nil {
		return nil, fmt.Errorf("failed to build pipeline: %w", err)
	}

	// Run pipeline with timing
	result, err := e.runWithTiming(ctx, execPipeline, input, stageTimings)
	if err != nil {
		return nil, fmt.Errorf("pipeline execution failed: %w", err)
	}

	// Convert result to SearchOutput
	output, ok := result.(*pipeline.SearchOutput)
	if !ok {
		return nil, fmt.Errorf("unexpected pipeline output type: %T", result)
	}

	// Add timing information
	output.Timing = pipeline.ExecutionTiming{
		TotalMs: time.Since(startTime).Milliseconds(),
		StageMs: stageTimings,
	}

	return output, nil
}

// runWithTiming executes the pipeline while collecting per-stage timing.
func (e *SearchExecutor) runWithTiming(
	ctx context.Context,
	execPipeline pipelineport.ExecutablePipeline,
	input any,
	timings map[string]int64,
) (any, error) {
	current := input
	stages := execPipeline.Stages()

	for _, stage := range stages {
		stageStart := time.Now()
		desc := stage.Descriptor()

		output, err := stage.Process(ctx, current)
		if err != nil {
			return nil, fmt.Errorf("stage %s failed: %w", desc.ID, err)
		}

		timings[desc.ID] = time.Since(stageStart).Milliseconds()
		current = output
	}

	return current, nil
}

// collectRequiredCapabilities collects all capability requirements from pipeline stages.
func (e *SearchExecutor) collectRequiredCapabilities(def pipeline.PipelineDefinition) []pipeline.CapabilityRequirement {
	seen := make(map[pipeline.CapabilityType]pipeline.CapabilityRequirement)

	for _, stageConfig := range def.Stages {
		if !stageConfig.Enabled {
			continue
		}

		// Look up factory via stage registry to get the descriptor
		factory, ok := e.stageRegistry.Get(stageConfig.StageID)
		if !ok {
			continue
		}

		desc := factory.Descriptor()
		for _, req := range desc.Capabilities {
			// Deduplicate by capability type, keeping the strictest mode
			// Required beats Optional beats Fallback
			existing, exists := seen[req.Type]
			if !exists || isStricterMode(req.Mode, existing.Mode) {
				seen[req.Type] = req
			}
		}
	}

	result := make([]pipeline.CapabilityRequirement, 0, len(seen))
	for _, req := range seen {
		result = append(result, req)
	}
	return result
}

// applyPreferences filters pipeline stages based on user preferences.
func (e *SearchExecutor) applyPreferences(def pipeline.PipelineDefinition, prefs *pipeline.StagePreferences) pipeline.PipelineDefinition {
	// Clone stages slice
	stages := make([]pipeline.StageConfig, len(def.Stages))
	copy(stages, def.Stages)

	for i := range stages {
		switch stages[i].StageID {
		case "bm25-retriever":
			if !prefs.BM25SearchEnabled {
				stages[i].Enabled = false
			}
		case "vector-retriever":
			if !prefs.VectorSearchEnabled {
				stages[i].Enabled = false
			}
		case "hybrid-retriever":
			if !prefs.BM25SearchEnabled || !prefs.VectorSearchEnabled {
				stages[i].Enabled = false
			}
		}
	}

	def.Stages = stages
	return def
}

// Ensure SearchExecutor implements the interface.
var _ pipelineport.SearchExecutor = (*SearchExecutor)(nil)
