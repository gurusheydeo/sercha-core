package indexing

import (
	"context"
	"log/slog"
	"time"

	"github.com/sercha-oss/sercha-core/internal/core/domain"
	"github.com/sercha-oss/sercha-core/internal/core/domain/pipeline"
	"github.com/sercha-oss/sercha-core/internal/core/ports/driven"
	pipelineport "github.com/sercha-oss/sercha-core/internal/core/ports/driven/pipeline"
)

const BM25LoaderStageID = "bm25-loader"

// BM25LoaderFactory creates BM25 loader stages.
type BM25LoaderFactory struct {
	descriptor pipeline.StageDescriptor
}

// NewBM25LoaderFactory creates a new BM25 loader factory.
func NewBM25LoaderFactory() *BM25LoaderFactory {
	return &BM25LoaderFactory{
		descriptor: pipeline.StageDescriptor{
			ID:          BM25LoaderStageID,
			Name:        "BM25 Loader",
			Type:        pipeline.StageTypeLoader,
			InputShape:  pipeline.ShapeChunk,
			OutputShape: pipeline.ShapeChunk,
			Cardinality: pipeline.CardinalityManyToMany,
			Capabilities: []pipeline.CapabilityRequirement{
				{Type: pipeline.CapabilitySearchEngine, Mode: pipeline.CapabilityRequired},
			},
			Version: "1.0.0",
		},
	}
}

// StageID returns the stage identifier.
func (f *BM25LoaderFactory) StageID() string {
	return f.descriptor.ID
}

// Descriptor returns the stage descriptor.
func (f *BM25LoaderFactory) Descriptor() pipeline.StageDescriptor {
	return f.descriptor
}

// Create creates a new BM25 loader stage.
func (f *BM25LoaderFactory) Create(config pipeline.StageConfig, capabilities *pipeline.CapabilitySet) (pipelineport.Stage, error) {
	// Get search engine from capabilities
	inst, ok := capabilities.Get(pipeline.CapabilitySearchEngine)
	if !ok {
		return nil, &StageError{Stage: f.descriptor.ID, Message: "search_engine capability not available"}
	}

	searchEngine, ok := inst.Instance.(driven.SearchEngine)
	if !ok {
		return nil, &StageError{Stage: f.descriptor.ID, Message: "invalid search_engine instance type"}
	}

	return &BM25LoaderStage{
		descriptor:   f.descriptor,
		searchEngine: searchEngine,
	}, nil
}

// Validate validates the stage configuration.
func (f *BM25LoaderFactory) Validate(config pipeline.StageConfig) error {
	return nil
}

// BM25LoaderStage persists chunks to the search engine for BM25 text indexing.
type BM25LoaderStage struct {
	descriptor   pipeline.StageDescriptor
	searchEngine driven.SearchEngine
}

// Descriptor returns the stage descriptor.
func (s *BM25LoaderStage) Descriptor() pipeline.StageDescriptor {
	return s.descriptor
}

// Process persists chunks to the search engine and passes them through for downstream stages.
func (s *BM25LoaderStage) Process(ctx context.Context, input any) (any, error) {
	chunks, ok := input.([]*pipeline.Chunk)
	if !ok {
		return nil, &StageError{Stage: s.descriptor.ID, Message: "expected []*pipeline.Chunk"}
	}

	if len(chunks) == 0 {
		return chunks, nil
	}

	// Convert pipeline chunks to domain chunks for indexing
	domainChunks := make([]*domain.Chunk, len(chunks))
	for i, chunk := range chunks {
		domainChunks[i] = &domain.Chunk{
			ID:         chunk.ID,
			DocumentID: chunk.DocumentID,
			SourceID:   "", // Will be set by caller context
			Content:    chunk.Content,
			Embedding:  chunk.Embedding,
			Position:   chunk.Position,
			StartChar:  chunk.StartOffset,
			EndChar:    chunk.EndOffset,
			CreatedAt:  time.Now(),
		}
	}

	// Index chunks to search engine (BM25 text indexing)
	if err := s.searchEngine.Index(ctx, domainChunks); err != nil {
		return nil, &StageError{Stage: s.descriptor.ID, Message: "failed to index chunks", Err: err}
	}

	slog.Info("indexed chunks for BM25 search",
		"document_id", chunks[0].DocumentID,
		"chunk_count", len(chunks))

	// Pass through chunks for downstream stages (embedder, vector-loader)
	return chunks, nil
}

// Ensure BM25LoaderFactory implements StageFactory.
var _ pipelineport.StageFactory = (*BM25LoaderFactory)(nil)

// Ensure BM25LoaderStage implements Stage.
var _ pipelineport.Stage = (*BM25LoaderStage)(nil)
