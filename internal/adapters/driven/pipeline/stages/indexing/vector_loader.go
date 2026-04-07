package indexing

import (
	"context"
	"log/slog"

	"github.com/sercha-oss/sercha-core/internal/core/domain/pipeline"
	"github.com/sercha-oss/sercha-core/internal/core/ports/driven"
	pipelineport "github.com/sercha-oss/sercha-core/internal/core/ports/driven/pipeline"
)

const VectorLoaderStageID = "vector-loader"

// VectorLoaderFactory creates vector loader stages.
type VectorLoaderFactory struct {
	descriptor pipeline.StageDescriptor
}

// NewVectorLoaderFactory creates a new vector loader factory.
func NewVectorLoaderFactory() *VectorLoaderFactory {
	return &VectorLoaderFactory{
		descriptor: pipeline.StageDescriptor{
			ID:          VectorLoaderStageID,
			Name:        "Vector Loader",
			Type:        pipeline.StageTypeLoader,
			InputShape:  pipeline.ShapeEmbeddedChunk,
			OutputShape: pipeline.ShapeIndexedDoc,
			Cardinality: pipeline.CardinalityManyToOne,
			Capabilities: []pipeline.CapabilityRequirement{
				{Type: pipeline.CapabilityVectorStore, Mode: pipeline.CapabilityRequired},
			},
			Version: "1.0.0",
		},
	}
}

// StageID returns the stage identifier.
func (f *VectorLoaderFactory) StageID() string {
	return f.descriptor.ID
}

// Descriptor returns the stage descriptor.
func (f *VectorLoaderFactory) Descriptor() pipeline.StageDescriptor {
	return f.descriptor
}

// Create creates a new vector loader stage.
func (f *VectorLoaderFactory) Create(config pipeline.StageConfig, capabilities *pipeline.CapabilitySet) (pipelineport.Stage, error) {
	// Get vector store from capabilities
	inst, ok := capabilities.Get(pipeline.CapabilityVectorStore)
	if !ok {
		return nil, &StageError{Stage: f.descriptor.ID, Message: "vector_store capability not available"}
	}

	vectorIndex, ok := inst.Instance.(driven.VectorIndex)
	if !ok {
		return nil, &StageError{Stage: f.descriptor.ID, Message: "invalid vector_store instance type"}
	}

	return &VectorLoaderStage{
		descriptor:  f.descriptor,
		vectorIndex: vectorIndex,
	}, nil
}

// Validate validates the stage configuration.
func (f *VectorLoaderFactory) Validate(config pipeline.StageConfig) error {
	return nil
}

// VectorLoaderStage persists embeddings to the vector index.
type VectorLoaderStage struct {
	descriptor  pipeline.StageDescriptor
	vectorIndex driven.VectorIndex
}

// Descriptor returns the stage descriptor.
func (s *VectorLoaderStage) Descriptor() pipeline.StageDescriptor {
	return s.descriptor
}

// Process persists chunk embeddings to the vector index.
func (s *VectorLoaderStage) Process(ctx context.Context, input any) (any, error) {
	chunks, ok := input.([]*pipeline.Chunk)
	if !ok {
		return nil, &StageError{Stage: s.descriptor.ID, Message: "expected []*pipeline.Chunk"}
	}

	if len(chunks) == 0 {
		return &pipeline.IndexingOutput{}, nil
	}

	// Filter to only chunks that have embeddings
	var ids []string
	var embeddings [][]float32
	for _, chunk := range chunks {
		if len(chunk.Embedding) > 0 {
			ids = append(ids, chunk.ID)
			embeddings = append(embeddings, chunk.Embedding)
		}
	}

	// If no chunks have embeddings, return empty output (no error)
	if len(ids) == 0 {
		slog.Warn("no chunks with embeddings to index",
			"document_id", chunks[0].DocumentID,
			"chunk_count", len(chunks))
		return &pipeline.IndexingOutput{
			DocumentID: chunks[0].DocumentID,
			ChunkIDs:   []string{},
		}, nil
	}

	// Index embeddings to vector store
	if err := s.vectorIndex.IndexBatch(ctx, ids, embeddings); err != nil {
		return nil, &StageError{Stage: s.descriptor.ID, Message: "failed to index embeddings", Err: err}
	}

	// Get document ID from first chunk
	documentID := ""
	if len(chunks) > 0 {
		documentID = chunks[0].DocumentID
	}

	return &pipeline.IndexingOutput{
		DocumentID: documentID,
		ChunkIDs:   ids,
	}, nil
}

// Ensure VectorLoaderFactory implements StageFactory.
var _ pipelineport.StageFactory = (*VectorLoaderFactory)(nil)

// Ensure VectorLoaderStage implements Stage.
var _ pipelineport.Stage = (*VectorLoaderStage)(nil)
