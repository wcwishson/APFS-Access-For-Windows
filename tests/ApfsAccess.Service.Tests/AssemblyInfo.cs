using Xunit;

// Several lifecycle tests intentionally change process-wide runtime-root state.
// Keep the service assembly deterministic instead of racing those environment
// changes against tests in another collection.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
