package depot

const (
	// 0440 is not supported on Windows, so our permissions checks fail,
	// causing permission denied errors for Windows users.
	BranchPerm = 0444
	LeafPerm   = 0444
)
