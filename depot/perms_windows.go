package depot

const (
	// 0440 is not supported on Windows (which only allows for all-read or all-write permissions)
	// Because our permissions checking requires permissions to meet a minimum criteria,
	// requiring 0440 for the leaf perm (key files) in windows will cause the permissions check to fail,
	// resulting permission denied errors for Windows users.
	BranchPerm = 0444
	LeafPerm   = 0444
)
