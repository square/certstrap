package depot

// windows does not allow 0600 permissions so we need to set test tags to be 0666
var (
	tag  = &Tag{"host.pem", 0666}
	tag2 = &Tag{"host2.pem", 0666}
)
