package testcases

//go:generate go run ../main.go --path issue_166.go --include ./other

import "github.com/NilFoundation/fastssz/sszgen/testcases/other"

type Issue165 struct {
	A other.Case4Bytes
}
