package testcases

//go:generate go run ../main.go --path generics.go --objs Test1,Test2

type Generic[T comparable] struct {
	Value T
}

type Wrapper struct {
	Generic[uint64]
}

type Test1 struct {
	G Wrapper
}

type Generic2[T any, F any] struct {
	Value1 T
	Value2 F
}

type Wrapper2 struct {
	Generic2[uint64, uint16]
}

type Test2 struct {
	G Wrapper2
}
