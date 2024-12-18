package generator

import (
	"fmt"
	"strconv"
	"strings"
)

// size creates a function that returns the SSZ size of the struct. There are two components:
// 1. Fixed: Size that we can determine at compilation time (i.e. uint, fixed bytes, fixed vector...)
// 2. Dynamic: Size that depends on the input (i.e. lists, dynamic containers...)
// Note that if any of the internal fields of the struct is nil, we will not fail, only not add up
// that field to the size. It is up to other methods like marshal to fail on that scenario.
func (e *env) size(name string, v *Value) string {
	tmpl := `// SizeSSZ returns the ssz encoded size in bytes for the {{.name}} object
	func (:: *{{.name}}) SizeSSZ() (size int) {
		size = {{.fixed}}{{if .dynamic}}

		{{.dynamic}}
		{{end}}
		return
	}
	{{.fieldsMaxSizes}}
	`

	str := execTmpl(tmpl, map[string]interface{}{
		"name":           name,
		"fixed":          v.fixedSize(),
		"dynamic":        v.sizeContainer("size", true),
		"fieldsMaxSizes": v.fieldsMaxSizes(name),
	})
	return appendObjSignature(str, v)
}

func (v *Value) fieldsMaxSizes(name string) string {
	out := []string{}
	for _, v := range v.o {
		if !v.isFixed() {
			out = append(out, fmt.Sprintf("const %sMax%sSize = %d", name, v.name, v.s))
		}
	}
	return strings.Join(out, "\n")
}

func (v *Value) fixedSize() uint64 {
	switch v.t {
	case TypeVector:
		if v.e == nil {
			panic(fmt.Sprintf("error computing size of empty vector %v for type name=%s", v, v.name))
		}
		if v.e.isFixed() {
			return v.s * v.e.fixedSize()
		} else {
			return v.s * bytesPerLengthOffset
		}
	case TypeContainer:
		var fixed uint64
		for _, f := range v.o {
			if f.isFixed() {
				fixed += f.fixedSize()
			} else {
				// we don't want variable size objects to recursively calculate their inner sizes
				fixed += bytesPerLengthOffset
			}
		}
		return fixed
	default:
		if !v.isFixed() {
			return bytesPerLengthOffset
		}
		return v.s
	}
}

func (v *Value) sizeContainer(name string, start bool) string {
	if !start {
		tmpl := `{{if .check}} if ::.{{.name}} == nil {
			::.{{.name}} = new({{ref .obj}})
		}
		{{end}} {{ .dst }} += ::.{{.name}}.SizeSSZ()`

		check := true
		if v.isListElem() {
			check = false
		}
		if v.noPtr {
			check = false
		}
		return execTmpl(tmpl, map[string]interface{}{
			"name":  v.name,
			"dst":   name,
			"obj":   v,
			"check": check,
		})
	}
	out := []string{}
	for indx, v := range v.o {
		if !v.isFixed() {
			out = append(out, fmt.Sprintf("// Field (%d) '%s'\n%s", indx, v.name, v.size(name)))
		}
	}
	return strings.Join(out, "\n\n")
}

// 'name' is the name of target variable we assign the size too. We also use this function
// during marshalling to figure out the size of the offset
func (v *Value) size(name string) string {
	if v.isFixed() {
		if v.t == TypeContainer {
			return v.sizeContainer(name, false)
		}
		if v.fixedSize() == 1 {
			return name + "++"
		}
		return name + " += " + strconv.Itoa(int(v.fixedSize()))
	}

	switch v.t {
	case TypeContainer, TypeReference:
		return v.sizeContainer(name, false)

	case TypeBitList:
		fallthrough

	case TypeBytes:
		return fmt.Sprintf(name+" += len(::.%s)", v.name)

	case TypeList:
		fallthrough

	case TypeVector:
		if v.e.isFixed() {
			return fmt.Sprintf("%s += len(::.%s) * %d", name, v.name, v.e.fixedSize())
		}
		v.e.name = v.name + "[ii]"
		tmpl := `for ii := 0; ii < len(::.{{.name}}); ii++ {
			{{.size}} += 4
			{{.dynamic}}
		}`
		return execTmpl(tmpl, map[string]interface{}{
			"name":    v.name,
			"size":    name,
			"dynamic": v.e.size(name),
		})

	default:
		panic(fmt.Errorf("size not implemented for type %s", v.t.String()))
	}
}
