package db_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"
)

// goPolicyTypes returns the value of every constant declared with type PolicyType in
// internal/types, so a new policy type cannot be added in Go without the database knowing it.
func goPolicyTypes(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob("../types/*.go")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range files {
		if filepath.Ext(f) != ".go" || len(f) > 8 && f[len(f)-8:] == "_test.go" {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				ident, ok := vs.Type.(*ast.Ident)
				if !ok || ident.Name != "PolicyType" {
					continue
				}
				for i, name := range vs.Names {
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					v, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					out[name.Name] = v
				}
			}
		}
	}
	if len(out) < 10 {
		t.Fatalf("found only %d PolicyType constants; the parser is not finding them", len(out))
	}
	return out
}

// Every PolicyType in Go must be a value of the policy_type enum, or creating that
// policy fails at insert time.
func TestPolicyTypeEnumCoversGoTypes(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	rows, err := pool.Query(context.Background(), `SELECT unnest(enum_range(NULL::policy_type))::text`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	inDB := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		inDB[v] = true
	}
	for name, v := range goPolicyTypes(t) {
		if !inDB[v] {
			t.Errorf("types.%s = %q is not in the policy_type enum; add a migration", name, v)
		}
	}
}
