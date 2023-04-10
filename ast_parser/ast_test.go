package ast_parser

import (
	"context"
	"testing"
)

func TestASTParserInit(t *testing.T) {
	astParser, err := NewASTParser("java")
	if err != nil {
		t.Errorf("Failed to create a new AST Parser")
	}
	rootNode, err := astParser.ParseCodeToAST(context.TODO(), []byte("System.out.println(\"Hello\");"))
	if err != nil {
		t.Errorf("Failed to getAST AST")
	}
	if rootNode.String() != "(program (expression_statement (method_invocation object: (field_access object: (identifier) field: (identifier)) name: (identifier) arguments: (argument_list (string_literal)))))" {
		t.Errorf("Parsing assertion error for rootNode %s", rootNode)
	}
}
