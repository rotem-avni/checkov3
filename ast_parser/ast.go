package ast_parser

import (
	"context"
	"fmt"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/python"
)

var languages = map[string]*sitter.Language{
	"python":     python.GetLanguage(),
	"javaScript": javascript.GetLanguage(),
	"java":       java.GetLanguage(),
}

type ASTParser struct {
	parser sitter.Parser
}

func NewASTParser(language string) (*ASTParser, error) {
	parser := sitter.NewParser()
	parser.SetLanguage(languages[language])

	astParser := &ASTParser{
		parser: *parser,
	}
	return astParser, nil
}

func (astParser *ASTParser) ParseCodeToAST(ctx context.Context, content []byte) (*sitter.Node, error) {
	tree, err := astParser.parser.ParseCtx(ctx, nil, content)
	if err != nil {
		fmt.Sprintf("ASTParser error parsing content: %s", err)
		return nil, err
	}
	// TODO: traverse tree and extend nodes according to language specific implementation
	return tree.RootNode(), nil
}
