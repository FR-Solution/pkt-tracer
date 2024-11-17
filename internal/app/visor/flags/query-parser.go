package flags

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/parser"
	"github.com/expr-lang/expr/parser/operator"
)

func init() {
	operator.Binary[","] = operator.Binary["||"]
	operator.Binary["OR"] = operator.Binary["or"]
	operator.Binary["Or"] = operator.Binary["or"]
	operator.Binary["AND"] = operator.Binary["and"]
	operator.Binary["And"] = operator.Binary["and"]
	operator.Binary["IN"] = operator.Binary["in"]
	operator.Binary["In"] = operator.Binary["in"]
}

type (
	query struct {
		cmd      string
		argToSql map[string]string
	}
)

func NewQueryParser(cmd string, argToSql map[string]string) *query {
	var q query
	q.formatInput(cmd, argToSql)
	return &q
}

func (q *query) formatInput(cmd string, argToSql map[string]string) {
	if q.argToSql == nil {
		q.argToSql = make(map[string]string, len(argToSql))
	}
	for k, v := range argToSql {
		q.argToSql[strings.ReplaceAll(k, "-", "_")] = v
	}
	re := regexp.MustCompile(`'[^']*'|"[^"]*"`)

	cmdSplits := re.Split(cmd, -1)

	for i, split := range cmdSplits {
		cmdSplits[i] = strings.ReplaceAll(split, "-", "_")
	}

	interIdxs := re.FindAllStringIndex(cmd, -1)
	for i, interIdx := range interIdxs {
		q.cmd += cmdSplits[i] + cmd[interIdx[0]:interIdx[1]]
	}
	q.cmd += cmdSplits[len(cmdSplits)-1]
}

func (q *query) astToSql(node ast.Node) (string, error) {
	switch n := node.(type) {
	case *ast.BinaryNode:
		op := n.Operator
		switch n.Operator {
		case "==":
			op = "="
		case "||", "or": //nolint:goconst
			op = "OR"
		case "&&", "and":
			op = "AND" //nolint:goconst
		case "in":
			op = "IN"
		}

		left, err := q.astToSql(n.Left)
		if err != nil {
			return "", err
		}

		right, err := q.astToSql(n.Right)
		if err != nil {
			return "", err
		}

		if l, ok := n.Left.(*ast.BinaryNode); ok {
			if (l.Operator == "||" || l.Operator == "or") && op == "AND" {
				left = "(" + left + ")"
			}
		}
		if r, ok := n.Right.(*ast.BinaryNode); ok {
			if (r.Operator == "||" || r.Operator == "or" || r.Operator == ",") &&
				(op == "AND" || op == "IN") {
				right = "(" + right + ")"
			}
		}

		if op != "," {
			op = " " + op + " "
		}
		return fmt.Sprintf("%s%s%s", left, op, right), nil

	case *ast.UnaryNode:
		val, err := q.astToSql(n.Node)
		if err != nil {
			return "", err
		}
		op := n.Operator
		if op == "!" {
			op = "NOT"
		}
		if n, ok := n.Node.(*ast.BinaryNode); ok {
			if n.Operator == "in" {
				return strings.Replace(val, " IN ", " NOT IN ", 1), nil
			}

			val = "(" + val + ")"
		}
		return fmt.Sprintf("%s %s", op, val), nil

	case *ast.IdentifierNode:
		sqlArg, ok := q.argToSql[n.Value]
		if !ok {
			return "", fmt.Errorf("%s is invalid query parameter", n.Value)
		}
		return sqlArg, nil
	case *ast.StringNode:
		return "'" + n.Value + "'", nil
	case *ast.IntegerNode:
		return fmt.Sprintf("%d", n.Value), nil
	default:
		return "", fmt.Errorf("unknown node type %T", n)
	}
}

func (q *query) ToSql() (string, error) {
	tree, err := parser.Parse(q.cmd)
	if err != nil {
		return "", err
	}
	return q.astToSql(tree.Node)
}
