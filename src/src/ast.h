#pragma once

#include <memory>
#include <vector>
#include <string>

// Forward declarations
class ASTNode;
class Expression;
class Statement;
class Declaration;

using ASTNodePtr = std::unique_ptr<ASTNode>;
using ExpressionPtr = std::unique_ptr<Expression>;
using StatementPtr = std::unique_ptr<Statement>;
using DeclarationPtr = std::unique_ptr<Declaration>;

enum class NodeType {
    // Expressions
    BINARY_EXPR,
    UNARY_EXPR,
    LITERAL_EXPR,
    VARIABLE_EXPR,
    CALL_EXPR,
    
    // Statements
    BLOCK_STMT,
    EXPR_STMT,
    IF_STMT,
    WHILE_STMT,
    BREAK_STMT,
    CONTINUE_STMT,
    RETURN_STMT,
    ASSIGN_STMT,
    VAR_DECL_STMT,
    
    // Declarations
    FUNCTION_DECL,
    PARAM_DECL,
    
    // Program
    PROGRAM
};

enum class BinaryOp {
    ADD, SUB, MUL, DIV, MOD,
    LT, GT, LE, GE, EQ, NE,
    AND, OR
};

enum class UnaryOp {
    PLUS, MINUS, NOT
};

enum class DataType {
    INT,
    VOID
};

class ASTNode {
public:
    NodeType type;
    virtual ~ASTNode() = default;
    
protected:
    explicit ASTNode(NodeType t) : type(t) {}
};

class Expression : public ASTNode {
public:
    DataType dataType = DataType::INT;
    
protected:
    explicit Expression(NodeType t) : ASTNode(t) {}
};

class BinaryExpression : public Expression {
public:
    BinaryOp op;
    ExpressionPtr left;
    ExpressionPtr right;
    
    BinaryExpression(BinaryOp op, ExpressionPtr left, ExpressionPtr right)
        : Expression(NodeType::BINARY_EXPR), op(op), left(std::move(left)), right(std::move(right)) {}
};

class UnaryExpression : public Expression {
public:
    UnaryOp op;
    ExpressionPtr operand;
    
    UnaryExpression(UnaryOp op, ExpressionPtr operand)
        : Expression(NodeType::UNARY_EXPR), op(op), operand(std::move(operand)) {}
};

class LiteralExpression : public Expression {
public:
    int value;
    
    explicit LiteralExpression(int value)
        : Expression(NodeType::LITERAL_EXPR), value(value) {}
};

class VariableExpression : public Expression {
public:
    std::string name;
    
    explicit VariableExpression(const std::string& name)
        : Expression(NodeType::VARIABLE_EXPR), name(name) {}
};

class CallExpression : public Expression {
public:
    std::string functionName;
    std::vector<ExpressionPtr> arguments;
    
    CallExpression(const std::string& name, std::vector<ExpressionPtr> args)
        : Expression(NodeType::CALL_EXPR), functionName(name), arguments(std::move(args)) {}
};

class Statement : public ASTNode {
protected:
    explicit Statement(NodeType t) : ASTNode(t) {}
};

class BlockStatement : public Statement {
public:
    std::vector<StatementPtr> statements;
    
    explicit BlockStatement(std::vector<StatementPtr> statements)
        : Statement(NodeType::BLOCK_STMT), statements(std::move(statements)) {}
};

class ExpressionStatement : public Statement {
public:
    ExpressionPtr expression;
    
    explicit ExpressionStatement(ExpressionPtr expr)
        : Statement(NodeType::EXPR_STMT), expression(std::move(expr)) {}
};

class IfStatement : public Statement {
public:
    ExpressionPtr condition;
    StatementPtr thenStmt;
    StatementPtr elseStmt;
    
    IfStatement(ExpressionPtr condition, StatementPtr thenStmt, StatementPtr elseStmt = nullptr)
        : Statement(NodeType::IF_STMT), condition(std::move(condition)), 
          thenStmt(std::move(thenStmt)), elseStmt(std::move(elseStmt)) {}
};

class WhileStatement : public Statement {
public:
    ExpressionPtr condition;
    StatementPtr body;
    
    WhileStatement(ExpressionPtr condition, StatementPtr body)
        : Statement(NodeType::WHILE_STMT), condition(std::move(condition)), body(std::move(body)) {}
};

class BreakStatement : public Statement {
public:
    BreakStatement() : Statement(NodeType::BREAK_STMT) {}
};

class ContinueStatement : public Statement {
public:
    ContinueStatement() : Statement(NodeType::CONTINUE_STMT) {}
};

class ReturnStatement : public Statement {
public:
    ExpressionPtr expression;
    
    explicit ReturnStatement(ExpressionPtr expr = nullptr)
        : Statement(NodeType::RETURN_STMT), expression(std::move(expr)) {}
};

class AssignStatement : public Statement {
public:
    std::string variable;
    ExpressionPtr expression;
    
    AssignStatement(const std::string& var, ExpressionPtr expr)
        : Statement(NodeType::ASSIGN_STMT), variable(var), expression(std::move(expr)) {}
};

class VarDeclStatement : public Statement {
public:
    std::string name;
    ExpressionPtr initializer;
    
    VarDeclStatement(const std::string& name, ExpressionPtr init)
        : Statement(NodeType::VAR_DECL_STMT), name(name), initializer(std::move(init)) {}
};

class Parameter {
public:
    std::string name;
    DataType type;
    
    Parameter(const std::string& name, DataType type) : name(name), type(type) {}
};

class FunctionDeclaration : public ASTNode {
public:
    std::string name;
    DataType returnType;
    std::vector<Parameter> parameters;
    std::unique_ptr<BlockStatement> body;
    
    FunctionDeclaration(const std::string& name, DataType returnType, 
                       std::vector<Parameter> params, std::unique_ptr<BlockStatement> body)
        : ASTNode(NodeType::FUNCTION_DECL), name(name), returnType(returnType),
          parameters(std::move(params)), body(std::move(body)) {}
};

class Program : public ASTNode {
public:
    std::vector<std::unique_ptr<FunctionDeclaration>> functions;
    
    explicit Program(std::vector<std::unique_ptr<FunctionDeclaration>> functions)
        : ASTNode(NodeType::PROGRAM), functions(std::move(functions)) {}
};