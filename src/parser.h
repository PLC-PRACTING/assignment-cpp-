#pragma once

#include "token.h"
#include "ast.h"
#include <vector>
#include <memory>

class Parser {
private:
    std::vector<Token> tokens;
    size_t current;
    
    bool isEnd() const;
    const Token& peek() const;  // 返回引用避免拷贝
    const Token& peekNext() const;
    const Token& advance();
    bool match(TokenType type);
    bool check(TokenType type) const;
    const Token& consume(TokenType type, const std::string& message);
    
    // Parsing methods
    std::unique_ptr<Program> parseProgram();
    std::unique_ptr<FunctionDeclaration> parseFunctionDeclaration();
    std::vector<Parameter> parseParameters();
    std::unique_ptr<BlockStatement> parseBlock();
    StatementPtr parseStatement();
    StatementPtr parseIfStatement();
    StatementPtr parseWhileStatement();
    StatementPtr parseReturnStatement();
    StatementPtr parseBreakStatement();
    StatementPtr parseContinueStatement();
    StatementPtr parseAssignOrVarDeclStatement();
    StatementPtr parseExpressionStatement();
    
    ExpressionPtr parseExpression();
    ExpressionPtr parseLogicalOr();
    ExpressionPtr parseLogicalAnd();
    ExpressionPtr parseRelational();
    ExpressionPtr parseAdditive();
    ExpressionPtr parseMultiplicative();
    ExpressionPtr parseUnary();
    ExpressionPtr parsePrimary();
    ExpressionPtr parseCall(ExpressionPtr expr);
    
    DataType parseType();
    
public:
    explicit Parser(std::vector<Token> tokens);
    std::unique_ptr<Program> parse();
};