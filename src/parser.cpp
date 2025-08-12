#include "parser.h"
#include <stdexcept>
#include <sstream>

Parser::Parser(std::vector<Token> tokens) : tokens(std::move(tokens)), current(0) {}

bool Parser::isEnd() const {
    return current >= tokens.size() || tokens[current].type == TokenType::END_OF_FILE;
}

const Token& Parser::peek() const {
    if (current >= tokens.size()) {
        static const Token eofToken(TokenType::END_OF_FILE);  // 缓存静态EOF token
        return eofToken;
    }
    return tokens[current];
}

const Token& Parser::peekNext() const {
    if (current + 1 >= tokens.size()) {
        static const Token eofToken(TokenType::END_OF_FILE);
        return eofToken;
    }
    return tokens[current + 1];
}

const Token& Parser::advance() {
    if (!isEnd()) current++;
    return tokens[current - 1];
}

bool Parser::match(TokenType type) {
    if (check(type)) {
        advance();
        return true;
    }
    return false;
}

bool Parser::check(TokenType type) const {
    if (isEnd()) return false;
    return peek().type == type;
}

const Token& Parser::consume(TokenType type, const std::string& message) {
    if (check(type)) return advance();
    
    std::stringstream ss;
    ss << message << " at line " << peek().line << ", column " << peek().column;
    throw std::runtime_error(ss.str());
}

DataType Parser::parseType() {
    if (match(TokenType::INT)) return DataType::INT;
    if (match(TokenType::VOID)) return DataType::VOID;
    throw std::runtime_error("Expected type specifier");
}

std::unique_ptr<Program> Parser::parseProgram() {
    std::vector<std::unique_ptr<FunctionDeclaration>> functions;
    
    while (!isEnd()) {
        functions.push_back(parseFunctionDeclaration());
    }
    
    if (functions.empty()) {
        throw std::runtime_error("Program must contain at least one function");
    }
    
    return std::make_unique<Program>(std::move(functions));
}

std::unique_ptr<FunctionDeclaration> Parser::parseFunctionDeclaration() {
    DataType returnType = parseType();
    
    const Token& nameToken = consume(TokenType::IDENTIFIER, "Expected function name");
    std::string name = nameToken.value;  // 只在需要时拷贝
    
    consume(TokenType::LEFT_PAREN, "Expected '(' after function name");
    std::vector<Parameter> parameters = parseParameters();
    consume(TokenType::RIGHT_PAREN, "Expected ')' after parameters");
    
    std::unique_ptr<BlockStatement> body = parseBlock();
    
    return std::make_unique<FunctionDeclaration>(name, returnType, std::move(parameters), std::move(body));
}

std::vector<Parameter> Parser::parseParameters() {
    std::vector<Parameter> parameters;
    
    if (!check(TokenType::RIGHT_PAREN)) {
        do {
            DataType type = parseType();
            const Token& nameToken = consume(TokenType::IDENTIFIER, "Expected parameter name");
            parameters.emplace_back(nameToken.value, type);
        } while (match(TokenType::COMMA));
    }
    
    return parameters;
}

std::unique_ptr<BlockStatement> Parser::parseBlock() {
    consume(TokenType::LEFT_BRACE, "Expected '{'");
    
    std::vector<StatementPtr> statements;
    while (!check(TokenType::RIGHT_BRACE) && !isEnd()) {
        statements.push_back(parseStatement());
    }
    
    consume(TokenType::RIGHT_BRACE, "Expected '}'");
    return std::make_unique<BlockStatement>(std::move(statements));
}

StatementPtr Parser::parseStatement() {
    if (check(TokenType::LEFT_BRACE)) {
        return parseBlock();
    }
    
    if (match(TokenType::SEMICOLON)) {
        return nullptr; // Empty statement
    }
    
    if (check(TokenType::IF)) {
        return parseIfStatement();
    }
    
    if (check(TokenType::WHILE)) {
        return parseWhileStatement();
    }
    
    if (check(TokenType::RETURN)) {
        return parseReturnStatement();
    }
    
    if (check(TokenType::BREAK)) {
        return parseBreakStatement();
    }
    
    if (check(TokenType::CONTINUE)) {
        return parseContinueStatement();
    }
    
    // Check for variable declaration or assignment
    if (check(TokenType::INT) || (check(TokenType::IDENTIFIER) && peekNext().type == TokenType::ASSIGN)) {
        return parseAssignOrVarDeclStatement();
    }
    
    return parseExpressionStatement();
}

StatementPtr Parser::parseIfStatement() {
    consume(TokenType::IF, "Expected 'if'");
    consume(TokenType::LEFT_PAREN, "Expected '(' after 'if'");
    ExpressionPtr condition = parseExpression();
    consume(TokenType::RIGHT_PAREN, "Expected ')' after if condition");
    
    StatementPtr thenStmt = parseStatement();
    StatementPtr elseStmt = nullptr;
    
    if (match(TokenType::ELSE)) {
        elseStmt = parseStatement();
    }
    
    return std::make_unique<IfStatement>(std::move(condition), std::move(thenStmt), std::move(elseStmt));
}

StatementPtr Parser::parseWhileStatement() {
    consume(TokenType::WHILE, "Expected 'while'");
    consume(TokenType::LEFT_PAREN, "Expected '(' after 'while'");
    ExpressionPtr condition = parseExpression();
    consume(TokenType::RIGHT_PAREN, "Expected ')' after while condition");
    
    StatementPtr body = parseStatement();
    
    return std::make_unique<WhileStatement>(std::move(condition), std::move(body));
}

StatementPtr Parser::parseReturnStatement() {
    consume(TokenType::RETURN, "Expected 'return'");
    
    ExpressionPtr expr = nullptr;
    if (!check(TokenType::SEMICOLON)) {
        expr = parseExpression();
    }
    
    consume(TokenType::SEMICOLON, "Expected ';' after return statement");
    return std::make_unique<ReturnStatement>(std::move(expr));
}

StatementPtr Parser::parseBreakStatement() {
    consume(TokenType::BREAK, "Expected 'break'");
    consume(TokenType::SEMICOLON, "Expected ';' after 'break'");
    return std::make_unique<BreakStatement>();
}

StatementPtr Parser::parseContinueStatement() {
    consume(TokenType::CONTINUE, "Expected 'continue'");
    consume(TokenType::SEMICOLON, "Expected ';' after 'continue'");
    return std::make_unique<ContinueStatement>();
}

StatementPtr Parser::parseAssignOrVarDeclStatement() {
    if (match(TokenType::INT)) {
        // Variable declaration
        const Token& nameToken = consume(TokenType::IDENTIFIER, "Expected variable name");
        consume(TokenType::ASSIGN, "Expected '=' in variable declaration");
        ExpressionPtr init = parseExpression();
        consume(TokenType::SEMICOLON, "Expected ';' after variable declaration");
        
        return std::make_unique<VarDeclStatement>(nameToken.value, std::move(init));
    } else {
        // Assignment
        const Token& nameToken = consume(TokenType::IDENTIFIER, "Expected variable name");
        consume(TokenType::ASSIGN, "Expected '='");
        ExpressionPtr expr = parseExpression();
        consume(TokenType::SEMICOLON, "Expected ';' after assignment");
        
        return std::make_unique<AssignStatement>(nameToken.value, std::move(expr));
    }
}

StatementPtr Parser::parseExpressionStatement() {
    ExpressionPtr expr = parseExpression();
    consume(TokenType::SEMICOLON, "Expected ';' after expression");
    return std::make_unique<ExpressionStatement>(std::move(expr));
}

ExpressionPtr Parser::parseExpression() {
    return parseLogicalOr();
}

ExpressionPtr Parser::parseLogicalOr() {
    ExpressionPtr expr = parseLogicalAnd();
    
    while (match(TokenType::LOGICAL_OR)) {
        ExpressionPtr right = parseLogicalAnd();
        expr = std::make_unique<BinaryExpression>(BinaryOp::OR, std::move(expr), std::move(right));
    }
    
    return expr;
}

ExpressionPtr Parser::parseLogicalAnd() {
    ExpressionPtr expr = parseRelational();
    
    while (match(TokenType::LOGICAL_AND)) {
        ExpressionPtr right = parseRelational();
        expr = std::make_unique<BinaryExpression>(BinaryOp::AND, std::move(expr), std::move(right));
    }
    
    return expr;
}

ExpressionPtr Parser::parseRelational() {
    ExpressionPtr expr = parseAdditive();
    
    while (true) {
        BinaryOp op;
        if (match(TokenType::LESS)) op = BinaryOp::LT;
        else if (match(TokenType::GREATER)) op = BinaryOp::GT;
        else if (match(TokenType::LESS_EQUAL)) op = BinaryOp::LE;
        else if (match(TokenType::GREATER_EQUAL)) op = BinaryOp::GE;
        else if (match(TokenType::EQUAL)) op = BinaryOp::EQ;
        else if (match(TokenType::NOT_EQUAL)) op = BinaryOp::NE;
        else break;
        
        ExpressionPtr right = parseAdditive();
        expr = std::make_unique<BinaryExpression>(op, std::move(expr), std::move(right));
    }
    
    return expr;
}

ExpressionPtr Parser::parseAdditive() {
    ExpressionPtr expr = parseMultiplicative();
    
    while (true) {
        BinaryOp op;
        if (match(TokenType::PLUS)) op = BinaryOp::ADD;
        else if (match(TokenType::MINUS)) op = BinaryOp::SUB;
        else break;
        
        ExpressionPtr right = parseMultiplicative();
        expr = std::make_unique<BinaryExpression>(op, std::move(expr), std::move(right));
    }
    
    return expr;
}

ExpressionPtr Parser::parseMultiplicative() {
    ExpressionPtr expr = parseUnary();
    
    while (true) {
        BinaryOp op;
        if (match(TokenType::MULTIPLY)) op = BinaryOp::MUL;
        else if (match(TokenType::DIVIDE)) op = BinaryOp::DIV;
        else if (match(TokenType::MODULO)) op = BinaryOp::MOD;
        else break;
        
        ExpressionPtr right = parseUnary();
        expr = std::make_unique<BinaryExpression>(op, std::move(expr), std::move(right));
    }
    
    return expr;
}

ExpressionPtr Parser::parseUnary() {
    if (match(TokenType::PLUS)) {
        ExpressionPtr operand = parseUnary();
        return std::make_unique<UnaryExpression>(UnaryOp::PLUS, std::move(operand));
    }
    
    if (match(TokenType::MINUS)) {
        ExpressionPtr operand = parseUnary();
        return std::make_unique<UnaryExpression>(UnaryOp::MINUS, std::move(operand));
    }
    
    if (match(TokenType::LOGICAL_NOT)) {
        ExpressionPtr operand = parseUnary();
        return std::make_unique<UnaryExpression>(UnaryOp::NOT, std::move(operand));
    }
    
    return parsePrimary();
}

ExpressionPtr Parser::parsePrimary() {
    if (match(TokenType::NUMBER)) {
        Token token = tokens[current - 1];
        int value = std::stoi(token.value);
        return std::make_unique<LiteralExpression>(value);
    }
    
    if (match(TokenType::IDENTIFIER)) {
        Token token = tokens[current - 1];
        ExpressionPtr expr = std::make_unique<VariableExpression>(token.value);
        return parseCall(std::move(expr));
    }
    
    if (match(TokenType::LEFT_PAREN)) {
        ExpressionPtr expr = parseExpression();
        consume(TokenType::RIGHT_PAREN, "Expected ')' after expression");
        return expr;
    }
    
    throw std::runtime_error("Expected expression");
}

ExpressionPtr Parser::parseCall(ExpressionPtr expr) {
    if (auto varExpr = dynamic_cast<VariableExpression*>(expr.get())) {
        if (match(TokenType::LEFT_PAREN)) {
            std::string functionName = varExpr->name;
            std::vector<ExpressionPtr> arguments;
            
            if (!check(TokenType::RIGHT_PAREN)) {
                do {
                    arguments.push_back(parseExpression());
                } while (match(TokenType::COMMA));
            }
            
            consume(TokenType::RIGHT_PAREN, "Expected ')' after arguments");
            expr.release(); // Release the variable expression
            return std::make_unique<CallExpression>(functionName, std::move(arguments));
        }
    }
    
    return expr;
}

std::unique_ptr<Program> Parser::parse() {
    return parseProgram();
}