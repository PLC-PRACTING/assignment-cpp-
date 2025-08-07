#pragma once

#include "token.h"
#include <vector>
#include <string>

class Lexer {
private:
    std::string source;
    size_t current;
    size_t line;
    size_t column;
    
    bool isEnd() const;
    char peek() const;
    char peekNext() const;
    char advance();
    void skipWhitespace();
    void skipComment();
    Token makeNumber();
    Token makeIdentifier();
    Token makeOperator(char c);
    
public:
    explicit Lexer(const std::string& source);
    std::vector<Token> tokenize();
    Token nextToken();
};