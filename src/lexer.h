#pragma once

#include "token.h"
#include <vector>
#include <string>
#include <string_view>

class Lexer {
private:
    std::string_view source;  // 使用string_view避免拷贝
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
    explicit Lexer(std::string_view source);  // 接受string_view
    std::vector<Token> tokenize();
    Token nextToken();
};