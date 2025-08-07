#pragma once

#include <string>
#include <unordered_map>

enum class TokenType {
    // Literals
    IDENTIFIER,
    NUMBER,
    
    // Keywords
    INT,
    VOID,
    IF,
    ELSE,
    WHILE,
    BREAK,
    CONTINUE,
    RETURN,
    
    // Operators
    PLUS,           // +
    MINUS,          // -
    MULTIPLY,       // *
    DIVIDE,         // /
    MODULO,         // %
    
    // Comparison
    LESS,           // <
    GREATER,        // >
    LESS_EQUAL,     // <=
    GREATER_EQUAL,  // >=
    EQUAL,          // ==
    NOT_EQUAL,      // !=
    
    // Logical
    LOGICAL_AND,    // &&
    LOGICAL_OR,     // ||
    LOGICAL_NOT,    // !
    
    // Assignment
    ASSIGN,         // =
    
    // Punctuation
    SEMICOLON,      // ;
    COMMA,          // ,
    LEFT_PAREN,     // (
    RIGHT_PAREN,    // )
    LEFT_BRACE,     // {
    RIGHT_BRACE,    // }
    
    // Special
    END_OF_FILE,
    INVALID
};

struct Token {
    TokenType type;
    std::string value;
    size_t line;
    size_t column;
    
    Token(TokenType t = TokenType::INVALID, const std::string& v = "", 
          size_t l = 0, size_t c = 0) 
        : type(t), value(v), line(l), column(c) {}
};

class TokenUtils {
public:
    static const std::unordered_map<std::string, TokenType> keywords;
    static std::string tokenTypeToString(TokenType type);
    static bool isKeyword(const std::string& str);
    static TokenType getKeywordType(const std::string& str);
};