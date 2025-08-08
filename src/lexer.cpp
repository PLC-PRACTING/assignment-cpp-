#include "lexer.h"
#include <cctype>
#include <stdexcept>

Lexer::Lexer(const std::string& source) 
    : source(source), current(0), line(1), column(1) {}

bool Lexer::isEnd() const {
    return current >= source.length();
}

char Lexer::peek() const {
    if (isEnd()) return '\0';
    return source[current];
}

char Lexer::peekNext() const {
    if (current + 1 >= source.length()) return '\0';
    return source[current + 1];
}

char Lexer::advance() {
    if (isEnd()) return '\0';
    char c = source[current++];
    if (c == '\n') {
        line++;
        column = 1;
    } else {
        column++;
    }
    return c;
}

void Lexer::skipWhitespace() {
    while (!isEnd() && std::isspace(peek())) {
        advance();
    }
}

void Lexer::skipComment() {
    if (peek() == '/' && peekNext() == '/') {
        // Single line comment
        while (!isEnd() && peek() != '\n') {
            advance();
        }
    } else if (peek() == '/' && peekNext() == '*') {
        // Multi-line comment - handle nested /* and */ properly
        advance(); // consume '/'
        advance(); // consume '*'
        int depth = 1;
        while (!isEnd() && depth > 0) {
            if (peek() == '/' && peekNext() == '*') {
                advance(); // consume '/'
                advance(); // consume '*'
                depth++;
            } else if (peek() == '*' && peekNext() == '/') {
                advance(); // consume '*'
                advance(); // consume '/'
                depth--;
            } else {
                advance();
            }
        }
        if (depth > 0) {
            throw std::runtime_error("Unterminated multi-line comment");
        }
    }
}

Token Lexer::makeNumber() {
    size_t start_line = line;
    size_t start_column = column;
    std::string value;
    
    // Handle negative numbers
    if (peek() == '-') {
        value += advance();
    }
    
    // Handle zero
    if (peek() == '0') {
        value += advance();
        if (std::isdigit(peek())) {
            throw std::runtime_error("Invalid number format: leading zeros not allowed");
        }
    } else {
        // Handle non-zero numbers
        while (!isEnd() && std::isdigit(peek())) {
            value += advance();
        }
    }
    
    return Token(TokenType::NUMBER, value, start_line, start_column);
}

Token Lexer::makeIdentifier() {
    size_t start_line = line;
    size_t start_column = column;
    std::string value;
    
    // First character: letter or underscore
    if (std::isalpha(peek()) || peek() == '_') {
        value += advance();
    }
    
    // Subsequent characters: letter, digit, or underscore
    while (!isEnd() && (std::isalnum(peek()) || peek() == '_')) {
        value += advance();
    }
    
    TokenType type = TokenUtils::isKeyword(value) ? 
                     TokenUtils::getKeywordType(value) : 
                     TokenType::IDENTIFIER;
    
    return Token(type, value, start_line, start_column);
}

Token Lexer::makeOperator(char c) {
    size_t start_line = line;
    size_t start_column = column;
    
    switch (c) {
        case '+': advance(); return Token(TokenType::PLUS, "+", start_line, start_column);
        case '-': 
            // Check if it's a negative number
            if (std::isdigit(peekNext())) {
                return makeNumber();
            }
            advance(); 
            return Token(TokenType::MINUS, "-", start_line, start_column);
        case '*': advance(); return Token(TokenType::MULTIPLY, "*", start_line, start_column);
        case '/': advance(); return Token(TokenType::DIVIDE, "/", start_line, start_column);
        case '%': advance(); return Token(TokenType::MODULO, "%", start_line, start_column);
        case '<':
            advance();
            if (peek() == '=') {
                advance();
                return Token(TokenType::LESS_EQUAL, "<=", start_line, start_column);
            }
            return Token(TokenType::LESS, "<", start_line, start_column);
        case '>':
            advance();
            if (peek() == '=') {
                advance();
                return Token(TokenType::GREATER_EQUAL, ">=", start_line, start_column);
            }
            return Token(TokenType::GREATER, ">", start_line, start_column);
        case '=':
            advance();
            if (peek() == '=') {
                advance();
                return Token(TokenType::EQUAL, "==", start_line, start_column);
            }
            return Token(TokenType::ASSIGN, "=", start_line, start_column);
        case '!':
            advance();
            if (peek() == '=') {
                advance();
                return Token(TokenType::NOT_EQUAL, "!=", start_line, start_column);
            }
            return Token(TokenType::LOGICAL_NOT, "!", start_line, start_column);
        case '&':
            advance();
            if (peek() == '&') {
                advance();
                return Token(TokenType::LOGICAL_AND, "&&", start_line, start_column);
            }
            return Token(TokenType::INVALID, "&", start_line, start_column);
        case '|':
            advance();
            if (peek() == '|') {
                advance();
                return Token(TokenType::LOGICAL_OR, "||", start_line, start_column);
            }
            return Token(TokenType::INVALID, "|", start_line, start_column);
        case ';': advance(); return Token(TokenType::SEMICOLON, ";", start_line, start_column);
        case ',': advance(); return Token(TokenType::COMMA, ",", start_line, start_column);
        case '(': advance(); return Token(TokenType::LEFT_PAREN, "(", start_line, start_column);
        case ')': advance(); return Token(TokenType::RIGHT_PAREN, ")", start_line, start_column);
        case '{': advance(); return Token(TokenType::LEFT_BRACE, "{", start_line, start_column);
        case '}': advance(); return Token(TokenType::RIGHT_BRACE, "}", start_line, start_column);
        default:
            advance();
            return Token(TokenType::INVALID, std::string(1, c), start_line, start_column);
    }
}

Token Lexer::nextToken() {
    while (!isEnd()) {
        skipWhitespace();
        if (isEnd()) break;
        
        // Handle comments
        if (peek() == '/' && (peekNext() == '/' || peekNext() == '*')) {
            skipComment();
            continue;
        }
        
        char c = peek();
        
        // Numbers (including negative)
        if (std::isdigit(c) || (c == '-' && std::isdigit(peekNext()))) {
            return makeNumber();
        }
        
        // Identifiers and keywords
        if (std::isalpha(c) || c == '_') {
            return makeIdentifier();
        }
        
        // Operators and punctuation
        return makeOperator(c);
    }
    
    return Token(TokenType::END_OF_FILE, "", line, column);
}

std::vector<Token> Lexer::tokenize() {
    std::vector<Token> tokens;
    Token token;
    
    do {
        token = nextToken();
        tokens.push_back(token);
    } while (token.type != TokenType::END_OF_FILE);
    
    return tokens;
}