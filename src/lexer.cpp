#include "lexer.h"
#include <cctype>
#include <stdexcept>

Lexer::Lexer(std::string_view source) : source(source), current(0), line(1), column(1) {}

bool Lexer::isEnd() const
{
    return current >= source.length();
}

char Lexer::peek() const
{
    if (isEnd())
        return '\0';
    return source[current];
}

char Lexer::peekNext() const
{
    if (current + 1 >= source.length())
        return '\0';
    return source[current + 1];
}

char Lexer::advance()
{
    if (isEnd())
        return '\0';
    char c = source[current++];
    if (c == '\n')
    {
        line++;
        column = 1;
    }
    else
    {
        column++;
    }
    return c;
}

void Lexer::skipWhitespace()
{
    while (!isEnd() && std::isspace(peek()))
    {
        advance();
    }
}

void Lexer::skipComment()
{
    if (peek() == '/' && peekNext() == '/')
    {
        // Single line comment
        while (!isEnd() && peek() != '\n')
        {
            advance();
        }
    }
    else if (peek() == '/' && peekNext() == '*')
    {
        // Multi-line comment - do NOT support nesting: stop at the nearest */
        advance(); // consume '/'
        advance(); // consume '*'
        while (!isEnd())
        {
            if (peek() == '*' && peekNext() == '/')
            {
                advance(); // consume '*'
                advance(); // consume '/'
                return;
            }
            advance();
        }
        throw std::runtime_error("Unterminated multi-line comment");
    }
}

Token Lexer::makeNumber()
{
    size_t start_line = line;
    size_t start_column = column;
    size_t start_pos = current;
    
    // Handle zero
    if (peek() == '0')
    {
        advance();
        if (std::isdigit(peek()))
        {
            throw std::runtime_error("Invalid number format: leading zeros not allowed");
        }
    }
    else
    {
        // Handle non-zero numbers
        while (!isEnd() && std::isdigit(peek()))
        {
            advance();
        }
    }
    
    // 使用substr的string_view版本避免字符拷贝
    std::string value(source.substr(start_pos, current - start_pos));
    return Token(TokenType::NUMBER, std::move(value), start_line, start_column);
}

Token Lexer::makeIdentifier()
{
    size_t start_line = line;
    size_t start_column = column;
    size_t start_pos = current;

    // First character: letter or underscore
    if (std::isalpha(peek()) || peek() == '_')
    {
        advance();
    }

    // Subsequent characters: letter, digit, or underscore
    while (!isEnd() && (std::isalnum(peek()) || peek() == '_'))
    {
        advance();
    }
    
    // 使用substr避免逐个字符拷贝
    std::string value(source.substr(start_pos, current - start_pos));
    TokenType type =
        TokenUtils::isKeyword(value) ? TokenUtils::getKeywordType(value) : TokenType::IDENTIFIER;

    return Token(type, std::move(value), start_line, start_column);
}

Token Lexer::makeOperator(char c)
{
    size_t start_line = line;
    size_t start_column = column;

    switch (c)
    {
    case '+':
        advance();
        return Token(TokenType::PLUS, "+", start_line, start_column);
    case '-':
        advance();
        return Token(TokenType::MINUS, "-", start_line, start_column);
    case '*':
        advance();
        return Token(TokenType::MULTIPLY, "*", start_line, start_column);
    case '/':
        advance();
        return Token(TokenType::DIVIDE, "/", start_line, start_column);
    case '%':
        advance();
        return Token(TokenType::MODULO, "%", start_line, start_column);
    case '<':
        advance();
        if (peek() == '=')
        {
            advance();
            return Token(TokenType::LESS_EQUAL, "<=", start_line, start_column);
        }
        return Token(TokenType::LESS, "<", start_line, start_column);
    case '>':
        advance();
        if (peek() == '=')
        {
            advance();
            return Token(TokenType::GREATER_EQUAL, ">=", start_line, start_column);
        }
        return Token(TokenType::GREATER, ">", start_line, start_column);
    case '=':
        advance();
        if (peek() == '=')
        {
            advance();
            return Token(TokenType::EQUAL, "==", start_line, start_column);
        }
        return Token(TokenType::ASSIGN, "=", start_line, start_column);
    case '!':
        advance();
        if (peek() == '=')
        {
            advance();
            return Token(TokenType::NOT_EQUAL, "!=", start_line, start_column);
        }
        return Token(TokenType::LOGICAL_NOT, "!", start_line, start_column);
    case '&':
        advance();
        if (peek() == '&')
        {
            advance();
            return Token(TokenType::LOGICAL_AND, "&&", start_line, start_column);
        }
        return Token(TokenType::INVALID, "&", start_line, start_column);
    case '|':
        advance();
        if (peek() == '|')
        {
            advance();
            return Token(TokenType::LOGICAL_OR, "||", start_line, start_column);
        }
        return Token(TokenType::INVALID, "|", start_line, start_column);
    case ';':
        advance();
        return Token(TokenType::SEMICOLON, ";", start_line, start_column);
    case ',':
        advance();
        return Token(TokenType::COMMA, ",", start_line, start_column);
    case '(':
        advance();
        return Token(TokenType::LEFT_PAREN, "(", start_line, start_column);
    case ')':
        advance();
        return Token(TokenType::RIGHT_PAREN, ")", start_line, start_column);
    case '{':
        advance();
        return Token(TokenType::LEFT_BRACE, "{", start_line, start_column);
    case '}':
        advance();
        return Token(TokenType::RIGHT_BRACE, "}", start_line, start_column);
    default:
        advance();
        return Token(TokenType::INVALID, std::string(1, c), start_line, start_column);
    }
}

Token Lexer::nextToken()
{
    while (!isEnd())
    {
        skipWhitespace();
        if (isEnd())
            break;

        // Handle comments
        if (peek() == '/' && (peekNext() == '/' || peekNext() == '*'))
        {
            skipComment();
            continue;
        }

        char c = peek();

        // Numbers (only digits start a number; '-' is always a separate token)
        if (std::isdigit(c))
        {
            return makeNumber();
        }

        // Identifiers and keywords
        if (std::isalpha(c) || c == '_')
        {
            return makeIdentifier();
        }

        // Operators and punctuation
        return makeOperator(c);
    }

    return Token(TokenType::END_OF_FILE, "", line, column);
}

std::vector<Token> Lexer::tokenize()
{
    std::vector<Token> tokens;
    // 预留空间减少内存分配次数
    tokens.reserve(source.size() / 4); // 估计token数量
    Token token;

    do
    {
        token = nextToken();
        tokens.emplace_back(std::move(token));  // 使用move语义
    } while (token.type != TokenType::END_OF_FILE);

    return tokens;
}