#pragma once

#include "ast.h"
#include <unordered_map>
#include <vector>
#include <string>

struct VariableInfo {
    DataType type;
    bool initialized;
    size_t scopeLevel;
    
    VariableInfo() : type(DataType::VOID), initialized(false), scopeLevel(0) {}
    VariableInfo(DataType t, bool init, size_t level) 
        : type(t), initialized(init), scopeLevel(level) {}
};

struct FunctionInfo {
    DataType returnType;
    std::vector<DataType> paramTypes;
    bool defined;
    
    FunctionInfo() : returnType(DataType::VOID), paramTypes(), defined(false) {}
    FunctionInfo(DataType ret, std::vector<DataType> params, bool def)
        : returnType(ret), paramTypes(std::move(params)), defined(def) {}
};

class SemanticAnalyzer {
private:
    std::vector<std::unordered_map<std::string, VariableInfo>> scopes;
    std::unordered_map<std::string, FunctionInfo> functions;
    size_t currentScopeLevel;
    size_t loopDepth;
    DataType currentFunctionReturnType;
    std::string currentFunctionName;
    
    void enterScope();
    void exitScope();
    void declareVariable(const std::string& name, DataType type);
    void checkVariableExists(const std::string& name);
    void checkFunctionExists(const std::string& name);
    void checkTypeCompatibility(DataType expected, DataType actual, const std::string& context);
    
    void analyzeProgram(Program* program);
    void analyzeFunctionDeclaration(FunctionDeclaration* func);
    void analyzeStatement(Statement* stmt);
    void analyzeBlockStatement(BlockStatement* stmt);
    void analyzeIfStatement(IfStatement* stmt);
    void analyzeWhileStatement(WhileStatement* stmt);
    void analyzeReturnStatement(ReturnStatement* stmt);
    void analyzeBreakStatement(BreakStatement* stmt);
    void analyzeContinueStatement(ContinueStatement* stmt);
    void analyzeAssignStatement(AssignStatement* stmt);
    void analyzeVarDeclStatement(VarDeclStatement* stmt);
    void analyzeExpressionStatement(ExpressionStatement* stmt);
    
    DataType analyzeExpression(Expression* expr);
    DataType analyzeBinaryExpression(BinaryExpression* expr);
    DataType analyzeUnaryExpression(UnaryExpression* expr);
    DataType analyzeLiteralExpression(LiteralExpression* expr);
    DataType analyzeVariableExpression(VariableExpression* expr);
    DataType analyzeCallExpression(CallExpression* expr);
    
    void checkReturnPaths(FunctionDeclaration* func);
    bool hasReturnInAllPaths(Statement* stmt);
    
public:
    SemanticAnalyzer();
    void analyze(Program* program);
};