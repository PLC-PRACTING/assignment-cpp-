#pragma once

#include "ast.h"
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <set>

class CodeGenerator
{
  private:
    std::stringstream output;
    std::unordered_map<std::string, int> variables; // variable name -> stack offset
    std::unordered_map<std::string, FunctionDeclaration *> functions;
    int stackOffset;
    int labelCounter;
    int currentStackSize;
    std::vector<int> loopBreakLabels;
    std::vector<int> loopContinueLabels;
    bool isUnreachable = false;
    
    // 优化相关
    std::unordered_map<std::string, std::optional<int>> constantValues;
    std::set<std::string> usedVariables;
    bool enableOptimizations = true;
    
    // 新增优化相关
    std::unordered_map<std::string, std::string> expressionCache; // 表达式缓存用于CSE
    std::unordered_map<std::string, int> registerAllocation; // 简单寄存器分配
    int registerCounter = 0;
    bool inLoop = false;
    std::vector<std::string> loopInvariantCode; // 循环不变代码

    void emit(const std::string &instruction);
    void emitLabel(const std::string &label);
    int nextLabel();
    std::string getLabelName(int labelId);

    void generateFunctionPrologue(const std::string &funcName, int localVarCount);
    void generateFunctionEpilogue();

    void generateProgram(Program *program);
    void generateFunction(FunctionDeclaration *func);
    void generateStatement(Statement *stmt);
    void generateBlockStatement(BlockStatement *stmt);
    void generateIfStatement(IfStatement *stmt);
    void generateWhileStatement(WhileStatement *stmt);
    void generateReturnStatement(ReturnStatement *stmt);
    void generateBreakStatement(BreakStatement *stmt);
    void generateContinueStatement(ContinueStatement *stmt);
    void generateAssignStatement(AssignStatement *stmt);
    void generateVarDeclStatement(VarDeclStatement *stmt);
    void generateExpressionStatement(ExpressionStatement *stmt);

    void generateExpression(Expression *expr);
    void generateBinaryExpression(BinaryExpression *expr);
    void generateUnaryExpression(UnaryExpression *expr);
    void generateLiteralExpression(LiteralExpression *expr);
    void generateVariableExpression(VariableExpression *expr);
    void generateCallExpression(CallExpression *expr);

    void generateShortCircuitAnd(BinaryExpression *expr);
    void generateShortCircuitOr(BinaryExpression *expr);

    std::optional<int> tryConstantFolding(Expression *expr);
    std::optional<int> getPowerOfTwoShift(Expression* expr);
    
    // 新增优化方法
    bool isDeadCode(Statement* stmt);
    bool canEliminateVariable(const std::string& name);
    void markVariableUsed(const std::string& name);
    void analyzeVariableUsage(BlockStatement* block);
    void optimizeDeadStores(Statement* stmt);
    
    // 强度削弱优化
    bool shouldUseShiftForMul(Expression* expr);
    bool shouldUseShiftForDiv(Expression* expr);
    std::optional<int> getMultiplyByConstant(int multiplier);
    void collectVariablesInExpression(Expression* expr);
    void analyzeVariableUsageInStatement(Statement* stmt);
    
    int getVariableOffset(const std::string &name);
    int countLocalVariables(BlockStatement *block);

  public:
    CodeGenerator();
    std::string generate(Program *program);
    void setOptimizationEnabled(bool enabled) { enableOptimizations = enabled; }
};