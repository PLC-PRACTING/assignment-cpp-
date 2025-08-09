#pragma once

#include "ast.h"
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

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

    // 当前函数上下文（用于尾调用优化等）
    std::string currentFunctionName;
    int currentFunctionBodyLabel = -1;
    // 变量作用域栈：记录每个块中新声明变量以及其前一个绑定，用于精确恢复遮蔽的外层变量
    struct ScopedVariableEntry
    {
        std::string name;
        bool hadPrevious;
        int previousOffset;
    };
    std::vector<std::vector<ScopedVariableEntry>> variableScopes;

    // 优化相关
    std::unordered_map<std::string, std::optional<int>> constantValues;
    std::set<std::string> usedVariables;
    bool enableOptimizations = true;

    // 基本块内保守寄存器复用：记录 a0 当前是否保存了某个变量槽位的值
    bool a0HoldsVariable = false;
    int a0HeldVarOffset = 0;

    // 循环不变式提取 + 简易 CSE（基于表达式串的保守复用）
    bool invariantReuseEnabled = false;
    bool invariantComputeBypass = false; // 预计算阶段不从缓存复用
    std::unordered_map<std::string, int> invariantExprToOffset;

    void emit(const std::string &instruction);
    void emitLabel(const std::string &label);
    int nextLabel();
    std::string getLabelName(int labelId);

    void invalidateA0Cache();

    // 分析/序列化工具
    std::string serializeExpr(Expression *expr);
    void collectAssignedVars(Statement *stmt, std::unordered_set<std::string> &out);
    void collectExprs(Statement *stmt, std::vector<Expression *> &out);
    void collectDeps(Expression *expr, std::unordered_set<std::string> &vars, bool &hasCall);

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
    std::optional<int> getPowerOfTwoShift(Expression *expr);

    // 新增优化方法
    bool isDeadCode(Statement *stmt);
    bool canEliminateVariable(const std::string &name);
    void markVariableUsed(const std::string &name);
    void analyzeVariableUsage(BlockStatement *block);
    void optimizeDeadStores(Statement *stmt);

    // 强度削弱优化
    bool shouldUseShiftForMul(Expression *expr);
    bool shouldUseShiftForDiv(Expression *expr);

    int getVariableOffset(const std::string &name);
    int countLocalVariables(BlockStatement *block);

    // 简单表达式直装寄存器优化
    bool tryLoadSimpleExprTo(Expression *expr, const char *regName);
    void emitLoadImmediate(const char *regName, int value);
    bool isITypeImmediate(int value);
    bool isSimpleExpr(Expression *expr);
    bool expressionContainsCall(Expression *expr);

  public:
    CodeGenerator();
    std::string generate(Program *program);
    void setOptimizationEnabled(bool enabled)
    {
        enableOptimizations = enabled;
    }
};