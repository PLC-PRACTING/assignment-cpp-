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
    
    // 优化字符串操作的缓存区
    std::string instructionBuffer;
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

    // 基本块内保守寄存器复用：记录 a0/a1 当前是否保存了某个变量槽位的值
    bool a0HoldsVariable = false;
    int a0HeldVarOffset = 0;
    bool a1HoldsVariable = false;
    int a1HeldVarOffset = 0;
    
    // 循环变量寄存器分配：t寄存器用于存储频繁访问的局部变量
    std::unordered_map<std::string, std::string> loopVarRegMap; // 变量名 -> 寄存器名
    bool inLoopContext = false;

    // 循环不变式提取 + 简易 CSE（基于表达式串的保守复用）
    bool invariantReuseEnabled = false;
    bool invariantComputeBypass = false; // 预计算阶段不从缓存复用
    std::unordered_map<std::string, int> invariantExprToOffset;

    void emit(const std::string &instruction);
    void emitFast(const char* instruction);  // 优化版本，避免string创建
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

    // 函数内联优化
    bool shouldInlineFunction(const std::string &functionName);
    bool canInlineFunction(FunctionDeclaration *func);
    void generateInlinedCall(CallExpression *expr, FunctionDeclaration *func);

    // 循环寄存器优化
    void analyzeAndAllocateLoopRegisters(WhileStatement *stmt);
    void collectLoopVariables(Statement *stmt, std::unordered_set<std::string> &vars);
    bool isLoopInvariant(Expression *expr, const std::unordered_set<std::string> &loopVars);
    
    // 循环不变量外提优化
    void hoistLoopInvariants(WhileStatement *stmt);
    void findInvariantExpressions(Statement *stmt, const std::unordered_set<std::string> &loopVars, 
                                  std::vector<Expression*> &invariants);
    void generateHoistedInvariants(const std::vector<Expression*> &invariants);
    
    // 数组索引计算优化
    bool isArrayIndexPattern(BinaryExpression *expr);
    void optimizeArrayIndexComputation(BinaryExpression *expr);

  public:
    CodeGenerator();
    std::string generate(Program *program);
    void setOptimizationEnabled(bool enabled)
    {
        enableOptimizations = enabled;
    }
};