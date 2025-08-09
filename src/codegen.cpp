#include "codegen.h"
#include <algorithm>
#include <cmath> // For log2
#include <stdexcept>

CodeGenerator::CodeGenerator()
    : stackOffset(0), labelCounter(0), currentStackSize(0), isUnreachable(false)
{
}

void CodeGenerator::emit(const std::string &instruction)
{
    output << "    " << instruction << std::endl;
}

void CodeGenerator::emitLabel(const std::string &label)
{
    output << label << ":" << std::endl;
}

int CodeGenerator::nextLabel()
{
    return ++labelCounter;
}

std::string CodeGenerator::getLabelName(int labelId)
{
    return ".L" + std::to_string(labelId);
}

void CodeGenerator::generateFunctionPrologue(const std::string &funcName, int localVarCount)
{
    emitLabel(funcName);

    // Calculate stack space needed with larger buffer for complex cases
    // Local variables + saved registers + parameter space + safety margin
    int frameSize = (localVarCount + 2) * 4;         // ra, fp, and local variables
    int maxStackSize = std::max(frameSize + 32, 64); // Ensure minimum 64 bytes
    maxStackSize = (maxStackSize + 15) & ~15;        // Align to 16 bytes
    currentStackSize = maxStackSize;

    if (maxStackSize > 0)
    {
        emit("addi sp, sp, -" + std::to_string(maxStackSize));
        emit("sw ra, " + std::to_string(maxStackSize - 4) + "(sp)");
        emit("sw fp, " + std::to_string(maxStackSize - 8) + "(sp)");
        emit("addi fp, sp, " + std::to_string(maxStackSize));
    }
}

void CodeGenerator::generateFunctionEpilogue()
{
    if (currentStackSize > 0)
    {
        emit("lw ra, " + std::to_string(currentStackSize - 4) + "(sp)");
        emit("lw fp, " + std::to_string(currentStackSize - 8) + "(sp)");
        emit("addi sp, sp, " + std::to_string(currentStackSize));
    }
    emit("ret");
}

int CodeGenerator::getVariableOffset(const std::string &name)
{
    auto it = variables.find(name);
    if (it == variables.end())
    {
        throw std::runtime_error("Variable not found: " + name);
    }
    return it->second;
}

int CodeGenerator::countLocalVariables(BlockStatement *block)
{
    int count = 0;
    for (auto &stmt : block->statements)
    {
        if (stmt && stmt->type == NodeType::VAR_DECL_STMT)
        {
            count++;
        }
        else if (stmt && stmt->type == NodeType::BLOCK_STMT)
        {
            count += countLocalVariables(static_cast<BlockStatement *>(stmt.get()));
        }
    }
    return count;
}

std::string CodeGenerator::generate(Program *program)
{
    output.str(""); // Clear output
    output.clear();

    emit(".text");
    emit(".globl main");

    generateProgram(program);

    return output.str();
}

void CodeGenerator::generateProgram(Program *program)
{
    // Store function references
    for (auto &func : program->functions)
    {
        functions[func->name] = func.get();
    }

    // Generate all functions
    for (auto &func : program->functions)
    {
        generateFunction(func.get());
    }
}

void CodeGenerator::generateFunction(FunctionDeclaration *func)
{
    variables.clear();
    constantValues.clear();
    usedVariables.clear();
    stackOffset = 0;
    isUnreachable = false;

    if (enableOptimizations)
    {
        analyzeVariableUsage(func->body.get());
    }

    // Count local variables for stack allocation (including nested blocks)
    int localVarCount = countLocalVariables(func->body.get());

    // Calculate proper stack layout
    int paramCount = static_cast<int>(func->parameters.size());
    int totalLocals = localVarCount + paramCount + 2; // +2 for ra and fp

    // Add parameters to variable map (negative offsets from fp)
    // Prologue saves ra at -4(fp) and fp at -8(fp), so first free slot is -12(fp)
    int paramOffset = -12;
    for (size_t i = 0; i < func->parameters.size(); i++)
    {
        variables[func->parameters[i].name] = paramOffset - static_cast<int>(i) * 4;
    }

    // Reserve space for local variables (negative offsets from fp) after parameters
    int localOffset = -12 - (paramCount * 4);

    // Initialize stack offset for local variables
    stackOffset = localOffset;

    generateFunctionPrologue(func->name, totalLocals);

    // Store parameters from registers to stack
    for (size_t i = 0; i < func->parameters.size() && i < 8; i++)
    {
        int offset = getVariableOffset(func->parameters[i].name);
        emit("sw a" + std::to_string(i) + ", " + std::to_string(offset) + "(fp)");
    }

    // Load stack-passed parameters (beyond a0-a7) from caller's stack into our frame
    if (func->parameters.size() > 8)
    {
        for (size_t i = 8; i < func->parameters.size(); i++)
        {
            int destOffset = getVariableOffset(func->parameters[i].name); // negative in our frame
            int srcOffset = static_cast<int>((i - 8) * 4); // positive from fp (caller frame)
            emit("lw a0, " + std::to_string(srcOffset) + "(fp)");
            emit("sw a0, " + std::to_string(destOffset) + "(fp)");
        }
    }

    generateStatement(func->body.get());

    // Add implicit return for void functions
    if (func->returnType == DataType::VOID)
    {
        generateFunctionEpilogue();
    }
}

void CodeGenerator::generateStatement(Statement *stmt)
{
    if (!stmt || isUnreachable)
        return;

    switch (stmt->type)
    {
    case NodeType::BLOCK_STMT:
        generateBlockStatement(static_cast<BlockStatement *>(stmt));
        break;
    case NodeType::IF_STMT:
        generateIfStatement(static_cast<IfStatement *>(stmt));
        break;
    case NodeType::WHILE_STMT:
        generateWhileStatement(static_cast<WhileStatement *>(stmt));
        break;
    case NodeType::RETURN_STMT:
        generateReturnStatement(static_cast<ReturnStatement *>(stmt));
        break;
    case NodeType::BREAK_STMT:
        generateBreakStatement(static_cast<BreakStatement *>(stmt));
        break;
    case NodeType::CONTINUE_STMT:
        generateContinueStatement(static_cast<ContinueStatement *>(stmt));
        break;
    case NodeType::ASSIGN_STMT:
        generateAssignStatement(static_cast<AssignStatement *>(stmt));
        break;
    case NodeType::VAR_DECL_STMT:
        generateVarDeclStatement(static_cast<VarDeclStatement *>(stmt));
        break;
    case NodeType::EXPR_STMT:
        generateExpressionStatement(static_cast<ExpressionStatement *>(stmt));
        break;
    }
}

void CodeGenerator::generateBlockStatement(BlockStatement *stmt)
{
    // Create new scope for variables
    auto oldVariables = variables;
    int oldStackOffset = stackOffset;

    // Process statements in this scope
    for (auto &s : stmt->statements)
    {
        generateStatement(s.get());
    }

    // Restore previous scope
    variables = oldVariables;
    stackOffset = oldStackOffset;
}

void CodeGenerator::generateIfStatement(IfStatement *stmt)
{
    int elseLabel = nextLabel();
    int endLabel = nextLabel();

    // Generate condition
    generateExpression(stmt->condition.get());

    // Branch if false
    emit("beqz a0, " + getLabelName(elseLabel));

    // Generate then statement
    generateStatement(stmt->thenStmt.get());
    bool thenIsUnreachable = isUnreachable;

    if (stmt->elseStmt)
    {
        emit("j " + getLabelName(endLabel));
        emitLabel(getLabelName(elseLabel));

        isUnreachable = false; // Reset for else branch
        generateStatement(stmt->elseStmt.get());
        bool elseIsUnreachable = isUnreachable;

        isUnreachable = thenIsUnreachable && elseIsUnreachable;

        emitLabel(getLabelName(endLabel));
    }
    else
    {
        emitLabel(getLabelName(elseLabel));
        isUnreachable = false; // Code after if is reachable if there's no else
    }
}

void CodeGenerator::generateWhileStatement(WhileStatement *stmt)
{
    int startLabel = nextLabel();
    int endLabel = nextLabel();

    loopBreakLabels.push_back(endLabel);
    loopContinueLabels.push_back(startLabel);

    emitLabel(getLabelName(startLabel));

    // Generate condition
    generateExpression(stmt->condition.get());

    // Branch if false
    emit("beqz a0, " + getLabelName(endLabel));

    // Generate body
    isUnreachable = false; // Body is reachable from the condition
    generateStatement(stmt->body.get());

    emit("j " + getLabelName(startLabel));

    emitLabel(getLabelName(endLabel));

    loopBreakLabels.pop_back();
    loopContinueLabels.pop_back();
    isUnreachable = false; // Code after loop is always considered reachable
}

void CodeGenerator::generateReturnStatement(ReturnStatement *stmt)
{
    if (stmt->expression)
    {
        generateExpression(stmt->expression.get());
    }
    generateFunctionEpilogue();
    isUnreachable = true;
}

void CodeGenerator::generateBreakStatement(BreakStatement *stmt)
{
    if (loopBreakLabels.empty())
    {
        throw std::runtime_error("Break statement outside of loop");
    }
    emit("j " + getLabelName(loopBreakLabels.back()));
    isUnreachable = true;
}

void CodeGenerator::generateContinueStatement(ContinueStatement *stmt)
{
    if (loopContinueLabels.empty())
    {
        throw std::runtime_error("Continue statement outside of loop");
    }
    emit("j " + getLabelName(loopContinueLabels.back()));
    isUnreachable = true;
}

void CodeGenerator::generateAssignStatement(AssignStatement *stmt)
{
    generateExpression(stmt->expression.get());
    int offset = getVariableOffset(stmt->variable);
    emit("sw a0, " + std::to_string(offset) + "(fp)");
}

void CodeGenerator::generateVarDeclStatement(VarDeclStatement *stmt)
{
    // Variable already allocated in function prologue
    generateExpression(stmt->initializer.get());

    // Allocate new variable
    variables[stmt->name] = stackOffset;
    int offset = stackOffset;
    stackOffset -= 4;

    emit("sw a0, " + std::to_string(offset) + "(fp)");
}

void CodeGenerator::generateExpressionStatement(ExpressionStatement *stmt)
{
    generateExpression(stmt->expression.get());
}

void CodeGenerator::generateExpression(Expression *expr)
{
    if (!expr)
        return;

    if (auto constValue = tryConstantFolding(expr))
    {
        emit("li a0, " + std::to_string(*constValue));
        return;
    }

    switch (expr->type)
    {
    case NodeType::BINARY_EXPR:
        generateBinaryExpression(static_cast<BinaryExpression *>(expr));
        break;
    case NodeType::UNARY_EXPR:
        generateUnaryExpression(static_cast<UnaryExpression *>(expr));
        break;
    case NodeType::LITERAL_EXPR:
        generateLiteralExpression(static_cast<LiteralExpression *>(expr));
        break;
    case NodeType::VARIABLE_EXPR:
        generateVariableExpression(static_cast<VariableExpression *>(expr));
        break;
    case NodeType::CALL_EXPR:
        generateCallExpression(static_cast<CallExpression *>(expr));
        break;
    }
}

std::optional<int> CodeGenerator::tryConstantFolding(Expression *expr)
{
    if (!expr)
        return std::nullopt;

    switch (expr->type)
    {
    case NodeType::LITERAL_EXPR:
        return static_cast<LiteralExpression *>(expr)->value;
    case NodeType::BINARY_EXPR: {
        auto binExpr = static_cast<BinaryExpression *>(expr);
        auto leftVal = tryConstantFolding(binExpr->left.get());
        auto rightVal = tryConstantFolding(binExpr->right.get());

        if (leftVal && rightVal)
        {
            switch (binExpr->op)
            {
            case BinaryOp::ADD:
                return *leftVal + *rightVal;
            case BinaryOp::SUB:
                return *leftVal - *rightVal;
            case BinaryOp::MUL:
                return *leftVal * *rightVal;
            case BinaryOp::DIV:
                if (*rightVal == 0)
                    throw std::runtime_error("Division by zero");
                return *leftVal / *rightVal;
            case BinaryOp::MOD:
                if (*rightVal == 0)
                    throw std::runtime_error("Modulo by zero");
                return *leftVal % *rightVal;
            case BinaryOp::LT:
                return *leftVal < *rightVal;
            case BinaryOp::LE:
                return *leftVal <= *rightVal;
            case BinaryOp::GT:
                return *leftVal > *rightVal;
            case BinaryOp::GE:
                return *leftVal >= *rightVal;
            case BinaryOp::EQ:
                return *leftVal == *rightVal;
            case BinaryOp::NE:
                return *leftVal != *rightVal;
            case BinaryOp::AND:
                return *leftVal && *rightVal;
            case BinaryOp::OR:
                return *leftVal || *rightVal;
            }
        }
        break;
    }
    case NodeType::UNARY_EXPR: {
        auto unaryExpr = static_cast<UnaryExpression *>(expr);
        auto operandVal = tryConstantFolding(unaryExpr->operand.get());
        if (operandVal)
        {
            switch (unaryExpr->op)
            {
            case UnaryOp::MINUS:
                return -*operandVal;
            case UnaryOp::NOT:
                return !*operandVal;
            case UnaryOp::PLUS:
                return *operandVal;
            }
        }
        break;
    }
    default:
        return std::nullopt;
    }
    return std::nullopt;
}

std::optional<int> CodeGenerator::getPowerOfTwoShift(Expression *expr)
{
    if (expr->type == NodeType::LITERAL_EXPR)
    {
        int value = static_cast<LiteralExpression *>(expr)->value;
        if (value > 0 && (value & (value - 1)) == 0)
        { // Check if power of two
            return static_cast<int>(log2(value));
        }
    }
    return std::nullopt;
}

// 新增：获取乘法逆元优化
std::optional<int> CodeGenerator::getMultiplyByConstant(int multiplier)
{
    // 对于乘以常数，使用移位和加法组合
    if (multiplier == 0) return 0;
    if (multiplier == 1) return 1;
    if (multiplier == 2) return 2;  // slli 1
    if (multiplier == 3) return 3;  // slli 1 + add
    if (multiplier == 4) return 4;  // slli 2
    if (multiplier == 5) return 5;  // slli 2 + add
    if (multiplier == 6) return 6;  // slli 2 + slli 1 + add
    if (multiplier == 8) return 8;  // slli 3
    if (multiplier == 9) return 9;  // slli 3 + add
    if (multiplier == 10) return 10; // slli 3 + slli 1 + add
    return std::nullopt;
}

// 死代码检测
bool CodeGenerator::isDeadCode(Statement *stmt)
{
    if (!stmt || !enableOptimizations)
        return false;

    switch (stmt->type)
    {
    case NodeType::VAR_DECL_STMT: {
        auto *varStmt = static_cast<VarDeclStatement *>(stmt);
        return !usedVariables.count(varStmt->name);
    }
    case NodeType::ASSIGN_STMT: {
        auto *assignStmt = static_cast<AssignStatement *>(stmt);
        return !usedVariables.count(assignStmt->variable);
    }
    default:
        return false;
    }
}

// 增强的变量使用分析 - 实际分析表达式中的变量使用
void CodeGenerator::analyzeVariableUsage(BlockStatement *block)
{
    if (!block || !enableOptimizations)
        return;

    // 收集所有变量声明
    std::set<std::string> declaredVars;
    for (auto &stmt : block->statements)
    {
        if (stmt && stmt->type == NodeType::VAR_DECL_STMT)
        {
            auto *varStmt = static_cast<VarDeclStatement *>(stmt.get());
            declaredVars.insert(varStmt->name);
        }
    }

    // 分析所有表达式中的变量使用
    for (auto &stmt : block->statements)
    {
        if (!stmt) continue;
        
        switch (stmt->type)
        {
        case NodeType::RETURN_STMT: {
            auto *retStmt = static_cast<ReturnStatement *>(stmt.get());
            if (retStmt->expression)
                collectVariablesInExpression(retStmt->expression.get());
            break;
        }
        case NodeType::ASSIGN_STMT: {
            auto *assignStmt = static_cast<AssignStatement *>(stmt.get());
            collectVariablesInExpression(assignStmt->expression.get());
            markVariableUsed(assignStmt->variable); // 赋值目标变量总是使用
            break;
        }
        case NodeType::VAR_DECL_STMT: {
            auto *varStmt = static_cast<VarDeclStatement *>(stmt.get());
            if (varStmt->initializer)
                collectVariablesInExpression(varStmt->initializer.get());
            break;
        }
        case NodeType::EXPR_STMT: {
            auto *exprStmt = static_cast<ExpressionStatement *>(stmt.get());
            collectVariablesInExpression(exprStmt->expression.get());
            break;
        }
        case NodeType::IF_STMT: {
            auto *ifStmt = static_cast<IfStatement *>(stmt.get());
            collectVariablesInExpression(ifStmt->condition.get());
            analyzeVariableUsageInStatement(ifStmt->thenStmt.get());
            if (ifStmt->elseStmt)
                analyzeVariableUsageInStatement(ifStmt->elseStmt.get());
            break;
        }
        case NodeType::WHILE_STMT: {
            auto *whileStmt = static_cast<WhileStatement *>(stmt.get());
            collectVariablesInExpression(whileStmt->condition.get());
            analyzeVariableUsageInStatement(whileStmt->body.get());
            break;
        }
        case NodeType::BLOCK_STMT: {
            analyzeVariableUsage(static_cast<BlockStatement *>(stmt.get()));
            break;
        }
        default:
            break;
        }
    }
}

// 收集表达式中的变量
void CodeGenerator::collectVariablesInExpression(Expression *expr)
{
    if (!expr) return;
    
    switch (expr->type)
    {
    case NodeType::VARIABLE_EXPR: {
        auto *varExpr = static_cast<VariableExpression *>(expr);
        markVariableUsed(varExpr->name);
        break;
    }
    case NodeType::BINARY_EXPR: {
        auto *binExpr = static_cast<BinaryExpression *>(expr);
        collectVariablesInExpression(binExpr->left.get());
        collectVariablesInExpression(binExpr->right.get());
        break;
    }
    case NodeType::UNARY_EXPR: {
        auto *unaryExpr = static_cast<UnaryExpression *>(expr);
        collectVariablesInExpression(unaryExpr->operand.get());
        break;
    }
    case NodeType::CALL_EXPR: {
        auto *callExpr = static_cast<CallExpression *>(expr);
        for (auto &arg : callExpr->arguments)
            collectVariablesInExpression(arg.get());
        break;
    }
    default:
        break;
    }
}

// 递归分析语句中的变量使用
void CodeGenerator::analyzeVariableUsageInStatement(Statement *stmt)
{
    if (!stmt) return;
    
    switch (stmt->type)
    {
    case NodeType::BLOCK_STMT:
        analyzeVariableUsage(static_cast<BlockStatement *>(stmt));
        break;
    case NodeType::IF_STMT: {
        auto *ifStmt = static_cast<IfStatement *>(stmt);
        analyzeVariableUsageInStatement(ifStmt->thenStmt.get());
        if (ifStmt->elseStmt)
            analyzeVariableUsageInStatement(ifStmt->elseStmt.get());
        break;
    }
    case NodeType::WHILE_STMT: {
        auto *whileStmt = static_cast<WhileStatement *>(stmt);
        analyzeVariableUsageInStatement(whileStmt->body.get());
        break;
    }
    default:
        break;
    }
}

void CodeGenerator::markVariableUsed(const std::string &name)
{
    usedVariables.insert(name);
}

// 强度削弱优化
bool CodeGenerator::shouldUseShiftForMul(Expression *expr)
{
    if (!enableOptimizations || !expr || expr->type != NodeType::BINARY_EXPR)
        return false;

    auto *binExpr = static_cast<BinaryExpression *>(expr);
    return binExpr->op == BinaryOp::MUL && (getPowerOfTwoShift(binExpr->left.get()).has_value() ||
                                            getPowerOfTwoShift(binExpr->right.get()).has_value());
}

bool CodeGenerator::shouldUseShiftForDiv(Expression *expr)
{
    if (!enableOptimizations || !expr || expr->type != NodeType::BINARY_EXPR)
        return false;

    auto *binExpr = static_cast<BinaryExpression *>(expr);
    if (binExpr->op == BinaryOp::DIV)
    {
        if (auto shift = getPowerOfTwoShift(binExpr->right.get()))
        {
            return *shift >= 0; // 除法也可以优化为右移
        }
    }
    return false;
}

void CodeGenerator::generateBinaryExpression(BinaryExpression *expr)
{
    if (expr->op == BinaryOp::AND)
    {
        generateShortCircuitAnd(expr);
    }
    else if (expr->op == BinaryOp::OR)
    {
        generateShortCircuitOr(expr);
    }
    else
    {
        // 强度削弱优化：检查是否为常数运算
        auto leftConst = tryConstantFolding(expr->left.get());
        auto rightConst = tryConstantFolding(expr->right.get());
        
        // 如果是常数运算，直接计算结果
        if (leftConst && rightConst)
        {
            int result = 0;
            switch (expr->op)
            {
                case BinaryOp::ADD: result = *leftConst + *rightConst; break;
                case BinaryOp::SUB: result = *leftConst - *rightConst; break;
                case BinaryOp::MUL: result = *leftConst * *rightConst; break;
                case BinaryOp::DIV: result = *rightConst != 0 ? *leftConst / *rightConst : 0; break;
                case BinaryOp::MOD: result = *rightConst != 0 ? *leftConst % *rightConst : 0; break;
                case BinaryOp::LT: result = *leftConst < *rightConst ? 1 : 0; break;
                case BinaryOp::GT: result = *leftConst > *rightConst ? 1 : 0; break;
                case BinaryOp::LE: result = *leftConst <= *rightConst ? 1 : 0; break;
                case BinaryOp::GE: result = *leftConst >= *rightConst ? 1 : 0; break;
                case BinaryOp::EQ: result = *leftConst == *rightConst ? 1 : 0; break;
                case BinaryOp::NE: result = *leftConst != *rightConst ? 1 : 0; break;
                default: break;
            }
            emit("li a0, " + std::to_string(result));
            return;
        }

        // 强度削弱优化：乘法优化
        if (expr->op == BinaryOp::MUL)
        {
            // 右侧是常数的情况
            if (auto rightVal = tryConstantFolding(expr->right.get()))
            {
                generateExpression(expr->left.get());
                
                // 2的幂次用移位
                if (auto shift = getPowerOfTwoShift(expr->right.get()))
                {
                    if (*shift > 0)
                        emit("slli a0, a0, " + std::to_string(*shift));
                    return;
                }
                
                // 特定常数优化
                if (*rightVal == 0)
                {
                    emit("li a0, 0");
                    return;
                }
                if (*rightVal == 1)
                {
                    return; // 乘以1不变
                }
                if (*rightVal == -1)
                {
                    emit("neg a0, a0");
                    return;
                }
                if (*rightVal == 3)
                {
                    emit("slli t0, a0, 1");
                    emit("add a0, a0, t0");
                    return;
                }
                if (*rightVal == 5)
                {
                    emit("slli t0, a0, 2");
                    emit("add a0, a0, t0");
                    return;
                }
                if (*rightVal == 7)
                {
                    emit("slli t0, a0, 3");
                    emit("sub a0, t0, a0");
                    return;
                }
                if (*rightVal == 9)
                {
                    emit("slli t0, a0, 3");
                    emit("add a0, a0, t0");
                    return;
                }
                if (*rightVal == 10)
                {
                    emit("slli t0, a0, 3");
                    emit("slli a0, a0, 1");
                    emit("add a0, a0, t0");
                    return;
                }
            }
            
            // 左侧是常数的情况
            if (auto leftVal = tryConstantFolding(expr->left.get()))
            {
                generateExpression(expr->right.get());
                
                if (auto shift = getPowerOfTwoShift(expr->left.get()))
                {
                    if (*shift > 0)
                        emit("slli a0, a0, " + std::to_string(*shift));
                    return;
                }
                
                if (*leftVal == 0)
                {
                    emit("li a0, 0");
                    return;
                }
                if (*leftVal == 1)
                {
                    return;
                }
                if (*leftVal == -1)
                {
                    emit("neg a0, a0");
                    return;
                }
                // 其他常数处理同上
            }
        }

        // 强度削弱优化：除法优化
        if (expr->op == BinaryOp::DIV)
        {
            if (auto rightVal = tryConstantFolding(expr->right.get()))
            {
                generateExpression(expr->left.get());
                
                if (*rightVal == 1)
                {
                    return; // 除以1不变
                }
                if (*rightVal == -1)
                {
                    emit("neg a0, a0");
                    return;
                }
                
                // 2的幂次用移位
                if (auto shift = getPowerOfTwoShift(expr->right.get()))
                {
                    emit("srai a0, a0, " + std::to_string(*shift));
                    return;
                }
            }
        }

        // 强度削弱优化：模运算优化
        if (expr->op == BinaryOp::MOD)
        {
            if (auto rightVal = tryConstantFolding(expr->right.get()))
            {
                generateExpression(expr->left.get());
                
                // 2的幂次用位运算
                if (auto shift = getPowerOfTwoShift(expr->right.get()))
                {
                    int mask = (1 << *shift) - 1;
                    emit("andi a0, a0, " + std::to_string(mask));
                    return;
                }
            }
        }

        // 强度削弱优化：加法优化
        if (expr->op == BinaryOp::ADD)
        {
            if (auto rightVal = tryConstantFolding(expr->right.get()))
            {
                generateExpression(expr->left.get());
                if (*rightVal == 0)
                {
                    return; // 加0不变
                }
                if (*rightVal == 1)
                {
                    emit("addi a0, a0, 1");
                    return;
                }
                if (*rightVal == -1)
                {
                    emit("addi a0, a0, -1");
                    return;
                }
                if (*rightVal > 0 && *rightVal <= 2047) // 12位立即数
                {
                    emit("addi a0, a0, " + std::to_string(*rightVal));
                    return;
                }
            }
            
            if (auto leftVal = tryConstantFolding(expr->left.get()))
            {
                generateExpression(expr->right.get());
                if (*leftVal == 0)
                {
                    return; // 加0不变
                }
                if (*leftVal == 1)
                {
                    emit("addi a0, a0, 1");
                    return;
                }
                if (*leftVal == -1)
                {
                    emit("addi a0, a0, -1");
                    return;
                }
                if (*leftVal > 0 && *leftVal <= 2047)
                {
                    emit("addi a0, a0, " + std::to_string(*leftVal));
                    return;
                }
            }
        }

        // 强度削弱优化：减法优化
        if (expr->op == BinaryOp::SUB)
        {
            if (auto rightVal = tryConstantFolding(expr->right.get()))
            {
                generateExpression(expr->left.get());
                if (*rightVal == 0)
                {
                    return; // 减0不变
                }
                if (*rightVal == 1)
                {
                    emit("addi a0, a0, -1");
                    return;
                }
                if (*rightVal > 0 && *rightVal <= 2047)
                {
                    emit("addi a0, a0, -" + std::to_string(*rightVal));
                    return;
                }
            }
        }

        // 普通情况：使用通用算法
        generateExpression(expr->right.get());
        
        // 如果右侧是常数0，可以优化
        if (auto rightVal = tryConstantFolding(expr->right.get()))
        {
            if (*rightVal == 0)
            {
                generateExpression(expr->left.get());
                if (expr->op == BinaryOp::ADD || expr->op == BinaryOp::SUB)
                {
                    return; // x + 0 = x, x - 0 = x
                }
            }
        }
        
        emit("addi sp, sp, -4");
        emit("sw a0, 0(sp)");
        generateExpression(expr->left.get());
        emit("lw a1, 0(sp)");
        emit("addi sp, sp, 4");

        switch (expr->op)
        {
        case BinaryOp::ADD:
            emit("add a0, a0, a1");
            break;
        case BinaryOp::SUB:
            emit("sub a0, a0, a1");
            break;
        case BinaryOp::MUL:
            emit("mul a0, a0, a1");
            break;
        case BinaryOp::DIV:
            emit("div a0, a0, a1");
            break;
        case BinaryOp::MOD:
            emit("rem a0, a0, a1");
            break;
        case BinaryOp::LT:
            emit("slt a0, a0, a1");
            break;
        case BinaryOp::GT:
            emit("sgt a0, a0, a1");
            break;
        case BinaryOp::LE:
            emit("sgt a0, a0, a1");
            emit("xori a0, a0, 1");
            break;
        case BinaryOp::GE:
            emit("slt a0, a0, a1");
            emit("xori a0, a0, 1");
            break;
        case BinaryOp::EQ:
            emit("sub a0, a0, a1");
            emit("seqz a0, a0");
            break;
        case BinaryOp::NE:
            emit("sub a0, a0, a1");
            emit("snez a0, a0");
            break;
        default:
            break; // AND and OR are handled above
        }
    }
}

void CodeGenerator::generateShortCircuitAnd(BinaryExpression *expr)
{
    int falseLabel = nextLabel();
    int endLabel = nextLabel();

    // Generate left operand
    generateExpression(expr->left.get());
    emit("beqz a0, " + getLabelName(falseLabel));

    // Generate right operand
    generateExpression(expr->right.get());
    // Normalize right operand to 0/1 for logical result
    emit("snez a0, a0");
    emit("j " + getLabelName(endLabel));

    // False case
    emitLabel(getLabelName(falseLabel));
    emit("li a0, 0");

    emitLabel(getLabelName(endLabel));
}

void CodeGenerator::generateShortCircuitOr(BinaryExpression *expr)
{
    int trueLabel = nextLabel();
    int endLabel = nextLabel();

    // Generate left operand
    generateExpression(expr->left.get());
    emit("bnez a0, " + getLabelName(trueLabel));

    // Generate right operand
    generateExpression(expr->right.get());
    // Normalize right operand to 0/1 for logical result
    emit("snez a0, a0");
    emit("j " + getLabelName(endLabel));

    // True case
    emitLabel(getLabelName(trueLabel));
    emit("li a0, 1");

    emitLabel(getLabelName(endLabel));
}

void CodeGenerator::generateUnaryExpression(UnaryExpression *expr)
{
    generateExpression(expr->operand.get());

    switch (expr->op)
    {
    case UnaryOp::PLUS:
        // No operation needed
        break;
    case UnaryOp::MINUS:
        emit("neg a0, a0");
        break;
    case UnaryOp::NOT:
        emit("seqz a0, a0");
        break;
    }
}

void CodeGenerator::generateLiteralExpression(LiteralExpression *expr)
{
    emit("li a0, " + std::to_string(expr->value));
}

void CodeGenerator::generateVariableExpression(VariableExpression *expr)
{
    int offset = getVariableOffset(expr->name);
    emit("lw a0, " + std::to_string(offset) + "(fp)");
}

void CodeGenerator::generateCallExpression(CallExpression *expr)
{
    size_t argCount = expr->arguments.size();

    if (argCount == 0)
    {
        emit("call " + expr->functionName);
        return;
    }

    // We must not clobber argument registers by nested calls during argument evaluation.
    // Strategy: evaluate all arguments to a temporary area, then move into a-registers
    // and stack argument area right before the call.

    int extraArgs = static_cast<int>(argCount > 8 ? argCount - 8 : 0);
    int spillAreaBytes = extraArgs * 4;                  // area visible to callee for args >8
    int tempAreaBytes = static_cast<int>(argCount) * 4;  // store all evaluated args
    int totalBytes = spillAreaBytes + tempAreaBytes + 8; // +8 for saved ra
    int alignedBytes = (totalBytes + 15) & ~15;          // 16-byte alignment

    emit("addi sp, sp, -" + std::to_string(alignedBytes));
    // Save return address at the top of this call frame
    emit("sw ra, " + std::to_string(alignedBytes - 4) + "(sp)");

    // Base offsets
    int tempBase = spillAreaBytes; // temporary args start after spill area

    // 1) Evaluate all arguments left-to-right, store each to temporary area
    for (size_t i = 0; i < argCount; i++)
    {
        generateExpression(expr->arguments[i].get());
        emit("sw a0, " + std::to_string(tempBase + static_cast<int>(i) * 4) + "(sp)");
    }

    // 2) Move first 8 args into a0-a7 from temporary area
    for (size_t i = 0; i < std::min<size_t>(8, argCount); i++)
    {
        emit("lw a" + std::to_string(i) + ", " +
             std::to_string(tempBase + static_cast<int>(i) * 4) + "(sp)");
    }

    // 3) Place remaining args into spill area at the beginning of the frame
    //    Use t0 as scratch to avoid clobbering a0-a7 which already hold args 0..7
    for (size_t i = 8; i < argCount; i++)
    {
        int src = tempBase + static_cast<int>(i) * 4;
        int dst = static_cast<int>(i - 8) * 4;
        emit("lw t0, " + std::to_string(src) + "(sp)");
        emit("sw t0, " + std::to_string(dst) + "(sp)");
    }

    // 4) Make the call
    emit("call " + expr->functionName);

    // 5) Restore return address and release frame
    emit("lw ra, " + std::to_string(alignedBytes - 4) + "(sp)");
    emit("addi sp, sp, " + std::to_string(alignedBytes));
}