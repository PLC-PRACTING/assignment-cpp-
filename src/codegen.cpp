#include "codegen.h"
#include <algorithm>
#include <cmath> // For log2
#include <stdexcept>

CodeGenerator::CodeGenerator()
    : stackOffset(0), labelCounter(0), currentStackSize(0), isUnreachable(false)
{
    variableScopes.clear();
}

void CodeGenerator::emit(const std::string &instruction)
{
    output << "    " << instruction << '\n';
}

void CodeGenerator::emitLabel(const std::string &label)
{
    output << label << ":" << '\n';
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
    // Local variables + saved registers; 对齐到 16 字节即可
    int frameSize = (localVarCount + 2) * 4;   // ra, fp, and local variables
    int maxStackSize = (frameSize + 15) & ~15; // Align to 16 bytes
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
    currentFunctionName = func->name;
    currentFunctionBodyLabel = nextLabel();

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

    // 标记函数体起始位置，便于尾调用跳转
    emitLabel(getLabelName(currentFunctionBodyLabel));
    generateStatement(func->body.get());

    // Add implicit return for void functions
    if (func->returnType == DataType::VOID)
    {
        generateFunctionEpilogue();
    }
    currentFunctionName.clear();
    currentFunctionBodyLabel = -1;
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
    // 进入新作用域：记录本块新增的变量名，避免整表拷贝
    variableScopes.emplace_back();
    int savedStackOffset = stackOffset;

    for (auto &s : stmt->statements)
    {
        generateStatement(s.get());
    }

    // 退出作用域：删除块内新声明变量，并恢复栈偏移
    for (const auto &entry : variableScopes.back())
    {
        if (entry.hadPrevious)
        {
            // 恢复外层同名变量的旧偏移（遮蔽恢复）
            variables[entry.name] = entry.previousOffset;
        }
        else
        {
            // 外层没有该变量，直接删除
            auto it = variables.find(entry.name);
            if (it != variables.end())
            {
                variables.erase(it);
            }
        }
    }
    stackOffset = savedStackOffset;
    variableScopes.pop_back();
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
    // 尾调用消除：return foo(args) -> 直接设置参数跳转到 foo
    if (stmt->expression && stmt->expression->type == NodeType::CALL_EXPR)
    {
        auto *call = static_cast<CallExpression *>(stmt->expression.get());
        // 自尾调用：跳转到当前函数起始处，并将实参写回 a0.. 及栈溢出区
        if (!currentFunctionName.empty() && call->functionName == currentFunctionName)
        {
            // 直接把新参数值写回当前帧中对应的参数栈槽，然后跳回函数体开头
            size_t argCount = call->arguments.size();
            for (size_t i = 0; i < argCount && i < 8; i++)
            {
                generateExpression(call->arguments[i].get());
                int offset = getVariableOffset(functions[currentFunctionName]->parameters[i].name);
                emit("sw a0, " + std::to_string(offset) + "(fp)");
            }
            for (size_t i = 8; i < argCount; i++)
            {
                generateExpression(call->arguments[i].get());
                int offset = getVariableOffset(functions[currentFunctionName]->parameters[i].name);
                emit("sw a0, " + std::to_string(offset) + "(fp)");
            }
            emit("j " + getLabelName(currentFunctionBodyLabel));
            isUnreachable = true;
            return;
        }
    }
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
    // Variable already accounted in prologue
    generateExpression(stmt->initializer.get());

    // 记录遮蔽信息
    bool hadPrev = false;
    int prevOff = 0;
    if (auto it = variables.find(stmt->name); it != variables.end())
    {
        hadPrev = true;
        prevOff = it->second;
    }
    variables[stmt->name] = stackOffset;
    int offset = stackOffset;
    stackOffset -= 4;

    emit("sw a0, " + std::to_string(offset) + "(fp)");

    if (variableScopes.empty())
    {
        variableScopes.emplace_back();
    }
    variableScopes.back().push_back({stmt->name, hadPrev, prevOff});
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

// 将简单表达式直接生成到指定寄存器，当前仅支持立即数与局部变量加载
bool CodeGenerator::tryLoadSimpleExprTo(Expression *expr, const char *regName)
{
    if (!expr)
        return false;
    if (expr->type == NodeType::LITERAL_EXPR)
    {
        int v = static_cast<LiteralExpression *>(expr)->value;
        emit(std::string("li ") + regName + ", " + std::to_string(v));
        return true;
    }
    if (expr->type == NodeType::VARIABLE_EXPR)
    {
        auto *ve = static_cast<VariableExpression *>(expr);
        int offset = getVariableOffset(ve->name);
        emit(std::string("lw ") + regName + ", " + std::to_string(offset) + "(fp)");
        return true;
    }
    return false;
}

void CodeGenerator::emitLoadImmediate(const char *regName, int value)
{
    emit(std::string("li ") + regName + ", " + std::to_string(value));
}

bool CodeGenerator::isITypeImmediate(int value)
{
    // RISC-V I-type imm is 12-bit signed
    return value >= -2048 && value <= 2047;
}

bool CodeGenerator::isSimpleExpr(Expression *expr)
{
    if (!expr)
        return false;
    return expr->type == NodeType::LITERAL_EXPR || expr->type == NodeType::VARIABLE_EXPR;
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

// 变量使用分析
void CodeGenerator::analyzeVariableUsage(BlockStatement *block)
{
    if (!block || !enableOptimizations)
        return;

    // 后向分析，找出真正使用的变量
    for (auto it = block->statements.rbegin(); it != block->statements.rend(); ++it)
    {
        auto &stmt = *it;
        if (!stmt)
            continue;

        switch (stmt->type)
        {
        case NodeType::RETURN_STMT: {
            auto *retStmt = static_cast<ReturnStatement *>(stmt.get());
            if (retStmt->expression)
            {
                // 标记返回值中使用的变量
                // 这里简化为标记所有变量
                for (const auto &var : variables)
                {
                    usedVariables.insert(var.first);
                }
            }
            break;
        }
        case NodeType::ASSIGN_STMT: {
            auto *assignStmt = static_cast<AssignStatement *>(stmt.get());
            markVariableUsed(assignStmt->variable);
            break;
        }
        case NodeType::VAR_DECL_STMT: {
            auto *varStmt = static_cast<VarDeclStatement *>(stmt.get());
            markVariableUsed(varStmt->name);
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
        // 强度削弱优化：乘法转换为移位
        if (expr->op == BinaryOp::MUL)
        {
            if (auto shiftAmount = getPowerOfTwoShift(expr->right.get()))
            {
                generateExpression(expr->left.get());
                emit("slli a0, a0, " + std::to_string(*shiftAmount));
                return;
            }
            if (auto shiftAmount = getPowerOfTwoShift(expr->left.get()))
            {
                generateExpression(expr->right.get());
                emit("slli a0, a0, " + std::to_string(*shiftAmount));
                return;
            }
        }

        // 强度削弱优化：除法转换为移位（仅当左操作数可静态判定为非负时）
        if (expr->op == BinaryOp::DIV)
        {
            if (auto shiftAmount = getPowerOfTwoShift(expr->right.get()))
            {
                if (auto leftVal = tryConstantFolding(expr->left.get()); leftVal && *leftVal >= 0)
                {
                    emit("li a0, " + std::to_string(*leftVal >> *shiftAmount));
                    return;
                }
                // 无法保证非负时，不做该优化，保持语义正确
            }
        }

        // 强度削弱优化：模运算转换为位运算（仅当左操作数可静态判定为非负且2的幂次）
        if (expr->op == BinaryOp::MOD)
        {
            if (auto shiftAmount = getPowerOfTwoShift(expr->right.get()))
            {
                if (auto leftVal = tryConstantFolding(expr->left.get()); leftVal && *leftVal >= 0)
                {
                    int mask = (1 << *shiftAmount) - 1;
                    emit("li a0, " + std::to_string(*leftVal & mask));
                    return;
                }
                // 无法保证非负时，不做该优化
            }
        }

        // 优化但保持正确性：
        // - 若左右都是简单表达式：直接装入寄存器，无需栈
        // - 若右简单左复杂：先求左入a0，再加载右到a1
        // - 若左简单右复杂：先求右入栈，再加载左到a0，最后出栈到a1
        bool leftSimple = isSimpleExpr(expr->left.get());
        bool rightSimple = isSimpleExpr(expr->right.get());

        if (leftSimple && rightSimple)
        {
            tryLoadSimpleExprTo(expr->left.get(), "a0");
            tryLoadSimpleExprTo(expr->right.get(), "a1");
        }
        else if (!leftSimple && rightSimple)
        {
            generateExpression(expr->left.get()); // a0
            tryLoadSimpleExprTo(expr->right.get(), "a1");
        }
        else if (leftSimple && !rightSimple)
        {
            generateExpression(expr->right.get());
            emit("addi sp, sp, -4");
            emit("sw a0, 0(sp)");
            tryLoadSimpleExprTo(expr->left.get(), "a0");
            emit("lw a1, 0(sp)");
            emit("addi sp, sp, 4");
        }
        else
        {
            generateExpression(expr->right.get());
            emit("addi sp, sp, -4");
            emit("sw a0, 0(sp)");
            generateExpression(expr->left.get());
            emit("lw a1, 0(sp)");
            emit("addi sp, sp, 4");
        }

        switch (expr->op)
        {
        case BinaryOp::ADD:
            // 尝试使用 addi a0,a0,imm
            if (auto rv = tryConstantFolding(expr->right.get()); rv && isITypeImmediate(*rv))
            {
                emit("addi a0, a0, " + std::to_string(*rv));
            }
            else
            {
                emit("add a0, a0, a1");
            }
            break;
        case BinaryOp::SUB:
            // a0 - imm => addi a0,a0,-imm
            if (auto rv = tryConstantFolding(expr->right.get()); rv && isITypeImmediate(-*rv))
            {
                emit("addi a0, a0, " + std::to_string(-*rv));
            }
            else
            {
                emit("sub a0, a0, a1");
            }
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

    // 快路径：所有实参均为简单表达式时，直接填充寄存器和溢出区
    bool allSimple = true;
    for (auto &a : expr->arguments)
    {
        if (!isSimpleExpr(a.get()))
        {
            allSimple = false;
            break;
        }
    }
    if (allSimple)
    {
        for (size_t i = 0; i < std::min<size_t>(8, argCount); i++)
        {
            tryLoadSimpleExprTo(expr->arguments[i].get(), ("a" + std::to_string(i)).c_str());
        }
        for (size_t i = 8; i < argCount; i++)
        {
            tryLoadSimpleExprTo(expr->arguments[i].get(), "t0");
            int dst = static_cast<int>(i - 8) * 4;
            emit("sw t0, " + std::to_string(dst) + "(sp)");
        }
        emit("call " + expr->functionName);
        return;
    }

    // 保守策略：为避免嵌套调用破坏，使用临时区缓存所有参数再搬运

    int extraArgs = static_cast<int>(argCount > 8 ? argCount - 8 : 0);
    int spillAreaBytes = extraArgs * 4;                 // area visible to callee for args >8
    int tempAreaBytes = static_cast<int>(argCount) * 4; // store all evaluated args
    int totalBytes = spillAreaBytes + tempAreaBytes;    // no caller-saved ra
    int alignedBytes = (totalBytes + 15) & ~15;         // 16-byte alignment

    emit("addi sp, sp, -" + std::to_string(alignedBytes));
    // No need to save ra here; callee will handle ra preservation.

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

    // 5) Release frame
    emit("addi sp, sp, " + std::to_string(alignedBytes));
}