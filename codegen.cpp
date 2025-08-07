#include "codegen.h"
#include <algorithm>
#include <stdexcept>
#include <cmath> // For log2

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

    // Calculate stack space needed (parameters + local variables + saved registers)
    int stackSize = (localVarCount + 2) * 4; // +2 for ra and old fp
    stackSize = (stackSize + 15) & ~15;      // Align to 16 bytes
    currentStackSize = stackSize;

    if (stackSize > 0)
    {
        emit("addi sp, sp, -" + std::to_string(stackSize));
        emit("sw ra, " + std::to_string(stackSize - 4) + "(sp)");
        emit("sw fp, " + std::to_string(stackSize - 8) + "(sp)");
        emit("addi fp, sp, " + std::to_string(stackSize));
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
            if (!enableOptimizations || !isDeadCode(stmt.get())) {
                count++;
            }
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
    
    if (enableOptimizations) {
        analyzeVariableUsage(func->body.get());
    }

    // Count local variables for stack allocation
    int localVarCount = countLocalVariables(func->body.get());

    // Add parameters to variable map (they're in registers initially)
    for (size_t i = 0; i < func->parameters.size(); i++)
    {
        stackOffset -= 4;
        variables[func->parameters[i].name] = stackOffset;
    }

    // Add local variables to variable map
    for (int i = 0; i < localVarCount; i++)
    {
        stackOffset -= 4;
    }

    generateFunctionPrologue(func->name, localVarCount + func->parameters.size());

    // Store parameters from registers to stack
    for (size_t i = 0; i < func->parameters.size() && i < 8; i++)
    {
        int offset = getVariableOffset(func->parameters[i].name);
        emit("sw a" + std::to_string(i) + ", " + std::to_string(offset) + "(fp)");
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
    // Note: isUnreachable is checked in generateStatement for each statement
    for (auto &s : stmt->statements)
    {
        generateStatement(s.get());
    }
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

    // Find the variable's offset
    auto it = variables.find(stmt->name);
    if (it == variables.end())
    {
        // Allocate new variable
        stackOffset -= 4;
        variables[stmt->name] = stackOffset;
    }

    int offset = getVariableOffset(stmt->name);
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

std::optional<int> CodeGenerator::getPowerOfTwoShift(Expression* expr) {
    if (expr->type == NodeType::LITERAL_EXPR) {
        int value = static_cast<LiteralExpression*>(expr)->value;
        if (value > 0 && (value & (value - 1)) == 0) { // Check if power of two
            return static_cast<int>(log2(value));
        }
    }
    return std::nullopt;
}

// 死代码检测
bool CodeGenerator::isDeadCode(Statement* stmt) {
    if (!stmt || !enableOptimizations) return false;
    
    switch (stmt->type) {
        case NodeType::VAR_DECL_STMT: {
            auto* varStmt = static_cast<VarDeclStatement*>(stmt);
            return !usedVariables.count(varStmt->name);
        }
        case NodeType::ASSIGN_STMT: {
            auto* assignStmt = static_cast<AssignStatement*>(stmt);
            return !usedVariables.count(assignStmt->variable);
        }
        default:
            return false;
    }
}

// 变量使用分析
void CodeGenerator::analyzeVariableUsage(BlockStatement* block) {
    if (!block || !enableOptimizations) return;
    
    // 后向分析，找出真正使用的变量
    for (auto it = block->statements.rbegin(); it != block->statements.rend(); ++it) {
        auto& stmt = *it;
        if (!stmt) continue;
        
        switch (stmt->type) {
            case NodeType::RETURN_STMT: {
                auto* retStmt = static_cast<ReturnStatement*>(stmt.get());
                if (retStmt->expression) {
                    // 标记返回值中使用的变量
                    // 这里简化为标记所有变量
                    for (const auto& var : variables) {
                        usedVariables.insert(var.first);
                    }
                }
                break;
            }
            case NodeType::ASSIGN_STMT: {
                auto* assignStmt = static_cast<AssignStatement*>(stmt.get());
                markVariableUsed(assignStmt->variable);
                break;
            }
            case NodeType::VAR_DECL_STMT: {
                auto* varStmt = static_cast<VarDeclStatement*>(stmt.get());
                markVariableUsed(varStmt->name);
                break;
            }
            case NodeType::BLOCK_STMT: {
                analyzeVariableUsage(static_cast<BlockStatement*>(stmt.get()));
                break;
            }
            default:
                break;
        }
    }
}

void CodeGenerator::markVariableUsed(const std::string& name) {
    usedVariables.insert(name);
}

// 强度削弱优化
bool CodeGenerator::shouldUseShiftForMul(Expression* expr) {
    if (!enableOptimizations || !expr || expr->type != NodeType::BINARY_EXPR) 
        return false;
    
    auto* binExpr = static_cast<BinaryExpression*>(expr);
    return binExpr->op == BinaryOp::MUL && 
           (getPowerOfTwoShift(binExpr->left.get()).has_value() || 
            getPowerOfTwoShift(binExpr->right.get()).has_value());
}

bool CodeGenerator::shouldUseShiftForDiv(Expression* expr) {
    if (!enableOptimizations || !expr || expr->type != NodeType::BINARY_EXPR) 
        return false;
    
    auto* binExpr = static_cast<BinaryExpression*>(expr);
    if (binExpr->op == BinaryOp::DIV) {
        if (auto shift = getPowerOfTwoShift(binExpr->right.get())) {
            return *shift >= 0; // 除法也可以优化为右移
        }
    }
    return false;
}

void CodeGenerator::generateBinaryExpression(BinaryExpression* expr) {
    if (expr->op == BinaryOp::AND) {
        generateShortCircuitAnd(expr);
    } else if (expr->op == BinaryOp::OR) {
        generateShortCircuitOr(expr);
    } else {
        // 强度削弱优化：乘法转换为移位
        if (expr->op == BinaryOp::MUL) {
            if (auto shiftAmount = getPowerOfTwoShift(expr->right.get())) {
                generateExpression(expr->left.get());
                emit("slli a0, a0, " + std::to_string(*shiftAmount));
                return;
            }
            if (auto shiftAmount = getPowerOfTwoShift(expr->left.get())) {
                generateExpression(expr->right.get());
                emit("slli a0, a0, " + std::to_string(*shiftAmount));
                return;
            }
        }
        
        // 强度削弱优化：除法转换为移位（仅正数）
        if (expr->op == BinaryOp::DIV) {
            if (auto shiftAmount = getPowerOfTwoShift(expr->right.get())) {
                generateExpression(expr->left.get());
                emit("srai a0, a0, " + std::to_string(*shiftAmount));
                return;
            }
        }
        
        // 强度削弱优化：模运算转换为位运算（仅2的幂次）
        if (expr->op == BinaryOp::MOD) {
            if (auto shiftAmount = getPowerOfTwoShift(expr->right.get())) {
                generateExpression(expr->left.get());
                emit("andi a0, a0, " + std::to_string((1 << *shiftAmount) - 1));
                return;
            }
        }

        generateExpression(expr->right.get());
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
    // Save caller-saved registers if needed
    emit("addi sp, sp, -4");
    emit("sw ra, 0(sp)");

    // Load arguments into registers (up to 8 arguments)
    for (size_t i = 0; i < expr->arguments.size() && i < 8; i++)
    {
        generateExpression(expr->arguments[i].get());
        if (i > 0)
        {
            emit("addi sp, sp, -4");
            emit("sw a" + std::to_string(i) + ", 0(sp)");
        }
    }

    // Restore arguments to correct registers (in reverse order)
    for (int i = std::min(expr->arguments.size(), (size_t)8) - 1; i > 0; i--)
    {
        emit("lw a" + std::to_string(i) + ", 0(sp)");
        emit("addi sp, sp, 4");
    }

    // Call function
    emit("call " + expr->functionName);

    // Restore caller-saved registers
    emit("lw ra, 0(sp)");
    emit("addi sp, sp, 4");
}