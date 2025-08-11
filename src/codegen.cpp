#include "codegen.h"
#include <algorithm>
#include <cmath> // For log2
#include <functional>
#include <sstream>
#include <stdexcept>

CodeGenerator::CodeGenerator()
    : stackOffset(0), labelCounter(0), currentStackSize(0), isUnreachable(false), lastInstruction("")
{
    variableScopes.clear();
    a0HoldsVariable = false;
    a0HeldVarOffset = 0;
    a1HoldsVariable = false;
    a1HeldVarOffset = 0;
}

void CodeGenerator::emit(const std::string &instruction)
{
    if (enableOptimizations && !lastInstruction.empty()) {
        // 窥孔优化：消除冗余的加载/存储
        if (instruction.rfind("lw a0", 0) == 0 && lastInstruction.rfind("sw a0", 0) == 0) {
            if (instruction.substr(instruction.find(",")) == lastInstruction.substr(lastInstruction.find(","))) {
                // sw a0, X(sp) 后面跟着 lw a0, X(sp)，忽略lw
                lastInstruction = instruction;
                return;
            }
        }
    }
    output << "    " << instruction << '\n';
    lastInstruction = instruction;
    // 写栈/读栈或对 a0 赋新值的指令，会导致 a0 的缓存失效
    // 这里做一个极其保守的失效：只要不是以 "lw a0," 开头就清空缓存
    if (instruction.rfind("lw a0,", 0) != 0)
    {
        a0HoldsVariable = false;
    }
}

void CodeGenerator::emitLabel(const std::string &label)
{
    output << label << ":" << '\n';
    invalidateA0Cache();
}

int CodeGenerator::nextLabel()
{
    return ++labelCounter;
}

std::string CodeGenerator::getLabelName(int labelId)
{
    return ".L" + std::to_string(labelId);
}

void CodeGenerator::invalidateA0Cache()
{
    a0HoldsVariable = false;
    a1HoldsVariable = false;
}

// 将表达式序列化为一个可比较的字符串（保守、忽略临时标签）
std::string CodeGenerator::serializeExpr(Expression *expr)
{
    if (!expr)
        return "";
    std::ostringstream s;
    switch (expr->type)
    {
    case NodeType::LITERAL_EXPR:
        s << "L(" << static_cast<LiteralExpression *>(expr)->value << ")";
        break;
    case NodeType::VARIABLE_EXPR:
        s << "V(" << static_cast<VariableExpression *>(expr)->name << ")";
        break;
    case NodeType::UNARY_EXPR: {
        auto *u = static_cast<UnaryExpression *>(expr);
        s << "U(" << (int)u->op << "," << serializeExpr(u->operand.get()) << ")";
        break;
    }
    case NodeType::BINARY_EXPR: {
        auto *b = static_cast<BinaryExpression *>(expr);
        s << "B(" << (int)b->op << "," << serializeExpr(b->left.get()) << ","
          << serializeExpr(b->right.get()) << ")";
        break;
    }
    case NodeType::CALL_EXPR: {
        auto *c = static_cast<CallExpression *>(expr);
        s << "C(" << c->functionName;
        for (auto &a : c->arguments)
            s << "," << serializeExpr(a.get());
        s << ")";
        break;
    }
    default:
        break;
    }
    return s.str();
}

void CodeGenerator::collectAssignedVars(Statement *stmt, std::unordered_set<std::string> &out)
{
    if (!stmt)
        return;
    switch (stmt->type)
    {
    case NodeType::ASSIGN_STMT: {
        auto *a = static_cast<AssignStatement *>(stmt);
        out.insert(a->variable);
        break;
    }
    case NodeType::VAR_DECL_STMT: {
        auto *v = static_cast<VarDeclStatement *>(stmt);
        out.insert(v->name);
        break;
    }
    case NodeType::BLOCK_STMT: {
        auto *b = static_cast<BlockStatement *>(stmt);
        for (auto &s : b->statements)
            collectAssignedVars(s.get(), out);
        break;
    }
    default:
        break;
    }
}

void CodeGenerator::collectExprs(Statement *stmt, std::vector<Expression *> &out)
{
    if (!stmt)
        return;
    switch (stmt->type)
    {
    case NodeType::EXPR_STMT:
        out.push_back(static_cast<ExpressionStatement *>(stmt)->expression.get());
        break;
    case NodeType::ASSIGN_STMT:
        out.push_back(static_cast<AssignStatement *>(stmt)->expression.get());
        break;
    case NodeType::VAR_DECL_STMT:
        out.push_back(static_cast<VarDeclStatement *>(stmt)->initializer.get());
        break;
    case NodeType::BLOCK_STMT: {
        auto *b = static_cast<BlockStatement *>(stmt);
        for (auto &s : b->statements)
            collectExprs(s.get(), out);
        break;
    }
    default:
        break;
    }
}

void CodeGenerator::collectDeps(Expression *expr, std::unordered_set<std::string> &vars,
                                bool &hasCall)
{
    if (!expr)
        return;
    switch (expr->type)
    {
    case NodeType::VARIABLE_EXPR:
        vars.insert(static_cast<VariableExpression *>(expr)->name);
        break;
    case NodeType::UNARY_EXPR:
        collectDeps(static_cast<UnaryExpression *>(expr)->operand.get(), vars, hasCall);
        break;
    case NodeType::BINARY_EXPR: {
        auto *b = static_cast<BinaryExpression *>(expr);
        collectDeps(b->left.get(), vars, hasCall);
        collectDeps(b->right.get(), vars, hasCall);
        break;
    }
    case NodeType::CALL_EXPR:
        hasCall = true;
        break;
    default:
        break;
    }
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

    // 参数使用性扫描（极简遍历，仅用于决定是否需要为参数分配槽并保存）
    std::function<bool(Expression *, const std::string &)> exprUsesVar =
        [&](Expression *e, const std::string &name) -> bool {
        if (!e)
            return false;
        switch (e->type)
        {
        case NodeType::VARIABLE_EXPR:
            return static_cast<VariableExpression *>(e)->name == name;
        case NodeType::UNARY_EXPR:
            return exprUsesVar(static_cast<UnaryExpression *>(e)->operand.get(), name);
        case NodeType::BINARY_EXPR: {
            auto *b = static_cast<BinaryExpression *>(e);
            return exprUsesVar(b->left.get(), name) || exprUsesVar(b->right.get(), name);
        }
        case NodeType::CALL_EXPR: {
            auto *c = static_cast<CallExpression *>(e);
            for (auto &a : c->arguments)
                if (exprUsesVar(a.get(), name))
                    return true;
            return false;
        }
        default:
            return false;
        }
    };
    std::function<bool(Statement *, const std::string &)> stmtUsesVar =
        [&](Statement *s, const std::string &name) -> bool {
        if (!s)
            return false;
        switch (s->type)
        {
        case NodeType::EXPR_STMT:
            return exprUsesVar(static_cast<ExpressionStatement *>(s)->expression.get(), name);
        case NodeType::ASSIGN_STMT: {
            auto *a = static_cast<AssignStatement *>(s);
            if (a->variable == name)
                return true;
            return exprUsesVar(a->expression.get(), name);
        }
        case NodeType::VAR_DECL_STMT: {
            auto *v = static_cast<VarDeclStatement *>(s);
            return exprUsesVar(v->initializer.get(), name);
        }
        case NodeType::RETURN_STMT:
            return exprUsesVar(static_cast<ReturnStatement *>(s)->expression.get(), name);
        case NodeType::IF_STMT: {
            auto *i = static_cast<IfStatement *>(s);
            if (exprUsesVar(i->condition.get(), name))
                return true;
            if (stmtUsesVar(i->thenStmt.get(), name))
                return true;
            return stmtUsesVar(i->elseStmt.get(), name);
        }
        case NodeType::WHILE_STMT: {
            auto *w = static_cast<WhileStatement *>(s);
            if (exprUsesVar(w->condition.get(), name))
                return true;
            return stmtUsesVar(w->body.get(), name);
        }
        case NodeType::BLOCK_STMT: {
            auto *b = static_cast<BlockStatement *>(s);
            for (auto &ss : b->statements)
                if (stmtUsesVar(ss.get(), name))
                    return true;
            return false;
        }
        default:
            return false;
        }
    };

    // Calculate proper stack layout（为所有形参保留槽位，避免间隔导致的越界/重叠）
    int paramCount = static_cast<int>(func->parameters.size());
    int totalLocals = localVarCount + paramCount; // 保存槽位数（不含 ra/fp）

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

    // 生成标准序言（经过验证更稳健）
    generateFunctionPrologue(func->name, totalLocals);

    // Store parameters from registers to stack（对前 8 个形参全部保存，确保槽位可用）
    for (size_t i = 0; i < func->parameters.size() && i < 8; i++)
    {
        int offset = getVariableOffset(func->parameters[i].name);
        emit("sw a" + std::to_string(i) + ", " + std::to_string(offset) + "(fp)");
    }
    invalidateA0Cache();

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
    invalidateA0Cache();

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
    default:
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

    // 禁用激进的不变式缓存，避免越界写栈导致错误结果
    invariantExprToOffset.clear();
    invariantReuseEnabled = false;
    invariantComputeBypass = false;

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

void CodeGenerator::generateBreakStatement([[maybe_unused]] BreakStatement *stmt)
{
    if (loopBreakLabels.empty())
    {
        throw std::runtime_error("Break statement outside of loop");
    }
    emit("j " + getLabelName(loopBreakLabels.back()));
    isUnreachable = true;
}

void CodeGenerator::generateContinueStatement([[maybe_unused]] ContinueStatement *stmt)
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

    // 简易 CSE：当循环复用开启且表达式可序列化命中缓存，直接从缓存槽加载
    if (invariantReuseEnabled && !invariantComputeBypass)
    {
        auto key = serializeExpr(expr);
        auto it = invariantExprToOffset.find(key);
        if (it != invariantExprToOffset.end() && it->second != 0)
        {
            emit("lw a0, " + std::to_string(it->second) + "(fp)");
            return;
        }
    }

    if (auto constValue = tryConstantFolding(expr))
    {
        emit("li a0, " + std::to_string(*constValue));
        // 常量不进入缓存
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
    default:
        break;
    }

    // 表达式结果计算完成，若处于循环复用阶段且该表达式在候选集合中，第一次使用时为其分配槽并写回
    if (invariantReuseEnabled && !invariantComputeBypass)
    {
        auto key = serializeExpr(expr);
        auto it = invariantExprToOffset.find(key);
        if (it != invariantExprToOffset.end())
        {
            if (it->second == 0)
            {
                // 分配一个新的槽位（使用当前 stackOffset）
                int slot = stackOffset;
                stackOffset -= 4;
                it->second = slot;
            }
            emit("sw a0, " + std::to_string(it->second) + "(fp)");
        }
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

static bool exprHasCallRecursive(Expression *expr)
{
    if (!expr)
        return false;
    switch (expr->type)
    {
    case NodeType::CALL_EXPR:
        return true;
    case NodeType::UNARY_EXPR:
        return exprHasCallRecursive(static_cast<UnaryExpression *>(expr)->operand.get());
    case NodeType::BINARY_EXPR: {
        auto *b = static_cast<BinaryExpression *>(expr);
        return exprHasCallRecursive(b->left.get()) || exprHasCallRecursive(b->right.get());
    }
    default:
        return false;
    }
}

// no header declaration; keep internal helper only

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
        // 比较/等于的立即数优化（不改变求值顺序，安全早返回）
        // 形如 a < C, a <= C, a > C, a >= C, a == 0, a != 0
        auto rightIsImm = [&](int &immOut) -> bool {
            if (expr->right && expr->right->type == NodeType::LITERAL_EXPR)
            {
                immOut = static_cast<LiteralExpression *>(expr->right.get())->value;
                return true;
            }
            return false;
        };

        int immVal = 0;

        // 代数恒等式（不改变求值顺序的前提下）：
        // ADD：0 + x => x；x + 0 => x
        if (expr->op == BinaryOp::ADD)
        {
            if (expr->left && expr->left->type == NodeType::LITERAL_EXPR &&
                static_cast<LiteralExpression *>(expr->left.get())->value == 0)
            {
                // 左是 0：直接计算右
                generateExpression(expr->right.get());
                return;
            }
            if (expr->right && expr->right->type == NodeType::LITERAL_EXPR &&
                static_cast<LiteralExpression *>(expr->right.get())->value == 0)
            {
                // 右是 0：直接计算左
                generateExpression(expr->left.get());
                return;
            }
        }

        // SUB：x - 0 => x；0 - x => -x（需计算右边保持副作用）
        if (expr->op == BinaryOp::SUB)
        {
            if (expr->right && expr->right->type == NodeType::LITERAL_EXPR &&
                static_cast<LiteralExpression *>(expr->right.get())->value == 0)
            {
                generateExpression(expr->left.get());
                return;
            }
            if (expr->left && expr->left->type == NodeType::LITERAL_EXPR &&
                static_cast<LiteralExpression *>(expr->left.get())->value == 0)
            {
                generateExpression(expr->right.get());
                emit("neg a0, a0");
                return;
            }
        }
        // 若左侧是立即数而右侧不是，尝试对比较运算做等价变换：
        // C < x → x > C，C <= x → x >= C，C > x → x < C，C >= x → x <= C，
        // C == x / C != x → x == C / x != C
        if (expr->left && expr->left->type == NodeType::LITERAL_EXPR &&
            (!expr->right || expr->right->type != NodeType::LITERAL_EXPR))
        {
            int lv = static_cast<LiteralExpression *>(expr->left.get())->value;
            BinaryOp mapped = expr->op;
            bool mappable = true;
            switch (expr->op)
            {
            case BinaryOp::LT:
                mapped = BinaryOp::GT;
                break;
            case BinaryOp::LE:
                mapped = BinaryOp::GE;
                break;
            case BinaryOp::GT:
                mapped = BinaryOp::LT;
                break;
            case BinaryOp::GE:
                mapped = BinaryOp::LE;
                break;
            case BinaryOp::EQ:
                mapped = BinaryOp::EQ;
                break;
            case BinaryOp::NE:
                mapped = BinaryOp::NE;
                break;
            default:
                mappable = false;
                break; // 仅处理比较与相等
            }
            if (mappable && isITypeImmediate(lv))
            {
                // 生成右值到 a0，然后套用“右侧立即数”的优化逻辑
                generateExpression(expr->right.get());
                // 利用下方同样的模式：把 (x op C) 的情形直接落指令
                switch (mapped)
                {
                case BinaryOp::LT:
                    emit("slti a0, a0, " + std::to_string(lv));
                    return;
                case BinaryOp::LE:
                    if (isITypeImmediate(lv + 1))
                    {
                        emit("slti a0, a0, " + std::to_string(lv + 1));
                        return;
                    }
                    break;
                case BinaryOp::GT:
                    if (isITypeImmediate(lv + 1))
                    {
                        emit("slti a0, a0, " + std::to_string(lv + 1));
                        emit("xori a0, a0, 1");
                        return;
                    }
                    break;
                case BinaryOp::GE:
                    emit("slti a0, a0, " + std::to_string(lv));
                    emit("xori a0, a0, 1");
                    return;
                case BinaryOp::EQ:
                    if (lv == 0)
                    {
                        emit("seqz a0, a0");
                        return;
                    }
                    else if (isITypeImmediate(-lv))
                    {
                        emit("addi a0, a0, " + std::to_string(-lv));
                        emit("seqz a0, a0");
                        return;
                    }
                    break;
                case BinaryOp::NE:
                    if (lv == 0)
                    {
                        emit("snez a0, a0");
                        return;
                    }
                    else if (isITypeImmediate(-lv))
                    {
                        emit("addi a0, a0, " + std::to_string(-lv));
                        emit("snez a0, a0");
                        return;
                    }
                    break;
                default:
                    break;
                }
                // 若立即数范围不适配，则继续走通用路径
            }
        }

        if (rightIsImm(immVal))
        {
            switch (expr->op)
            {
            // 按位运算不在本语言语义中（AND/OR 用于逻辑短路），此处不做 andi/ori 优化
            case BinaryOp::MUL:
                if (immVal == 0)
                {
                    generateExpression(expr->left.get());
                    emit("li a0, 0");
                    return;
                }
                else if (immVal == 1)
                {
                    generateExpression(expr->left.get());
                    return;
                }
                else if (immVal == -1)
                {
                    generateExpression(expr->left.get());
                    emit("neg a0, a0");
                    return;
                }
                break;
            case BinaryOp::DIV:
                if (immVal == 1)
                {
                    generateExpression(expr->left.get());
                    return;
                }
                break;
            case BinaryOp::MOD:
                if (immVal == 1 || immVal == -1)
                {
                    generateExpression(expr->left.get());
                    emit("li a0, 0");
                    return;
                }
                break;
            case BinaryOp::LT:
                if (isITypeImmediate(immVal))
                {
                    generateExpression(expr->left.get());
                    emit("slti a0, a0, " + std::to_string(immVal));
                    return;
                }
                break;
            case BinaryOp::LE:
                if (isITypeImmediate(immVal + 1))
                {
                    generateExpression(expr->left.get());
                    emit("slti a0, a0, " + std::to_string(immVal + 1));
                    return;
                }
                break;
            case BinaryOp::GT:
                if (isITypeImmediate(immVal + 1))
                {
                    generateExpression(expr->left.get());
                    emit("slti a0, a0, " + std::to_string(immVal + 1));
                    emit("xori a0, a0, 1");
                    return;
                }
                break;
            case BinaryOp::GE:
                if (isITypeImmediate(immVal))
                {
                    generateExpression(expr->left.get());
                    emit("slti a0, a0, " + std::to_string(immVal));
                    emit("xori a0, a0, 1");
                    return;
                }
                break;
            case BinaryOp::EQ:
                if (immVal == 0)
                {
                    generateExpression(expr->left.get());
                    emit("seqz a0, a0");
                    return;
                }
                else if (isITypeImmediate(-immVal))
                {
                    generateExpression(expr->left.get());
                    emit("addi a0, a0, " + std::to_string(-immVal));
                    emit("seqz a0, a0");
                    return;
                }
                break;
            case BinaryOp::NE:
                if (immVal == 0)
                {
                    generateExpression(expr->left.get());
                    emit("snez a0, a0");
                    return;
                }
                else if (isITypeImmediate(-immVal))
                {
                    generateExpression(expr->left.get());
                    emit("addi a0, a0, " + std::to_string(-immVal));
                    emit("snez a0, a0");
                    return;
                }
                break;
            default:
                break;
            }
        }

        // 左操作数为立即数的可交换优化（仅算术）：
        // - 加法：imm + x -> addi x, imm
        if (expr->left && expr->left->type == NodeType::LITERAL_EXPR)
        {
            int lv = static_cast<LiteralExpression *>(expr->left.get())->value;
            switch (expr->op)
            {
            case BinaryOp::ADD:
                if (isITypeImmediate(lv))
                {
                    generateExpression(expr->right.get());
                    if (lv != 0)
                        emit("addi a0, a0, " + std::to_string(lv));
                    return;
                }
                break;
            default:
                break;
            }
        }

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

        // 强度削弱优化：常量移位
        if (expr->op == BinaryOp::DIV || expr->op == BinaryOp::MOD)
        {
            // 已在后面处理，保持原逻辑
        }
        else if (expr->op == BinaryOp::ADD || expr->op == BinaryOp::SUB)
        {
            // 非移位运算，跳过
        }
        else
        {
            // 只支持移位节点：这里假设语法中暂未显式提供移位运算，
            // 因此不做其它转换
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
        // - 若两侧都不包含调用：用 t0 临时寄存器转存右操作数，避免入栈/出栈
        // - 若右简单左复杂：先求左入a0，再加载右到a1
        // - 若左简单右复杂：先求右入栈，再加载左到a0，最后出栈到a1
        bool leftSimple = isSimpleExpr(expr->left.get());
        bool rightSimple = isSimpleExpr(expr->right.get());

        if (leftSimple && rightSimple)
        {
            tryLoadSimpleExprTo(expr->left.get(), "a0");
            tryLoadSimpleExprTo(expr->right.get(), "a1");
            // 变量相同的特例：进一步规约
            if (expr->left->type == NodeType::VARIABLE_EXPR &&
                expr->right->type == NodeType::VARIABLE_EXPR)
            {
                auto *lv = static_cast<VariableExpression *>(expr->left.get());
                auto *rv = static_cast<VariableExpression *>(expr->right.get());
                int loff = getVariableOffset(lv->name);
                int roff = getVariableOffset(rv->name);
                if (loff == roff)
                {
                    switch (expr->op)
                    {
                    case BinaryOp::ADD:
                        // x + x => slli x,1
                        emit("slli a0, a0, 1");
                        return;
                    case BinaryOp::SUB:
                        emit("li a0, 0");
                        return;
                    case BinaryOp::EQ:
                        emit("li a0, 1");
                        return;
                    case BinaryOp::NE:
                        emit("li a0, 0");
                        return;
                    case BinaryOp::LT:
                        emit("li a0, 0");
                        return;
                    case BinaryOp::LE:
                        emit("li a0, 1");
                        return;
                    case BinaryOp::GT:
                        emit("li a0, 0");
                        return;
                    case BinaryOp::GE:
                        emit("li a0, 1");
                        return;
                    default:
                        break;
                    }
                }
            }
        }
        // 注意：不要在此使用寄存器保存右值以避免被左侧求值过程覆写（左侧生成可能会使用 a1）。
        // 保守栈路径
        else if (!leftSimple && rightSimple)
        {
            generateExpression(expr->left.get()); // a0
            tryLoadSimpleExprTo(expr->right.get(), "a1");
        }
        else if (leftSimple && !rightSimple)
        {
            // 右侧复杂：先计算右值到 a0，再将其移动到 a1，避免入栈/出栈开销；
            // 随后把左侧简单表达式直接装入 a0。
            generateExpression(expr->right.get());
            // mv a1,a0（以 addi 形式发出，便于所有汇编器接受）
            emit("addi a1, a0, 0");
            tryLoadSimpleExprTo(expr->left.get(), "a0");
            a1HoldsVariable = false; // 复杂生成可能覆盖
        }
        else
        {
            // 增强的寄存器分配：如果可能，使用临时寄存器而不是堆栈
            if (enableOptimizations && !exprHasCallRecursive(expr->left.get()) && !exprHasCallRecursive(expr->right.get())) {
                generateExpression(expr->left.get());
                emit("addi t0, a0, 0"); // 使用t0作为临时寄存器
                generateExpression(expr->right.get());
                emit("addi a1, a0, 0");
                emit("addi a0, t0, 0");
            } else {
                // 增强的CSE：如果两个子表达式相同，则只计算一次
                if (enableOptimizations && serializeExpr(expr->left.get()) == serializeExpr(expr->right.get())) {
                    generateExpression(expr->left.get());
                    emit("addi a1, a0, 0"); // a1 = a0
                } else {
                    generateExpression(expr->right.get());
                    emit("addi sp, sp, -4");
                    emit("sw a0, 0(sp)");
                    generateExpression(expr->left.get());
                    emit("lw a1, 0(sp)");
                    emit("addi sp, sp, 4");
                }
            }
        }

        switch (expr->op)
        {
        case BinaryOp::ADD:
            // 补充：左立即数且右非简单 -> 已在上方处理；
            // 这里增加 "x + (-C)" 规约
            if (auto rv = tryConstantFolding(expr->right.get()); rv && isITypeImmediate(*rv))
            {
                if (*rv != 0)
                {
                    emit("addi a0, a0, " + std::to_string(*rv));
                }
            }
            else
            {
                emit("add a0, a0, a1");
            }
            break;
        case BinaryOp::SUB:
            // a0 - imm => addi a0,a0,-imm（当 -imm 为 0 时同样跳过）
            if (auto rv = tryConstantFolding(expr->right.get()); rv && isITypeImmediate(-*rv))
            {
                if (-*rv != 0)
                {
                    emit("addi a0, a0, " + std::to_string(-*rv));
                }
                // -rv==0 时无需发指令
            }
            else
            {
                emit("sub a0, a0, a1");
            }
            break;
        case BinaryOp::AND:
            emit("and a0, a0, a1");
            break;
        case BinaryOp::OR:
            emit("or a0, a0, a1");
            break;
        case BinaryOp::MUL:
            // 乘以小常量（右值是常量时已在前面处理）；
            // 这里处理左值为常量的情形
            if (auto lv = tryConstantFolding(expr->left.get()))
            {
                int c = *lv;
                if (c == 0)
                {
                    emit("li a0, 0");
                }
                else if (c == 1)
                {
                    // a0 already holds right operand
                }
                else if (c == -1)
                {
                    emit("neg a0, a0");
                }
                else if (c == 2)
                {
                    emit("slli a0, a0, 1");
                }
                else if (c == 4)
                {
                    emit("slli a0, a0, 2");
                }
                else if (c == 8)
                {
                    emit("slli a0, a0, 3");
                }
                else
                {
                    emit("mul a0, a0, a1");
                }
            }
            else
            {
                emit("mul a0, a0, a1");
            }
            break;
        case BinaryOp::DIV:
            // 保守：保持除法指令，避免负数时 srai 与 C 语义（趋零截断）不一致
            emit("div a0, a0, a1");
            break;
        case BinaryOp::MOD:
            // 右操作数为 2 的幂：用位掩码实现（x & (2^k-1)）。
            if (auto sh = getPowerOfTwoShift(expr->right.get()))
            {
                int mask = (1 << *sh) - 1;
                if (isITypeImmediate(mask))
                {
                    emit("andi a0, a0, " + std::to_string(mask));
                }
                else
                {
                    emit("li t0, " + std::to_string(mask));
                    emit("and a0, a0, t0");
                }
            }
            else
            {
                emit("rem a0, a0, a1");
            }
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
    // 保守寄存器复用：若 a0 已经持有同一槽位的值且中间无调用/破坏，则无需再次 lw
    if (a0HoldsVariable && a0HeldVarOffset == offset)
    {
        return;
    }
    emit("lw a0, " + std::to_string(offset) + "(fp)");
    a0HoldsVariable = true;
    a0HeldVarOffset = offset;
}

void CodeGenerator::generateCallExpression(CallExpression *expr)
{
    invalidateA0Cache();
    size_t argCount = expr->arguments.size();

    if (argCount == 0)
    {
        emit("call " + expr->functionName);
        return;
    }

    // 快路径：所有实参均为简单表达式且不包含调用，直接填充寄存器和溢出区
    bool allSimple = true;
    for (auto &a : expr->arguments)
    {
        if (!isSimpleExpr(a.get()) || exprHasCallRecursive(a.get()))
        {
            allSimple = false;
            break;
        }
    }
    if (allSimple)
    {
        int extraArgs = static_cast<int>(argCount > 8 ? argCount - 8 : 0);
        int spillAreaBytes = extraArgs * 4;
        int alignedBytes = (spillAreaBytes + 15) & ~15;
        if (alignedBytes > 0)
        {
            emit("addi sp, sp, -" + std::to_string(alignedBytes));
        }
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
        if (alignedBytes > 0)
        {
            emit("addi sp, sp, " + std::to_string(alignedBytes));
        }
        return;
    }

    // 保守策略：为避免嵌套调用破坏，使用临时区缓存所有参数再搬运

    int extraArgs = static_cast<int>(argCount > 8 ? argCount - 8 : 0);
    int spillAreaBytes = extraArgs * 4;                 // area visible to callee for args >8
    int tempAreaBytes = static_cast<int>(argCount) * 4; // store all evaluated args
    int totalBytes = spillAreaBytes + tempAreaBytes;    // no caller-saved ra
    int alignedBytes = (totalBytes + 15) & ~15;         // 16-byte alignment

    emit("addi sp, sp, -" + std::to_string(alignedBytes));

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
    invalidateA0Cache();
}