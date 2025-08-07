#include "semantic.h"
#include <stdexcept>
#include <sstream>

SemanticAnalyzer::SemanticAnalyzer() 
    : currentScopeLevel(0), loopDepth(0), currentFunctionReturnType(DataType::VOID) {
    // Initialize global scope
    scopes.emplace_back();
}

void SemanticAnalyzer::enterScope() {
    currentScopeLevel++;
    scopes.emplace_back();
}

void SemanticAnalyzer::exitScope() {
    if (currentScopeLevel > 0) {
        currentScopeLevel--;
        scopes.pop_back();
    }
}

void SemanticAnalyzer::declareVariable(const std::string& name, DataType type) {
    // Check if variable already exists in current scope
    auto& currentScope = scopes.back();
    if (currentScope.find(name) != currentScope.end()) {
        throw std::runtime_error("Variable '" + name + "' already declared in this scope");
    }
    
    currentScope[name] = VariableInfo(type, true, currentScopeLevel);
}

void SemanticAnalyzer::checkVariableExists(const std::string& name) {
    // Search from innermost to outermost scope
    for (auto it = scopes.rbegin(); it != scopes.rend(); ++it) {
        if (it->find(name) != it->end()) {
            return; // Variable found
        }
    }
    
    throw std::runtime_error("Undefined variable '" + name + "'");
}

void SemanticAnalyzer::checkFunctionExists(const std::string& name) {
    if (functions.find(name) == functions.end()) {
        throw std::runtime_error("Undefined function '" + name + "'");
    }
}

void SemanticAnalyzer::checkTypeCompatibility(DataType expected, DataType actual, const std::string& context) {
    if (expected != actual) {
        std::stringstream ss;
        ss << "Type mismatch in " << context << ": expected ";
        ss << (expected == DataType::INT ? "int" : "void");
        ss << ", got " << (actual == DataType::INT ? "int" : "void");
        throw std::runtime_error(ss.str());
    }
}

void SemanticAnalyzer::analyze(Program* program) {
    analyzeProgram(program);
}

void SemanticAnalyzer::analyzeProgram(Program* program) {
    // First pass: collect all function declarations
    for (auto& func : program->functions) {
        std::vector<DataType> paramTypes;
        for (const auto& param : func->parameters) {
            paramTypes.push_back(param.type);
        }
        
        if (functions.find(func->name) != functions.end()) {
            throw std::runtime_error("Function '" + func->name + "' already declared");
        }
        
        functions[func->name] = FunctionInfo(func->returnType, paramTypes, true);
    }
    
    // Check for main function
    if (functions.find("main") == functions.end()) {
        throw std::runtime_error("Program must contain a 'main' function");
    }
    
    const FunctionInfo& mainFunc = functions["main"];
    if (mainFunc.returnType != DataType::INT || !mainFunc.paramTypes.empty()) {
        throw std::runtime_error("'main' function must have return type 'int' and no parameters");
    }
    
    // Second pass: analyze function bodies
    for (auto& func : program->functions) {
        analyzeFunctionDeclaration(func.get());
    }
}

void SemanticAnalyzer::analyzeFunctionDeclaration(FunctionDeclaration* func) {
    currentFunctionReturnType = func->returnType;
    currentFunctionName = func->name;
    
    enterScope();
    
    // Add parameters to scope
    for (const auto& param : func->parameters) {
        declareVariable(param.name, param.type);
    }
    
    analyzeStatement(func->body.get());
    
    // Check return paths for int functions
    if (func->returnType == DataType::INT) {
        checkReturnPaths(func);
    }
    
    exitScope();
}

void SemanticAnalyzer::checkReturnPaths(FunctionDeclaration* func) {
    if (!hasReturnInAllPaths(func->body.get())) {
        throw std::runtime_error("Function '" + func->name + "' must return a value on all paths");
    }
}

bool SemanticAnalyzer::hasReturnInAllPaths(Statement* stmt) {
    if (!stmt) return false;
    
    switch (stmt->type) {
        case NodeType::RETURN_STMT:
            return true;
            
        case NodeType::BLOCK_STMT: {
            auto block = static_cast<BlockStatement*>(stmt);
            for (auto& s : block->statements) {
                if (s && hasReturnInAllPaths(s.get())) {
                    return true;
                }
            }
            return false;
        }
        
        case NodeType::IF_STMT: {
            auto ifStmt = static_cast<IfStatement*>(stmt);
            return ifStmt->elseStmt && 
                   hasReturnInAllPaths(ifStmt->thenStmt.get()) && 
                   hasReturnInAllPaths(ifStmt->elseStmt.get());
        }
        
        case NodeType::WHILE_STMT: {
            auto whileStmt = static_cast<WhileStatement*>(stmt);
            return hasReturnInAllPaths(whileStmt->body.get());
        }
        
        default:
            return false;
    }
}

void SemanticAnalyzer::analyzeStatement(Statement* stmt) {
    if (!stmt) return;
    
    switch (stmt->type) {
        case NodeType::BLOCK_STMT:
            analyzeBlockStatement(static_cast<BlockStatement*>(stmt));
            break;
        case NodeType::IF_STMT:
            analyzeIfStatement(static_cast<IfStatement*>(stmt));
            break;
        case NodeType::WHILE_STMT:
            analyzeWhileStatement(static_cast<WhileStatement*>(stmt));
            break;
        case NodeType::RETURN_STMT:
            analyzeReturnStatement(static_cast<ReturnStatement*>(stmt));
            break;
        case NodeType::BREAK_STMT:
            analyzeBreakStatement(static_cast<BreakStatement*>(stmt));
            break;
        case NodeType::CONTINUE_STMT:
            analyzeContinueStatement(static_cast<ContinueStatement*>(stmt));
            break;
        case NodeType::ASSIGN_STMT:
            analyzeAssignStatement(static_cast<AssignStatement*>(stmt));
            break;
        case NodeType::VAR_DECL_STMT:
            analyzeVarDeclStatement(static_cast<VarDeclStatement*>(stmt));
            break;
        case NodeType::EXPR_STMT:
            analyzeExpressionStatement(static_cast<ExpressionStatement*>(stmt));
            break;
        case NodeType::BINARY_EXPR:
        case NodeType::UNARY_EXPR:
        case NodeType::LITERAL_EXPR:
        case NodeType::VARIABLE_EXPR:
        case NodeType::CALL_EXPR:
        case NodeType::FUNCTION_DECL:
        case NodeType::PARAM_DECL:
        case NodeType::PROGRAM:
            break;
    }
}

void SemanticAnalyzer::analyzeBlockStatement(BlockStatement* stmt) {
    enterScope();
    for (auto& s : stmt->statements) {
        analyzeStatement(s.get());
    }
    exitScope();
}

void SemanticAnalyzer::analyzeIfStatement(IfStatement* stmt) {
    DataType condType = analyzeExpression(stmt->condition.get());
    checkTypeCompatibility(DataType::INT, condType, "if condition");
    
    analyzeStatement(stmt->thenStmt.get());
    if (stmt->elseStmt) {
        analyzeStatement(stmt->elseStmt.get());
    }
}

void SemanticAnalyzer::analyzeWhileStatement(WhileStatement* stmt) {
    DataType condType = analyzeExpression(stmt->condition.get());
    checkTypeCompatibility(DataType::INT, condType, "while condition");
    
    loopDepth++;
    analyzeStatement(stmt->body.get());
    loopDepth--;
}

void SemanticAnalyzer::analyzeReturnStatement(ReturnStatement* stmt) {
    if (stmt->expression) {
        DataType exprType = analyzeExpression(stmt->expression.get());
        checkTypeCompatibility(currentFunctionReturnType, exprType, "return statement");
    } else {
        checkTypeCompatibility(currentFunctionReturnType, DataType::VOID, "return statement");
    }
}

void SemanticAnalyzer::analyzeBreakStatement(BreakStatement*) {
    if (loopDepth == 0) {
        throw std::runtime_error("'break' statement must be inside a loop");
    }
}

void SemanticAnalyzer::analyzeContinueStatement(ContinueStatement*) {
    if (loopDepth == 0) {
        throw std::runtime_error("'continue' statement must be inside a loop");
    }
}

void SemanticAnalyzer::analyzeAssignStatement(AssignStatement* stmt) {
    checkVariableExists(stmt->variable);
    DataType exprType = analyzeExpression(stmt->expression.get());
    checkTypeCompatibility(DataType::INT, exprType, "assignment");
}

void SemanticAnalyzer::analyzeVarDeclStatement(VarDeclStatement* stmt) {
    DataType initType = analyzeExpression(stmt->initializer.get());
    checkTypeCompatibility(DataType::INT, initType, "variable initialization");
    declareVariable(stmt->name, DataType::INT);
}

void SemanticAnalyzer::analyzeExpressionStatement(ExpressionStatement* stmt) {
    analyzeExpression(stmt->expression.get());
}

DataType SemanticAnalyzer::analyzeExpression(Expression* expr) {
    switch (expr->type) {
        case NodeType::BINARY_EXPR:
            return analyzeBinaryExpression(static_cast<BinaryExpression*>(expr));
        case NodeType::UNARY_EXPR:
            return analyzeUnaryExpression(static_cast<UnaryExpression*>(expr));
        case NodeType::LITERAL_EXPR:
            return analyzeLiteralExpression(static_cast<LiteralExpression*>(expr));
        case NodeType::VARIABLE_EXPR:
            return analyzeVariableExpression(static_cast<VariableExpression*>(expr));
        case NodeType::CALL_EXPR:
            return analyzeCallExpression(static_cast<CallExpression*>(expr));
        default:
            throw std::runtime_error("Unknown expression type");
    }
}

DataType SemanticAnalyzer::analyzeBinaryExpression(BinaryExpression* expr) {
    DataType leftType = analyzeExpression(expr->left.get());
    DataType rightType = analyzeExpression(expr->right.get());
    
    checkTypeCompatibility(DataType::INT, leftType, "binary expression left operand");
    checkTypeCompatibility(DataType::INT, rightType, "binary expression right operand");
    
    return DataType::INT;
}

DataType SemanticAnalyzer::analyzeUnaryExpression(UnaryExpression* expr) {
    DataType operandType = analyzeExpression(expr->operand.get());
    checkTypeCompatibility(DataType::INT, operandType, "unary expression operand");
    return DataType::INT;
}

DataType SemanticAnalyzer::analyzeLiteralExpression(LiteralExpression*) {
    return DataType::INT;
}

DataType SemanticAnalyzer::analyzeVariableExpression(VariableExpression* expr) {
    checkVariableExists(expr->name);
    return DataType::INT; // All variables in ToyC are int
}

DataType SemanticAnalyzer::analyzeCallExpression(CallExpression* expr) {
    checkFunctionExists(expr->functionName);
    
    const FunctionInfo& funcInfo = functions[expr->functionName];
    
    // Check argument count
    if (expr->arguments.size() != funcInfo.paramTypes.size()) {
        std::stringstream ss;
        ss << "Function '" << expr->functionName << "' expects " 
           << funcInfo.paramTypes.size() << " arguments, got " << expr->arguments.size();
        throw std::runtime_error(ss.str());
    }
    
    // Check argument types
    for (size_t i = 0; i < expr->arguments.size(); i++) {
        DataType argType = analyzeExpression(expr->arguments[i].get());
        checkTypeCompatibility(funcInfo.paramTypes[i], argType, 
                              "function call argument " + std::to_string(i + 1));
    }
    
    return funcInfo.returnType;
}