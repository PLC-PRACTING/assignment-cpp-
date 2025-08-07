#include "lexer.h"
#include "parser.h"
#include "semantic.h"
#include "codegen.h"
#include <iostream>
#include <fstream>
#include <stdexcept>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <input.tc> <output.s>" << std::endl;
        return 1;
    }
    
    std::string inputFile = argv[1];
    std::string outputFile = argv[2];
    
    try {
        // Read input file
        std::ifstream file(inputFile);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open input file: " + inputFile);
        }
        
        std::string source((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());
        file.close();
        
        // Lexical analysis
        Lexer lexer(source);
        std::vector<Token> tokens = lexer.tokenize();
        
        // Syntax analysis
        Parser parser(std::move(tokens));
        std::unique_ptr<Program> ast = parser.parse();
        
        // Semantic analysis
        SemanticAnalyzer analyzer;
        analyzer.analyze(ast.get());
        
        // Code generation
        CodeGenerator generator;
        std::string assembly = generator.generate(ast.get());
        
        // Write output file
        std::ofstream outFile(outputFile);
        if (!outFile.is_open()) {
            throw std::runtime_error("Cannot create output file: " + outputFile);
        }
        
        outFile << assembly;
        outFile.close();
        
        std::cout << "Compilation successful: " << inputFile << " -> " << outputFile << std::endl;
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}