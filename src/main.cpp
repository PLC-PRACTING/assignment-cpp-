#include "codegen.h"
#include "lexer.h"
#include "parser.h"
#include "semantic.h"
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <stdexcept>

int main(int argc, char *argv[])
{
    bool optimization_enabled = false;

    // Check for -opt parameter
    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];
        if (arg == "-opt")
        {
            optimization_enabled = true;
        }
    }

    try
    {
        // Read from stdin
        std::stringstream buffer;
        buffer << std::cin.rdbuf();
        std::string source = buffer.str();

        if (source.empty())
        {
            throw std::runtime_error("No input provided");
        }

        // Lexical analysis
        Lexer lexer(source);
        std::vector<Token> tokens = lexer.tokenize();

        // Optional debug: dump tokens when TOYC_DUMP_TOKENS=1
        if (const char *dump = std::getenv("TOYC_DUMP_TOKENS"))
        {
            if (std::string(dump) == "1")
            {
                for (const auto &tk : tokens)
                {
                    std::cerr << TokenUtils::tokenTypeToString(tk.type) << "(\"" << tk.value
                              << "\")@" << tk.line << ":" << tk.column << "\n";
                }
            }
        }

        // Syntax analysis
        Parser parser(std::move(tokens));
        std::unique_ptr<Program> ast = parser.parse();

        // Semantic analysis
        SemanticAnalyzer analyzer;
        analyzer.analyze(ast.get());

        // Code generation
        CodeGenerator generator;
        generator.setOptimizationEnabled(optimization_enabled);
        std::string assembly = generator.generate(ast.get());

        // Write to stdout
        std::cout << assembly;

        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}