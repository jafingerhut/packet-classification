#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <cstdlib>
#include <cmath>
#include <string>

// Function to generate a random IPv4 prefix in CIDR notation
std::string gen_ipv4_prefix() {
    int a = rand() % 256;
    int b = rand() % 256;
    int c = rand() % 256;
    int d = rand() % 256;
    int prefix = std::floor(std::sqrt(rand() % 1024)) + 1; // range from 1-32 (skewed)
    
    std::stringstream ss;
    ss << a << "." << b << "." << c << "." << d << "/" << prefix;
    return ss.str();
}

// Function to generate a random IPv6 prefix in CIDR notation
std::string gen_ipv6_prefix() {
    // TODO
    return "";
}

// Function to generate a random vector of CIDR prefixes
std::vector<std::string> gen_prefix_group(int vers) {
    int group_size = 1 + (rand() % 20); // Random number of prefixes for this group (1-20)
    std::vector<std::string> group;
    while (group.size() < group_size) {
        if (vers == 4) {
            group.push_back(gen_ipv4_prefix());
        }
        else {
            group.push_back(gen_ipv6_prefix());
        }
    }
    return group;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <4 for IPv4 | 6 for IPv6> <number of rules>" << std::endl;
        return EXIT_FAILURE;
    }
    
    int vers = atoi(argv[1]);
    int n = atoi(argv[2]);

    if (vers != 4 && vers != 6) {
        std::cerr << "Must enter either 4 or 6 for the IP version." << std::endl;
        return EXIT_FAILURE;
    }
    
    if (vers == 6) {
        std::cerr << "IPv6 generation is not yet implemented." << std::endl;
        return EXIT_FAILURE;
    }
    
    std::srand(time(0)); // Seed random number generator
    
    std::ofstream outFile("generated_prefixes.txt");
    if (!outFile) {
        std::cerr << "Error: Could not open output file." << std::endl;
        return EXIT_FAILURE;
    }
    
    for (int i = 0; i < n; ++i) {
        std::vector<std::string> group = gen_prefix_group(vers);
        outFile << "{";
        bool first = true;
        for (const std::string& prefix : group) {
            if (!first) {
                outFile << ",";
            }
            outFile << prefix;
            first = false;
        }
        outFile << "}" << std::endl;
    }
    
    outFile.close();
    std::cout << "Generated " << n << " lines of random prefixes in 'generated_prefixes.txt'." << std::endl;
    
    return EXIT_SUCCESS;
}
