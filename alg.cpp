#include <iostream>
#include <fstream>
#include <sstream>
#include <bitset>
#include <stack>
#include <unordered_set>
#include <vector>
#include <string>
#include <stdexcept>
#include <memory>

using Rule = std::vector<std::string>;
using Group = std::unordered_set<std::string>;

enum class IPVersion { IPV4, IPV6 };

// Function prototypes
IPVersion parse_ip_version(const std::string& version);
std::ifstream open_file(const std::string& file_name);
std::vector<Rule> parse_file(std::ifstream& file, IPVersion ip_version);
Rule parse_line(const std::string& line, IPVersion ip_version);
std::string ipv4_cidr_to_binary(const std::string& cidr);
void print_rules(const std::vector<Rule>& rules, const std::string& msg);

int main(int argc, char* argv[]) {
    IPVersion version;
    try {
        if (argc != 3) {
            throw std::invalid_argument("Usage: ./program_name <input_file> <ip_version>\n"
                                        "Provide '4' for IPv4 or '6' for IPv6");
        }

        version = parse_ip_version(argv[2]);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    std::string file_name = argv[1];
    std::ifstream file = open_file(file_name);
    if (!file.is_open()) {
        return EXIT_FAILURE;
    }

    std::vector<Rule> rules = parse_file(file, version);
    print_rules(rules, "Original Rules");

    

    return EXIT_SUCCESS;
}

// Function to convert a command-line argument to IPVersion
IPVersion parse_ip_version(const std::string& version) {
    if (version == "4") {
        return IPVersion::IPV4;
    }
    else if (version == "6") {
        return IPVersion::IPV6;
    }
    else {
        throw std::invalid_argument("Invalid argument. Use '4' for IPv4 or '6' for IPv6.");
    }
}

// Function to open the file and return an ifstream
std::ifstream open_file(const std::string& file_name) {
    std::ifstream file(file_name);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << file_name << std::endl;
    }
    return file;
}

// Function to parse the file and return a vector of Rule
std::vector<Rule> parse_file(std::ifstream& file, IPVersion ip_version) {
    std::vector<Rule> rules;
    std::string line;

    while (std::getline(file, line)) {
        try {
            Rule rule = parse_line(line, ip_version);
            if (rule.size() > 0){
                rules.push_back(rule);
            }
        } catch (const std::invalid_argument& e) {
            std::cerr << "Skipping line due to error - " << e.what() << std::endl;
        }
    }

    return rules;
}

// Function to parse a single line and return a Rule object
Rule parse_line(const std::string& line, IPVersion ip_version) {
    std::size_t start = line.find('{');
    std::size_t end = line.find('}');
    if (start == std::string::npos || end == std::string::npos || start >= end) {
        throw std::invalid_argument("Invalid format in line: " + line);
    }

    std::string prefixes = line.substr(start + 1, end - start - 1);
    Rule rule;

    std::stringstream ss(prefixes);
    std::string cidr;

    if (ip_version == IPVersion::IPV4) {
        while (std::getline(ss, cidr, ',')) {
            if (cidr.size() > 0) {
                try {
                    std::string binary = ipv4_cidr_to_binary(cidr);
                    rule.push_back(binary);
                } catch (const std::invalid_argument& e) {
                    std::cerr << "Error converting prefix " << cidr << " to binary - " << e.what() << std::endl;
                }
            }
        }
    }

    else {
        std::cerr << "UNEXPECTED ERROR" << std::endl;
    }

    return rule;
}

// Function to convert an IPv4 CIDR notation string to a binary string
std::string ipv4_cidr_to_binary(const std::string& cidr) {
    std::size_t slash_delim = cidr.find('/');
    if (slash_delim == std::string::npos) {
        throw std::invalid_argument("Invalid CIDR format: " + cidr);
    }

    std::string prefix = cidr.substr(0, slash_delim);

    return prefix;

    // int length = std::stoi(cidr.substr(slash_delim + 1));

    // std::stringstream ss(prefix);
    // std::string byte;

    // std::bitset<32> bitstring;
    // int shift = 24;

    // while (std::getline(ss, byte, '.')) {
    //     bitstring |= (std::bitset<32>(std::stoi(byte)) << shift);
    //     shift -= 8;
    // }

    // return bitstring.to_string().substr(0, length);
}

// Function to print out all the rules
void print_rules(const std::vector<Rule>& rules, const std::string& msg) {
    std::cout << msg << std::endl;
    for (std::size_t i = 0; i < rules.size(); i++) {
        std::cout << "R" << i << ": ";
        for (const std::string& element : rules[i]) {
            if (element == "") {
                std::cout << '*' << " ";
            }
            else {
                std::cout << element << " ";
            }
        }
        std::cout << std::endl;
    }
}