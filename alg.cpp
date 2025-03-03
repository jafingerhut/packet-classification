#include <iostream>
#include <fstream>
#include <sstream>
#include <bitset>
#include <stack>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <string>
#include <stdexcept>
#include <memory>

using Rule = std::vector<std::string>;
using Group = std::unordered_set<std::string>;

enum class IPVersion { IPV4, IPV6 };

struct Node {
    std::unique_ptr<Node> left;
    std::unique_ptr<Node> right;
    bool is_end_of_prefix;

    // Constructor
    Node() : left(nullptr), right(nullptr), is_end_of_prefix(false) {}
};

class OptimizationTrie {
    private:
        std::unique_ptr<Node> root;
    
    public:
        // Constructor
        OptimizationTrie() : root(std::make_unique<Node>()) {}
    
        // Insert a binary string into the trie whilst performing compression optimizations
        void insert(const std::string& prefix) {
            std::stack<Node*> visited;
            Node* current = root.get();
    
            // Optimization 1: First check if the root node has a prefix
            if (current->is_end_of_prefix) {
                return;
            }
    
            for (char bit : prefix) {
                visited.push(current);
    
                if (bit == '0') {
                    if (!current->left) {
                        current->left = std::make_unique<Node>();
                    }
                    current = current->left.get();
                }
    
                else if (bit == '1') {
                    if (!current->right) {
                        current->right = std::make_unique<Node>();
                    }
                    current = current->right.get();
                }
    
                else {
                    std::cerr << "Encountered an invalid bit" << std::endl;
                    return;
                }
    
                // Optimization 1: If we encounter a node that has a prefix, end insertion
                if (current->is_end_of_prefix) {
                    return;
                }
            }
    
            // Optimization 1: If we stop at a node that has children, delete the node's children
            if (current->left || current->right) {
                current->left.reset();
                current->right.reset();
            }
    
            current->is_end_of_prefix = true;
    
            // Optimization 2: In reverse order, perform prefix aggregation if possible
            while (!visited.empty()) {
                Node* parent = visited.top();
                visited.pop();
    
                if (parent->left && parent->right) {
                    if (parent->left->is_end_of_prefix && parent->right->is_end_of_prefix) {
                        parent->is_end_of_prefix = true;
                        parent->left.reset();
                        parent->right.reset();
                    }
                }
    
                else {
                    break;
                }
            }
        }
    
        // Traverse the trie and return a rule containing all its prefixes
        Rule traverse() const {
            Rule result;
            dfs_traversal(root.get(), result, "");
            return result;
        }
    
    private:
        // Helper function to perform DFS traversal
        void dfs_traversal(Node* node, Rule& result, std::string prefix) const {
            if (!node) return;
    
            if (node->is_end_of_prefix) {
                result.push_back(prefix);
            }
    
            dfs_traversal(node->left.get(), result, prefix + '0');
            dfs_traversal(node->right.get(), result, prefix + '1');
        }
};

class UnibitTrie {
    private:
        std::unique_ptr<Node> root;

    public:
        // Constructor
        UnibitTrie() : root(std::make_unique<Node>()) {}

        // Insert a binary string into the unibit trie
        void insert(const std::string& prefix) {
            Node* current = root.get();
    
            for (char bit : prefix) {
                if (bit == '0') {
                    if (!current->left) {
                        current->left = std::make_unique<Node>();
                    }
                    current = current->left.get();
                }
    
                else if (bit == '1') {
                    if (!current->right) {
                        current->right = std::make_unique<Node>();
                    }
                    current = current->right.get();
                }
    
                else {
                    std::cerr << "Encountered an invalid bit" << std::endl;
                    return;
                }
            }
    
            current->is_end_of_prefix = true;
        }

        bool find_overlap(const std::string& prefix) const {
            Node* current = root.get();
            size_t len = prefix.size();
            size_t index = 0;

            if (current->is_end_of_prefix) {
                return true;
            }
            
            for (char bit : prefix) {
                if (bit == '0') {
                    if (!current->left) {
                        std::cerr << "Unexpected behavior: did not find pre-existing path in unibit trie" << std::endl;
                    }
                    current = current->left.get();
                }
    
                else if (bit == '1') {
                    if (!current->right) {
                        std::cerr << "Unexpected behavior: did not find pre-existing path in unibit trie" << std::endl;
                    }
                    current = current->right.get();
                }
    
                else {
                    std::cerr << "Encountered an invalid bit" << std::endl;
                }
    
                // If we reach an end of prefix before the last character, it means there exists overlap
                if (current->is_end_of_prefix && index < len-1) {
                    return true;
                }

                index += 1;
            }

            // If we stop at a node that has children, then there exists overlap
            if (current->left || current->right) {
                return true;
            }
            else{
                return false;
            }
        }
};

// Function prototypes
IPVersion parse_ip_version(const std::string& version);
std::ifstream open_file(const std::string& file_name);
std::vector<Rule> parse_file(std::ifstream& file, IPVersion ip_version);
Rule parse_line(const std::string& line, IPVersion ip_version);
std::string ipv4_cidr_to_binary(const std::string& cidr);
std::vector<std::unique_ptr<OptimizationTrie>> build_optimization_tries(const std::vector<std::vector<std::string>>& rules);
void print_rules(const std::vector<Rule>& rules, const std::string& msg);
void print_groups(const std::vector<Group>& groups, const std::string& msg, const std::string& label);
std::vector<Rule> optimize_rules(const std::vector<Rule>& original_rules);
std::pair<std::vector<Group>, std::vector<Group>> create_overlap_groups(const std::vector<Rule>& compressed_rules);
std::vector<Group> create_atomic_groups(const std::vector<Group>& non_overlap_groups);

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

    // Read the raw rules
    std::vector<Rule> original_rules = parse_file(file, version);

    // Optimize the rules by performing aggregation and compression
    std::vector<Rule> compressed_rules = optimize_rules(original_rules);

    print_rules(original_rules, "Original Rules");
    std::cout << std::endl;
    print_rules(compressed_rules, "Optimized Rules");
    std::cout << std::endl;
    original_rules.clear();
    original_rules.shrink_to_fit();

    // Create initial overlapping and non-overlapping groups (goal is to separate overlapping entries)
    auto [overlap_groups, non_overlap_groups] = create_overlap_groups(compressed_rules);

    print_groups(non_overlap_groups, "Non-overlap Groups", "G");
    std::cout << std::endl;
    print_groups(overlap_groups, "Overlap Groups", "G");
    std::cout << std::endl;

    // From the non-overlapping groups, create the atomic groups for GID assignment
    std::vector<Group> atomic_groups = create_atomic_groups(non_overlap_groups);

    print_groups(atomic_groups, "Atomic Groups", "G");
    std::cout << std::endl;

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
    int length = std::stoi(cidr.substr(slash_delim + 1));
    std::stringstream ss(prefix);
    std::string byte;
    std::bitset<32> bitstring;
    int shift = 24;

    while (std::getline(ss, byte, '.')) {
        bitstring |= (std::bitset<32>(std::stoi(byte)) << shift);
        shift -= 8;
    }

    return bitstring.to_string().substr(0, length);
}

// Function to build tries for each rule read
std::vector<std::unique_ptr<OptimizationTrie>> build_optimization_tries(const std::vector<Rule>& rules) {
    std::vector<std::unique_ptr<OptimizationTrie>> tries;

    for (const auto& rule : rules) {
        std::unique_ptr<OptimizationTrie> trie = std::make_unique<OptimizationTrie>();
        for (const auto& prefix : rule) {
            trie->insert(prefix);
        }
        tries.push_back(std::move(trie)); // Store the trie in the list
    }

    return tries;
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

// Function to print out all the groups
void print_groups(const std::vector<Group>& groups, const std::string& msg, const std::string& label) {
    std::cout << msg << std::endl;
    for (std::size_t i = 0; i < groups.size(); i++) {
        std::cout << label << i << ": ";
        for (const std::string& element : groups[i]) {
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

std::vector<Rule> optimize_rules(const std::vector<Rule>& original_rules) {
    // For each raw rule, build an optimization trie to perform prefix aggregation and compression
    // Traverse each optimization trie and compile all the compressed rules back together
    std::vector<Rule> compressed_rules;

    auto optimization_tries = build_optimization_tries(original_rules);
    for (std::size_t i = 0; i < optimization_tries.size(); i++) {
        Rule prefixes = optimization_tries[i]->traverse();
        compressed_rules.push_back(prefixes);
    }

    return compressed_rules;
}

std::pair<std::vector<Group>, std::vector<Group>> create_overlap_groups(const std::vector<Rule>& compressed_rules) {
    // Initialize a unibit trie containing all the prefixes for a given field
    std::unique_ptr<UnibitTrie> unibit_trie = std::make_unique<UnibitTrie>();
    for (const auto& rule : compressed_rules) {
        for (const auto& str : rule) {
            unibit_trie->insert(str);
        }
    }

    // Now using the compressed rules and the unibit trie, create two sets of groups
    // 1. Brand new groups created to hold overlapping entries (overlap_groups)
    // 2. Groups containing leftover entries from the compressed rules (non_overlap_groups)
    std::vector<Group> overlap_groups;
    std::vector<Group> non_overlap_groups;
    for (const auto& rule : compressed_rules) {
        Group non_overlap_group;
        for (const auto& str : rule) {
            bool exists_overlap = unibit_trie->find_overlap(str);
            if (exists_overlap) {
                // if there exists overlap, first check if the prefix does not already exist in any of the new hash sets
                bool prefix_found = false;
                for (const auto& group : overlap_groups) {
                    if (group.find(str) != group.end()) {
                        prefix_found = true;
                        break;
                    }
                }
                if (!prefix_found) {
                    Group overlap_group = {str};
                    overlap_groups.push_back(overlap_group);
                }
            }
            else {
                non_overlap_group.insert(str);
            }
        }
        if (non_overlap_group.size() != 0){
            non_overlap_groups.push_back(non_overlap_group);
        }
    }

    return {overlap_groups, non_overlap_groups};
}

std::vector<Group> create_atomic_groups(const std::vector<Group>& non_overlap_groups) {
    // Now we need to form the atomic units for the non_overlap_groups (not for overlap_groups because they are size 1)
    // Store new atomic groups in atomic_groups, use atomic_map to map prefix ==> index of its atomic group in the vector (performance optimization)
    std::vector<Group> atomic_groups;
    std::unordered_map<std::string, int> atomic_map;

    int atomic_index = 0;
    for (const auto& non_overlap_group : non_overlap_groups) {
        Group atomic_group;
        std::unordered_set<int> matched_indices;
        // for a given non_overlap_group, assemble list of matching indices (union of atomic groups to check)
        for (const auto& str : non_overlap_group) {
            if (atomic_map.find(str) != atomic_map.end()) {
                matched_indices.insert(atomic_map[str]); // if found in pre-existing atomic group, append index (hash set for unique)
            }
            else {
                atomic_map[str] = atomic_index; // if not found in pre-existing atomic group, add to new atomic group
                atomic_group.insert(str);
            }
        }

        // if new atomic group created, add to list of atomic groups
        if (atomic_group.size() > 0) {
            atomic_groups.push_back(atomic_group);
            atomic_index++;
        }

        for (int curr : matched_indices) { // for each matched atomic group, see if it is necessary to splinter/branch off new sub-group
            Group atomic_splinter;
            std::vector<std::string> to_remove;
            for (const auto& str : atomic_groups[curr]) {
                // for each prefix in the union of matched atomic groups, if it doesn't exist in the non_overlap_group, splinter the atomic group
                if (non_overlap_group.find(str) == non_overlap_group.end()) {
                    // if entry in atomic group is not found in non_overlap_group, it means we need to split atomic group into subsets
                    atomic_map[str] = atomic_index;
                    atomic_splinter.insert(str);
                    to_remove.push_back(str);
                }
            }

            if (atomic_splinter.size() > 0) {
                atomic_groups.push_back(atomic_splinter);
                atomic_index++;
                for (const auto& str : to_remove) {
                    atomic_groups[curr].erase(str); // if adding prefix to new atomic group, remove trace of it from old atomic group
                }
            }

            // sanity check
            if (atomic_groups[curr].size() == 0) {
                std::cerr << "Error: all the entries were removed from an atomic group" << std::endl;
                return {};
            }
        }
    }

    return atomic_groups;
}