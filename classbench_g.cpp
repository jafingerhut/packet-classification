#include <iostream>
#include <fstream>
#include <sstream>
#include <bitset>
#include <stack>
#include <unordered_map>
#include <vector>
#include <string>
#include <stdexcept>
#include <memory>

using Group = std::vector<std::string>;

enum class IPVersion { IPV4, IPV6 };

enum class SetType { EQUAL, PROPER_SUBSET, DISJOINT, INTERSECTING };

struct Node {
    std::unique_ptr<Node> left;
    std::unique_ptr<Node> right;
    bool is_end_of_prefix;
    std::string stored_prefix;

    // Constructor
    Node() : left(nullptr), right(nullptr), is_end_of_prefix(false), stored_prefix("") {}
};

class Trie {
private:
    std::unique_ptr<Node> root;

public:
    // Constructor
    Trie() : root(std::make_unique<Node>()) {}

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
        current->stored_prefix = prefix;

        // Optimization 2: In reverse order, perform prefix aggregation if possible
        while (!visited.empty()) {
            Node* parent = visited.top();
            visited.pop();

            if (parent->left && parent->right) {
                if (parent->left->is_end_of_prefix && parent->right->is_end_of_prefix) {
                    // Sanity check
                    std::string left_prefix = parent->left->stored_prefix.substr(0, parent->left->stored_prefix.size() - 1);
                    std::string right_prefix = parent->right->stored_prefix.substr(0, parent->right->stored_prefix.size() - 1);
                    if (left_prefix != right_prefix) {
                        std::cerr << "Left prefix does not match right prefix" << std::endl;
                        return;
                    }

                    parent->is_end_of_prefix = true;
                    parent->stored_prefix = left_prefix;
                    parent->left.reset();
                    parent->right.reset();
                }
            }

            else {
                break;
            }
        }
    }

    // Search for a binary string in the trie and update the corresponding flags
    void search(const std::string& prefix, bool& exists_overlap, bool& unique_found) const {
        Node* current = root.get();

        if (current->is_end_of_prefix) {
            exists_overlap = true;
            return;
        }

        for (char bit : prefix) {
            if (bit == '0') {
                if (!current->left) {
                    unique_found = true;
                    return;
                }
                current = current->left.get();
            }

            else if (bit == '1') {
                if (!current->right) {
                    unique_found = true;
                    return;
                }
                current = current->right.get();
            }

            else {
                std::cerr << "Encountered an invalid bit" << std::endl;
                return;
            }

            if (current->is_end_of_prefix) {
                exists_overlap = true;
                return;
            }
        }

        if (current->left || current->right) {
            exists_overlap = true;
            unique_found = true;
        }
    }

    // Traverse the trie and return a group containing all its prefixes
    Group traverse() const {
        Group result;
        dfs_traversal(root.get(), result);
        return result;
    }

private:
    // Helper function to perform DFS traversal
    void dfs_traversal(Node* node, Group& result) const {
        if (!node) return;

        if (node->is_end_of_prefix) {
            result.push_back(node->stored_prefix);
        }

        dfs_traversal(node->left.get(), result);
        dfs_traversal(node->right.get(), result);
    }
};

// Function prototypes
IPVersion parse_ip_version(const std::string& arg);
std::ifstream open_file(const std::string& file_name);
std::vector<Group> parse_file(std::ifstream& file, IPVersion ip_version);
Group parse_line(const std::string& line, IPVersion ip_version);
std::string ipv4_cidr_to_binary(const std::string& cidr);
std::vector<std::unique_ptr<Trie>> build_tries(const std::vector<std::vector<std::string>>& groups);
void generate_stats(const std::vector<std::unique_ptr<Trie>>& tries, const std::vector<Group>& compressed_groups);
std::string set_type_to_str(SetType type);
void print_groups(const std::vector<Group>& groups, const std::string& msg);
long long n_choose_2(long long n);

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

    std::vector<Group> raw_groups = parse_file(file, version);

    auto tries = build_tries(raw_groups);

    std::vector<Group> compressed_groups;

    for (std::size_t i = 0; i < tries.size(); i++) {
        Group prefixes = tries[i]->traverse();
        compressed_groups.push_back(prefixes);
    }

    print_groups(raw_groups, "Raw Groups");
    std::cout << std::endl;
    print_groups(compressed_groups, "Compressed Groups");
    std::cout << std::endl;

    generate_stats(tries, compressed_groups);

    return EXIT_SUCCESS;
}

// Function to convert a command-line argument to IPVersion
IPVersion parse_ip_version(const std::string& arg) {
    if (arg == "4") {
        return IPVersion::IPV4;
    }
    else if (arg == "6") {
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

// Function to parse the file and return a vector of Group
std::vector<Group> parse_file(std::ifstream& file, IPVersion ip_version) {
    std::vector<Group> groups;
    std::string line;

    while (std::getline(file, line)) {
        try {
            Group new_group = parse_line(line, ip_version);
            if (new_group.size() > 0){
                groups.push_back(new_group);
            }
        } catch (const std::invalid_argument& e) {
            std::cerr << "Skipping line due to error - " << e.what() << std::endl;
        }
    }

    return groups;
}

// Function to parse a single line and return a Group object
Group parse_line(const std::string& line, IPVersion ip_version) {
    std::size_t start = line.find('{');
    std::size_t end = line.find('}');
    if (start == std::string::npos || end == std::string::npos || start >= end) {
        throw std::invalid_argument("Invalid format in line: " + line);
    }

    std::string prefixes = line.substr(start + 1, end - start - 1);
    Group new_group;

    std::stringstream ss(prefixes);
    std::string cidr;

    if (ip_version == IPVersion::IPV4) {
        while (std::getline(ss, cidr, ',')) {
            if (cidr.size() > 0) {
                try {
                    std::string binary = ipv4_cidr_to_binary(cidr);
                    new_group.push_back(binary);
                } catch (const std::invalid_argument& e) {
                    std::cerr << "Error converting prefix " << cidr << " to binary - " << e.what() << std::endl;
                }
            }
        }
    }

    else {
        std::cerr << "UNEXPECTED ERROR" << std::endl;
    }

    return new_group;
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

// Function to build tries for each group of prefixes
std::vector<std::unique_ptr<Trie>> build_tries(const std::vector<Group>& groups) {
    std::vector<std::unique_ptr<Trie>> tries;

    for (const auto& group : groups) {
        std::unique_ptr<Trie> trie = std::make_unique<Trie>();
        for (const auto& prefix : group) {
            trie->insert(prefix);
        }
        tries.push_back(std::move(trie)); // Store the trie in the list
    }

    return tries;
}

// Function to generate the set type statistics across all groups
void generate_stats(
    const std::vector<std::unique_ptr<Trie>>& tries,
    const std::vector<Group>& compressed_groups
) {
    std::unordered_map<SetType, int> counters = {
        {SetType::EQUAL, 0},
        {SetType::PROPER_SUBSET, 0},
        {SetType::DISJOINT, 0},
        {SetType::INTERSECTING, 0}
    };

    for (int i = 0; i < compressed_groups.size(); i++) {
        for (int j = i + 1; j < compressed_groups.size(); j++) {
            bool exists_overlap = false, unique_in_i = false, unique_in_j = false;

            for (const auto& prefix : compressed_groups[j]) {
                tries[i]->search(prefix, exists_overlap, unique_in_j);
            }

            for (const auto& prefix : compressed_groups[i]) {
                tries[j]->search(prefix, exists_overlap, unique_in_i);
            }

            // Check combinations of flags to determine which counter to increment
            if (exists_overlap && !unique_in_i && !unique_in_j) {
                counters[SetType::EQUAL]++;
            }
            else if (exists_overlap && unique_in_i && unique_in_j) {
                counters[SetType::INTERSECTING]++;
            }
            else if (!exists_overlap && unique_in_i && unique_in_j) {
                counters[SetType::DISJOINT]++;
            }
            else if (exists_overlap && ( unique_in_i || unique_in_j )) {
                counters[SetType::PROPER_SUBSET]++;
            }
            else {
                std::cerr << "Error: encountered an unknown combination of statistic flags" << std::endl;
            }
        }
    }

    size_t sum = 0;
    for (const auto& [key, value] : counters) {
        std::cout << set_type_to_str(key) << ": " << value << '\n';
        sum += value;
    }

    if (sum != n_choose_2(compressed_groups.size())) {
        std::cerr << "Error: failed n choose 2 sanity check" << std::endl;
    }
}

// Function to convert SetType to a string
std::string set_type_to_str(SetType type) {
    switch (type) {
        case SetType::EQUAL: return "EQUAL";
        case SetType::PROPER_SUBSET: return "PROPER_SUBSET";
        case SetType::DISJOINT: return "DISJOINT";
        case SetType::INTERSECTING: return "INTERSECTING";
        default: return "UNKNOWN";
    }
}

// Function to print out all the groups
void print_groups(const std::vector<Group>& groups, const std::string& msg) {
    std::cout << msg << std::endl;
    for (std::size_t i = 0; i < groups.size(); i++) {
        std::cout << "G" << i << ": ";
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

// Function to calculate n choose 2
long long n_choose_2(long long n) {
    if (n < 2) {
        return 0;
    }
    return n * (n - 1) / 2;
}