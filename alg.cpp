#include <iostream>
#include <fstream>
#include <sstream>
#include <bitset>
#include <stack>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <queue>
#include <string>
#include <stdexcept>
#include <memory>
#include <algorithm>

using Rule = std::vector<std::string>;
using Group = std::unordered_set<std::string>;
using GroupID = std::string;

enum class IPVersion { IPV4, IPV6 };

// Regular node type used for unibit trie representations
struct Node {
    std::unique_ptr<Node> left;
    std::unique_ptr<Node> right;
    bool is_end_of_prefix;

    // Constructor
    Node() : left(nullptr), right(nullptr), is_end_of_prefix(false) {}
};

// Special node type used for GID assignment (PIS encoding)
struct PISNode {
    std::vector<std::unique_ptr<PISNode>> children;   // Arbitrary number of child nodes
    Group stored_strings;                             // Hash set of strings stored at this node
    GroupID group_id;                                 // Assigned Group ID (string)
    bool is_dummy;                                    // Flag indicating if this is a dummy node
    int suffix_cost;                                  // Suffix cost
    int infix_cost;                                   // Infix cost

    // Constructor
    PISNode() : group_id(""), is_dummy(false), suffix_cost(-1), infix_cost(-1) {}

    // Add a child node
    void add_child(std::unique_ptr<PISNode> child) {
        children.push_back(std::move(child));
    }
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

        Node* get_root() {
            return root.get();
        }

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

class PISTree {
    private:
        std::unique_ptr<PISNode> root;

    public:
        // Constructor
        PISTree() : root(std::make_unique<PISNode>()) {}

        void insert_atomic_groups(const std::vector<Group>& atomic_groups) {
            for (const auto& group : atomic_groups) {
                auto new_node = std::make_unique<PISNode>();
                for (const auto& str : group) {
                    new_node->stored_strings.insert(str);
                }
                root->add_child(std::move(new_node));
            }
        }

        void insert_overlap_groups(const std::vector<Group>& overlap_groups) {
            // Initialize a unibit trie containing all the overlapping prefixes
            std::unique_ptr<UnibitTrie> unibit_trie = std::make_unique<UnibitTrie>();
            for (const auto& group : overlap_groups) {
                for (const auto& str : group) {
                    unibit_trie->insert(str);
                }
            }

            // Perform DFS traversal to create PIS nodes for overlap_groups
            dfs_traversal(unibit_trie->get_root(), "", root.get());
        }

        // Adds one dummy node to every non-leaf, non-root node
        void add_dummies() {
            if (!root) {
                std::cout << "Empty Tree" << std::endl;
                return; // Edge case: Empty tree
            }

            std::queue<PISNode*> q;
            for (const auto& child : root->children) {
                q.push(child.get()); // Use .get() to obtain the raw pointer
            }

            while (!q.empty()) {
                PISNode* current = q.front();
                q.pop();

                // PIS node contains at least one child, add a dummy child to it
                if (!current->children.empty()) {
                    auto new_node = std::make_unique<PISNode>();
                    new_node->is_dummy = true;
                    current->add_child(std::move(new_node));
                }
                
                // Enqueue all child nodes
                for (const auto& child : current->children) {
                    if (!child->is_dummy) {
                        q.push(child.get()); // Only add non-dummy nodes to the queue
                    }
                }
            }
            return;
        }

        void print_level_order() {
            if (!root) {
                std::cout << "Empty Tree" << std::endl;
                return; // Edge case: Empty tree
            }
            
            std::queue<PISNode*> q;
            q.push(root.get());
            int level = 0;

            while (!q.empty()) {
                std::cout << "Level " << level << ":" << std::endl;
                int curr_size = q.size();

                for(int i = 0; i < curr_size; i++) {
                    PISNode* current = q.front();
                    q.pop();

                    // Print stored strings at this node
                    if (current->stored_strings.empty() && !current->is_dummy) {
                        std::cout << "Root" << std::endl;
                    }

                    else if (current->is_dummy) {
                        std::cout << "Dummy" << std::endl;
                    }

                    else {
                        std::cout << "[ ";
                        for (const std::string& str : current->stored_strings) {
                            if (str.empty()) {
                                std::cout << "* ";
                            }
                            else {
                                std::cout << str << " ";
                            }
                        }
                        std::cout << "]" << std::endl;
                    }
                    
                    // Enqueue all child nodes
                    for (const auto& child : current->children) {
                        q.push(child.get()); // Use .get() to obtain the raw pointer
                    }
                }

                level++;
            }
        }

    private:
        void dfs_traversal(Node* node, const std::string prefix, PISNode* parent) {
            if (!node) return;

            if (node->is_end_of_prefix) {
                auto new_node = std::make_unique<PISNode>();
                new_node->stored_strings.insert(prefix);
                parent->add_child(std::move(new_node));
                parent = parent->children.back().get();
            }

            if (node->left) {
                dfs_traversal(node->left.get(), prefix + "0", parent);
            }
            
            if (node->right) {
                dfs_traversal(node->right.get(), prefix + "1", parent);
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
void assign_gids(const std::vector<Group>& overlap_groups, const std::vector<Group>& atomic_groups);

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

    print_groups(overlap_groups, "Overlap Groups", "G");
    std::cout << std::endl;
    print_groups(non_overlap_groups, "Non-overlap Groups", "G");
    std::cout << std::endl;

    // From the non-overlapping groups, create the atomic groups for GID assignment
    std::vector<Group> atomic_groups = create_atomic_groups(non_overlap_groups);

    print_groups(atomic_groups, "Atomic Groups", "G");
    std::cout << std::endl;

    // Perform GID assignment
    assign_gids(overlap_groups, atomic_groups);

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

        // Make a copy of the elements to sort
        std::vector<std::string> sorted_elements = rules[i];
        // Sort by length first, then lexicographically
        std::sort(sorted_elements.begin(), sorted_elements.end(), 
            [](const std::string& a, const std::string& b) {
                if (a.length() != b.length()) {
                    return a.length() < b.length(); // Sort by length
                }
                return a < b; // Sort alphabetically if lengths are equal
            });

        for (const std::string& element : sorted_elements) {
            if (element.empty()) {
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

        // Make a copy of the elements to sort
        std::vector<std::string> sorted_elements(groups[i].begin(), groups[i].end());
        // Sort by length first, then lexicographically
        std::sort(sorted_elements.begin(), sorted_elements.end(), 
            [](const std::string& a, const std::string& b) {
                if (a.length() != b.length()) {
                    return a.length() < b.length(); // Sort by length
                }
                return a < b; // Sort alphabetically if lengths are equal
            });

        for (const std::string& element : sorted_elements) {
            if (element.empty()) {
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

    // Sort the overlap_groups by decreasing length (reflect eventual TCAM ordering)
    std::sort(overlap_groups.begin(), overlap_groups.end(), 
        [](const Group& a, const Group& b) {
            // Extract the only element from each group
            const std::string& str_a = *a.begin();
            const std::string& str_b = *b.begin();
            return str_a.length() > str_b.length(); // Sort by decreasing length
        });
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

void assign_gids(const std::vector<Group>& overlap_groups, const std::vector<Group>& atomic_groups) {
    // Initialize an empty PIS tree
    std::unique_ptr<PISTree> pis_tree = std::make_unique<PISTree>();
    pis_tree->insert_atomic_groups(atomic_groups);
    pis_tree->insert_overlap_groups(overlap_groups);
    
    // Now create all the dummy nodes
    pis_tree->add_dummies();

    // Now begin to assign infix/suffix costs
    

    pis_tree->print_level_order(); // Sanity check
}