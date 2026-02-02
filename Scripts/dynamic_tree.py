#!/usr/bin/env python3
"""
ISE Dynamic Decision Tree Generator

This script dynamically discovers ALL attributes used in ISE authorization policies
and generates separate decision trees for each policy set.

Key Features:
- Dynamic attribute discovery (no hardcoding)
- Per-policy-set analysis
- Flexible hierarchy based on attribute frequency
- Handles complex conditions (AND/OR blocks, nested)

Output: dynamic_decision_tree.json
"""

import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional, Set, Tuple


# ============================================================================
# HIERARCHY CONFIGURATION
# ============================================================================
# Define custom hierarchy order for each policy set
# - Keys: Policy set names (exact match), or '*' for default (applies to all)
# - Values: List of attribute names in desired order, or None for automatic
#
# Set to None or empty dict to use ONLY attributes present in each rule
# (no forcing rules through a fixed hierarchy with "Not Specified" values)
# ============================================================================

# DISABLED: Let each rule show only its own attributes
CUSTOM_HIERARCHY = {}


class DynamicISETreeGenerator:
    """Generates dynamic decision tree analysis from ISE authorization policies"""

    def __init__(self, input_file: Path, output_file: Path):
        self.input_file = input_file
        self.output_file = output_file
        self.all_attributes = Counter()  # attribute_name -> count
        self.attribute_values = defaultdict(set)  # attribute_name -> set of values
        self.policy_set_data = {}  # policy_set_name -> data

    def load_data(self) -> Dict:
        """Load the processed ISE data"""
        print(f"Loading data from {self.input_file}...")
        with open(self.input_file, 'r') as f:
            return json.load(f)

    def extract_attributes_from_condition(self, condition: Dict, attributes: Set[Tuple[str, str]]) -> None:
        """
        Recursively extract all attributes from a condition tree

        Args:
            condition: The condition object to parse
            attributes: Set to store (dictionary_name, attribute_name, operator, value) tuples
        """
        if not condition:
            return

        condition_type = condition.get('conditionType')

        # Handle ConditionAttributes - leaf node with actual attribute
        if condition_type == 'ConditionAttributes':
            dict_name = condition.get('dictionaryName', '')
            attr_name = condition.get('attributeName', '')
            operator = condition.get('operator', 'equals')
            attr_value = condition.get('attributeValue', '')

            if dict_name and attr_name:
                full_attr_name = f"{dict_name}.{attr_name}"
                attributes.add((full_attr_name, operator, attr_value))

        # Handle ConditionAndBlock - recursive AND of children
        elif condition_type == 'ConditionAndBlock':
            children = condition.get('children', [])
            for child in children:
                self.extract_attributes_from_condition(child, attributes)

        # Handle ConditionOrBlock - recursive OR of children
        elif condition_type == 'ConditionOrBlock':
            children = condition.get('children', [])
            for child in children:
                self.extract_attributes_from_condition(child, attributes)

        # Handle LibraryConditionAttributes - similar to ConditionAttributes
        elif condition_type == 'LibraryConditionAttributes':
            dict_name = condition.get('dictionaryName', '')
            attr_name = condition.get('attributeName', '')
            operator = condition.get('operator', 'equals')
            attr_value = condition.get('attributeValue', '')

            if dict_name and attr_name:
                full_attr_name = f"{dict_name}.{attr_name}"
                attributes.add((full_attr_name, operator, attr_value))

        # Handle ConditionReference - may need to follow link
        elif condition_type == 'ConditionReference':
            # For now, we'll note it exists but can't follow the reference
            # In a real implementation, you'd fetch the referenced condition
            pass

    def discover_attributes(self, data: Dict):
        """
        Discover all attributes used across all authorization policies
        """
        print("Discovering attributes from authorization policies...")

        for policy_set in data.get('policy_sets', []):
            policy_set_name = policy_set.get('name', 'Unknown')

            # Initialize policy set data structure
            if policy_set_name not in self.policy_set_data:
                self.policy_set_data[policy_set_name] = {
                    'rules': [],
                    'attributes': Counter(),
                    'attribute_values': defaultdict(set)
                }

            for auth_policy in policy_set.get('authorization_policies', []):
                rule = auth_policy.get('rule', {})
                condition = rule.get('condition')

                # Extract attributes from this rule's conditions
                rule_attributes = set()
                self.extract_attributes_from_condition(condition, rule_attributes)

                # Build rule info
                rule_info = {
                    'rule_id': rule.get('id'),
                    'rule_name': rule.get('name'),
                    'rank': rule.get('rank'),
                    'state': rule.get('state'),
                    'default': rule.get('default', False),
                    'profile': auth_policy.get('profile', []),
                    'profile_str': ', '.join(auth_policy.get('profile', [])),
                    'security_group': auth_policy.get('securityGroup'),
                    'condition': condition,
                    'attributes': {}  # Will store {attr_name: value}
                }

                # Process discovered attributes
                # Group attributes by name to handle OR conditions (same attribute multiple times)
                attr_groups = defaultdict(list)
                for attr_name, operator, attr_value in rule_attributes:
                    attr_groups[attr_name].append((operator, attr_value))

                    # Track globally
                    self.all_attributes[attr_name] += 1
                    if attr_value:
                        self.attribute_values[attr_name].add(attr_value)

                    # Track per policy set
                    self.policy_set_data[policy_set_name]['attributes'][attr_name] += 1
                    if attr_value:
                        self.policy_set_data[policy_set_name]['attribute_values'][attr_name].add(attr_value)

                # Store in rule info - combine OR values together
                for attr_name, values_list in attr_groups.items():
                    if len(values_list) == 1:
                        # Single value - store as-is
                        operator, attr_value = values_list[0]
                        rule_info['attributes'][attr_name] = attr_value
                    else:
                        # Multiple values (OR condition) - combine them
                        or_parts = []
                        for operator, attr_value in values_list:
                            # Include operator if not 'equals'
                            if operator == 'equals':
                                or_parts.append(attr_value)
                            else:
                                or_parts.append(f"{operator} {attr_value}")
                        rule_info['attributes'][attr_name] = " OR ".join(or_parts)

                # Add rule to policy set
                self.policy_set_data[policy_set_name]['rules'].append(rule_info)

        # Sort rules by rank within each policy set
        for policy_set_name in self.policy_set_data:
            self.policy_set_data[policy_set_name]['rules'].sort(
                key=lambda x: (x['rank'] if x['rank'] is not None else float('inf'), x['rule_name'])
            )

        print(f"  Discovered {len(self.all_attributes)} unique attributes")
        print(f"  Analyzed {len(self.policy_set_data)} policy sets")

    def format_condition_for_display(self, condition: Dict, indent: int = 0) -> str:
        """Format a condition object for human-readable display"""
        if not condition:
            return "No conditions"

        condition_type = condition.get('conditionType')
        prefix = "  " * indent

        if condition_type == 'ConditionAndBlock':
            children = condition.get('children', [])
            parts = []
            for child in children:
                parts.append(self.format_condition_for_display(child, indent))
            return " AND ".join(parts)

        elif condition_type == 'ConditionOrBlock':
            children = condition.get('children', [])
            parts = []
            for child in children:
                parts.append(self.format_condition_for_display(child, indent))
            return "(" + " OR ".join(parts) + ")"

        elif condition_type in ['ConditionAttributes', 'LibraryConditionAttributes']:
            dict_name = condition.get('dictionaryName', '')
            attr_name = condition.get('attributeName', '')
            operator = condition.get('operator', 'equals')
            attr_value = condition.get('attributeValue', '')
            is_negate = condition.get('isNegate', False)
            negate_str = "NOT " if is_negate else ""
            return f"{negate_str}{dict_name}.{attr_name} {operator} {attr_value}"

        elif condition_type == 'ConditionReference':
            name = condition.get('name', 'Unknown')
            return f"[Reference: {name}]"

        return "Complex condition"

    def build_tree_for_policy_set(self, policy_set_name: str, hierarchy: List[str]) -> Dict:
        """
        Build hierarchical tree structure for a specific policy set
        Only includes attributes that actually exist in each rule (no "Not Specified")

        Args:
            policy_set_name: Name of the policy set
            hierarchy: List of attribute names in order (for sorting/organization)

        Returns:
            Nested dictionary representing the tree with attribute names at each level
            Format: {attr_name: {value: {next_attr_name: {value: ...}}}}
        """
        print(f"  Building tree for {policy_set_name} with hierarchy: {hierarchy}")

        rules = self.policy_set_data[policy_set_name]['rules']

        # Build tree recursively with attribute names at each level
        tree = {}

        for rule in rules:
            # Get only the attributes that actually exist in this rule
            rule_attrs = rule['attributes']
            if not rule_attrs:
                # Rule has no attributes - add directly as a result
                if '_no_attrs_' not in tree:
                    tree['_no_attrs_'] = {}
                if 'default' not in tree['_no_attrs_']:
                    tree['_no_attrs_']['default'] = []
                tree['_no_attrs_']['default'].append({
                    'result': rule['profile_str'],
                    'rule_rank': rule['rank'],
                    'rule_name': rule['rule_name'],
                    'rule_id': rule['rule_id'],
                    'state': rule['state'],
                    'attributes': rule['attributes']
                })
                continue

            # Sort this rule's attributes by the hierarchy order (for consistency)
            sorted_attrs = []
            for h_attr in hierarchy:
                if h_attr in rule_attrs:
                    sorted_attrs.append(h_attr)
            # Add any remaining attributes not in hierarchy
            for attr in rule_attrs.keys():
                if attr not in sorted_attrs:
                    sorted_attrs.append(attr)

            # Build tree path for this rule using only its attributes
            current = tree
            for level_idx, attr_name in enumerate(sorted_attrs):
                value = rule_attrs[attr_name]

                # Ensure attribute name exists as key at this level
                if attr_name not in current:
                    current[attr_name] = {}

                # Navigate into attribute
                attr_dict = current[attr_name]

                if level_idx == len(sorted_attrs) - 1:
                    # Leaf level - store results under the value
                    # Check if value exists and what type it is
                    if value not in attr_dict:
                        # New value - create a list for results
                        attr_dict[value] = []
                    elif isinstance(attr_dict[value], dict):
                        # Another rule went deeper from this point
                        # Create a special '_results_' key to store this rule
                        if '_results_' not in attr_dict[value]:
                            attr_dict[value]['_results_'] = []
                        attr_dict[value]['_results_'].append({
                            'result': rule['profile_str'],
                            'rule_rank': rule['rank'],
                            'rule_name': rule['rule_name'],
                            'rule_id': rule['rule_id'],
                            'state': rule['state'],
                            'attributes': rule['attributes']
                        })
                        continue  # Don't append to the main list

                    # Append to the list (normal case)
                    if isinstance(attr_dict[value], list):
                        attr_dict[value].append({
                            'result': rule['profile_str'],
                            'rule_rank': rule['rank'],
                            'rule_name': rule['rule_name'],
                            'rule_id': rule['rule_id'],
                            'state': rule['state'],
                            'attributes': rule['attributes']
                        })
                else:
                    # Intermediate level - ensure value exists and navigate deeper
                    if value not in attr_dict:
                        attr_dict[value] = {}
                    elif isinstance(attr_dict[value], list):
                        # Another rule ended here - convert to dict with _results_
                        existing_results = attr_dict[value]
                        attr_dict[value] = {'_results_': existing_results}

                    current = attr_dict[value]

        return tree

    def generate_mermaid_for_policy_set(self, policy_set_name: str, tree: Dict, hierarchy: List[str]) -> str:
        """Generate Mermaid flowchart for a specific policy set"""
        print(f"  Generating Mermaid flowchart for {policy_set_name}")

        lines = ['flowchart TD']
        lines.append(f'    Start([{policy_set_name}<br/>Decision Flow])')
        lines.append('')

        node_counter = 1
        node_map = {}
        connections = []

        # Define colors for each hierarchy level (cycle through if more levels than colors)
        level_colors = [
            ('rvlanStyle', 'fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000'),
            ('zoneStyle', 'fill:#f3e5f5,stroke:#4a148c,stroke-width:2px,color:#000'),
            ('tenantStyle', 'fill:#e8f5e9,stroke:#1b5e20,stroke-width:2px,color:#000'),
            ('attr4Style', 'fill:#e3f2fd,stroke:#0d47a1,stroke-width:2px,color:#000'),
            ('attr5Style', 'fill:#fce4ec,stroke:#880e4f,stroke-width:2px,color:#000'),
        ]

        # Build tree recursively - now iterates through ALL attributes at this level
        def build_nodes(current_tree: Dict, level: int, parent_node: str):
            nonlocal node_counter

            # Skip special keys
            if '_results_' in current_tree:
                # Handle results at this level first
                pass  # Will be handled below

            # Iterate through all attributes present at this level
            for attr_name in sorted(current_tree.keys()):
                # Skip special keys
                if attr_name == '_results_' or attr_name == '_no_attrs_':
                    continue

                # Get all values for this attribute
                attr_values = current_tree[attr_name]

                # Iterate through each value
                for value in sorted(attr_values.keys()):
                    node_id = f'N{node_counter}'
                    node_counter += 1

                    # Determine style for this level
                    style_name = level_colors[level % len(level_colors)][0]
                    node_map[node_id] = style_name

                    # Get short attribute name for display
                    attr_short = attr_name.split('.')[-1] if '.' in attr_name else attr_name
                    label = f'<b>{attr_short}</b><br/>{value}'
                    lines.append(f'    {node_id}{{{{{label}}}}}')

                    # Add edge label showing which condition value this branch represents
                    edge_label = f"{attr_short}={value}"
                    connections.append(f'    {parent_node} -->|{edge_label}| {node_id}')

                    # Get content under this value
                    content = attr_values[value]

                    # Content can be:
                    # 1. A list of results (rule ends here)
                    # 2. A dict with more attributes to traverse
                    # 3. A dict with '_results_' key (rule ends here but also has deeper branches)

                    # Check if content is a list (results at this level)
                    if isinstance(content, list):
                        for result in content:
                            result_node_id = f'N{node_counter}'
                            node_counter += 1

                            # Check if rule is disabled
                            state = result.get('state', 'enabled')
                            is_disabled = state != 'enabled'

                            # Use different style for disabled rules
                            node_map[result_node_id] = 'disabledResult' if is_disabled else 'result'

                            profile = result['result']
                            rule_name = result['rule_name']
                            rank = result['rule_rank']

                            # Add DISABLED badge if not enabled
                            disabled_badge = '<br/><b>&#9888; DISABLED</b>' if is_disabled else ''

                            lines.append(f'    {result_node_id}[<b>Profile:</b> {profile}<br/><b>Rule:</b> {rule_name}<br/><b>Rank:</b> {rank}{disabled_badge}]')
                            connections.append(f'    {node_id} -->|Match| {result_node_id}')

                    # Check if content is a dict (more levels or mixed)
                    elif isinstance(content, dict):
                        # Check for special '_results_' key (rules that end at this level)
                        if '_results_' in content:
                            for result in content['_results_']:
                                result_node_id = f'N{node_counter}'
                                node_counter += 1

                                # Check if rule is disabled
                                state = result.get('state', 'enabled')
                                is_disabled = state != 'enabled'

                                # Use different style for disabled rules
                                node_map[result_node_id] = 'disabledResult' if is_disabled else 'result'

                                profile = result['result']
                                rule_name = result['rule_name']
                                rank = result['rule_rank']

                                # Add DISABLED badge if not enabled
                                disabled_badge = '<br/><b>&#9888; DISABLED</b>' if is_disabled else ''

                                lines.append(f'    {result_node_id}[<b>Profile:</b> {profile}<br/><b>Rule:</b> {rule_name}<br/><b>Rank:</b> {rank}{disabled_badge}]')
                                connections.append(f'    {node_id} -->|Match| {result_node_id}')

                        # Continue traversing deeper levels
                        build_nodes(content, level + 1, node_id)

        # Start building from root
        build_nodes(tree, 0, 'Start')

        lines.append('')
        lines.append('    %% Connections')
        lines.extend(connections)

        # Add styling
        lines.append('')
        lines.append('    %% Styling')
        lines.append('    classDef startStyle fill:#e1f5ff,stroke:#01579b,stroke-width:3px,color:#000')
        for style_name, style_def in level_colors:
            lines.append(f'    classDef {style_name} {style_def}')
        lines.append('    classDef resultStyle fill:#ffebee,stroke:#b71c1c,stroke-width:2px,color:#000')
        lines.append('    classDef disabledResultStyle fill:#4a5568,stroke:#718096,stroke-width:2px,stroke-dasharray:5 5,color:#a0aec0')
        lines.append('')
        lines.append('    class Start startStyle')

        # Apply styles to nodes
        for node_id, style_name in node_map.items():
            # Add 'Style' suffix if it's a result/disabledResult
            if style_name in ['result', 'disabledResult']:
                lines.append(f'    class {node_id} {style_name}Style')
            else:
                lines.append(f'    class {node_id} {style_name}')

        return '\n'.join(lines)

    def build_paths_for_policy_set(self, policy_set_name: str, hierarchy: List[str]) -> List[Dict]:
        """Build list of all paths for a specific policy set"""
        rules = self.policy_set_data[policy_set_name]['rules']
        paths = []

        for idx, rule in enumerate(rules, 1):
            path = {
                'path_id': idx,
                'rule_rank': rule['rank'],
                'rule_name': rule['rule_name'],
                'rule_id': rule['rule_id'],
                'profile': rule['profile_str'],
                'state': rule['state'],
                'default': rule['default'],
                'conditions': {},
                'all_attributes': rule['attributes']
            }

            # Extract values for hierarchy attributes
            for attr_name in hierarchy:
                path['conditions'][attr_name] = rule['attributes'].get(attr_name, 'Not Specified')

            paths.append(path)

        return paths

    def get_max_attribute_count(self, policy_set_name: str) -> int:
        """
        Get the maximum number of attributes used by any single rule in a policy set

        Args:
            policy_set_name: Name of policy set

        Returns:
            Maximum attribute count across all rules
        """
        rules = self.policy_set_data[policy_set_name]['rules']
        max_count = 0

        for rule in rules:
            attr_count = len(rule['attributes'])
            if attr_count > max_count:
                max_count = attr_count

        return max_count

    def determine_hierarchy(self, policy_set_name: str, max_levels: Optional[int] = None) -> List[str]:
        """
        Determine the best attribute hierarchy for a policy set

        Strategy:
        1. Check CUSTOM_HIERARCHY configuration first
        2. Append any additional attributes not in custom hierarchy (ordered by frequency)
        3. If no custom hierarchy, use automatic frequency-based ordering

        Args:
            policy_set_name: Name of policy set
            max_levels: Maximum number of hierarchy levels (None = auto-detect)

        Returns:
            List of attribute names in hierarchical order
        """
        attributes = self.policy_set_data[policy_set_name]['attributes']

        # Check if custom hierarchy is defined for this specific policy set
        custom_base = None
        if policy_set_name in CUSTOM_HIERARCHY and CUSTOM_HIERARCHY[policy_set_name] is not None:
            custom_base = CUSTOM_HIERARCHY[policy_set_name]
            print(f"  Using CUSTOM hierarchy for {policy_set_name}: {custom_base}")
        # Check for wildcard default '*' that applies to all policy sets
        elif '*' in CUSTOM_HIERARCHY and CUSTOM_HIERARCHY['*'] is not None:
            custom_base = CUSTOM_HIERARCHY['*']
            print(f"  Using DEFAULT hierarchy for {policy_set_name}: {custom_base}")

        # If we have a custom base hierarchy
        if custom_base is not None:
            custom_hierarchy = custom_base.copy()

            # Find any additional attributes not in the custom hierarchy
            custom_set = set(custom_hierarchy)
            additional_attrs = [attr for attr in attributes.keys() if attr not in custom_set]

            if additional_attrs:
                # Sort additional attributes by frequency
                additional_sorted = sorted(additional_attrs, key=lambda x: attributes[x], reverse=True)
                custom_hierarchy.extend(additional_sorted)
                print(f"  + Auto-appending additional attributes: {additional_sorted}")

            return custom_hierarchy

        # Fall back to automatic frequency-based ordering
        print(f"  Using AUTOMATIC hierarchy for {policy_set_name}")

        attributes = self.policy_set_data[policy_set_name]['attributes']

        # If max_levels not specified, automatically detect from rules
        if max_levels is None:
            max_levels = self.get_max_attribute_count(policy_set_name)
            print(f"  Auto-detected max hierarchy levels: {max_levels}")

        # Sort by frequency (most common first)
        sorted_attrs = sorted(attributes.items(), key=lambda x: x[1], reverse=True)

        # Take top N attributes
        hierarchy = [attr_name for attr_name, count in sorted_attrs[:max_levels]]

        return hierarchy

    def analyze_policy_set(self, policy_set_name: str) -> Dict:
        """
        Perform complete analysis for a single policy set

        Returns:
            Dictionary with summary, tree, paths, and mermaid flowchart
        """
        print(f"\nAnalyzing policy set: {policy_set_name}")

        ps_data = self.policy_set_data[policy_set_name]

        # Determine hierarchy (most common attributes)
        # Auto-detect max levels based on the rule with the most attributes
        hierarchy = self.determine_hierarchy(policy_set_name)

        # Build structures
        tree_structure = {}
        paths = []
        mermaid_flowchart = ""

        if hierarchy:
            tree_structure = self.build_tree_for_policy_set(policy_set_name, hierarchy)
            paths = self.build_paths_for_policy_set(policy_set_name, hierarchy)
            mermaid_flowchart = self.generate_mermaid_for_policy_set(policy_set_name, tree_structure, hierarchy)
        else:
            print(f"  No hierarchical attributes found for {policy_set_name}")

        # Build summary
        summary = {
            'total_rules': len(ps_data['rules']),
            'hierarchy': hierarchy,
            'attributes_used': list(ps_data['attributes'].keys()),
            'attribute_frequency': dict(ps_data['attributes']),
            'unique_values_per_attribute': {
                attr: sorted(list(values))
                for attr, values in ps_data['attribute_values'].items()
            }
        }

        # Build detailed rules list
        rules_list = []
        for rule in ps_data['rules']:
            rules_list.append({
                'rank': rule['rank'],
                'name': rule['rule_name'],
                'profile': rule['profile_str'],
                'state': rule['state'],
                'default': rule['default'],
                'attributes': rule['attributes'],
                'conditions_formatted': self.format_condition_for_display(rule['condition'])
            })

        return {
            'summary': summary,
            'mermaid_flowchart': mermaid_flowchart,
            'tree_structure': tree_structure,
            'paths': paths,
            'rules': rules_list
        }

    def generate_dynamic_tree(self):
        """Main method to generate the dynamic decision tree analysis"""
        print("\n" + "=" * 60)
        print("ISE Dynamic Decision Tree Generator")
        print("=" * 60 + "\n")

        # Load data
        data = self.load_data()

        # Discover attributes dynamically
        self.discover_attributes(data)

        # Build global summary
        print("\nGlobal attribute discovery:")
        for attr, count in self.all_attributes.most_common(10):
            print(f"  {attr}: {count} rules")

        # Analyze each policy set
        print("\n" + "=" * 60)
        print("Per-Policy-Set Analysis")
        print("=" * 60)

        policy_set_analyses = {}
        for policy_set_name in self.policy_set_data:
            policy_set_analyses[policy_set_name] = self.analyze_policy_set(policy_set_name)

        # Build output structure
        output = {
            'metadata': {
                'generated_at': datetime.utcnow().isoformat() + 'Z',
                'source_file': str(self.input_file),
                'total_policy_sets': len(self.policy_set_data),
                'total_rules': sum(len(ps['rules']) for ps in self.policy_set_data.values())
            },
            'discovered_attributes': {
                'all_attributes': list(self.all_attributes.keys()),
                'attribute_frequency': dict(self.all_attributes),
                'attribute_values': {
                    attr: sorted(list(values))
                    for attr, values in self.attribute_values.items()
                }
            },
            'policy_sets': policy_set_analyses,
            'global_summary': {
                'policy_sets_analyzed': len(self.policy_set_data),
                'total_unique_attributes': len(self.all_attributes),
                'most_common_attributes': [
                    attr for attr, count in self.all_attributes.most_common(5)
                ]
            }
        }

        # Save output
        print(f"\n\nSaving dynamic decision tree to {self.output_file}...")
        with open(self.output_file, 'w') as f:
            json.dump(output, f, indent=2)

        print("\n" + "=" * 60)
        print("Dynamic Tree Generation Complete!")
        print("=" * 60)
        print(f"\nOutput file: {self.output_file}")
        print(f"Policy sets analyzed: {len(self.policy_set_data)}")
        print(f"Total attributes discovered: {len(self.all_attributes)}")
        print(f"Total rules analyzed: {sum(len(ps['rules']) for ps in self.policy_set_data.values())}")
        print("\nMost common attributes:")
        for attr, count in self.all_attributes.most_common(5):
            print(f"  {attr}: {count} rules")

        # Show per-policy-set attributes for configuration reference
        print("\n" + "=" * 60)
        print("HIERARCHY CONFIGURATION REFERENCE")
        print("=" * 60)
        print("\nTo customize the hierarchy order, edit CUSTOM_HIERARCHY at the")
        print("top of dynamic_tree.py with the following attributes:\n")

        for ps_name in sorted(self.policy_set_data.keys()):
            ps_attrs = self.policy_set_data[ps_name]['attributes']
            if ps_attrs:
                print(f"  '{ps_name}': [")
                for attr in sorted(ps_attrs.keys(), key=lambda x: ps_attrs[x], reverse=True):
                    print(f"      '{attr}',  # Used in {ps_attrs[attr]} rules")
                print("  ],")
        print()


def main():
    """Main entry point"""
    # Define paths
    script_dir = Path(__file__).parent
    config_dir = script_dir.parent / 'configs'

    input_file = config_dir / 'processed_data.json'
    output_file = config_dir / 'dynamic_decision_tree.json'

    # Check if input file exists
    if not input_file.exists():
        print(f"Error: Input file not found: {input_file}")
        print("Please run the data collection scripts first.")
        return 1

    # Generate dynamic decision tree
    try:
        generator = DynamicISETreeGenerator(input_file, output_file)
        generator.generate_dynamic_tree()
        return 0
    except Exception as e:
        print(f"\nError generating dynamic decision tree: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    exit(main())
