#!/usr/bin/env python3
"""
ISE Authorization Policy Decision Tree Generator

This script reads processed_data.json and generates a hierarchical decision tree
analysis for endpoint attribute-based authorization rules.

The tree follows the hierarchy: rVLAN → NetworkZone → Tenant → Result

Output: decision_tree.json
"""

import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Any, Optional


class ISEDecisionTreeGenerator:
    """Generates decision tree analysis from ISE authorization policies"""

    def __init__(self, input_file: Path, output_file: Path):
        self.input_file = input_file
        self.output_file = output_file
        self.endpoint_rules = []
        self.other_rules = []
        self.unique_values = {
            'rVLAN': set(),
            'NetworkZone': set(),
            'Tenant': set()
        }

    def load_data(self) -> Dict:
        """Load the processed ISE data"""
        print(f"Loading data from {self.input_file}...")
        with open(self.input_file, 'r') as f:
            return json.load(f)

    def extract_endpoint_attributes(self, condition: Dict) -> Dict[str, Optional[str]]:
        """
        Extract endpoint attributes (rVLAN, NetworkZone, Tenant) from a rule condition

        Returns dict with keys: rVLAN, NetworkZone, Tenant (values are None if not found)
        """
        attributes = {
            'rVLAN': None,
            'NetworkZone': None,
            'Tenant': None
        }

        if not condition:
            return attributes

        # Handle ConditionAndBlock with children
        if condition.get('conditionType') == 'ConditionAndBlock':
            children = condition.get('children', [])
            for child in children:
                if child.get('dictionaryName') == 'EndPoints':
                    attr_name = child.get('attributeName')
                    if attr_name in attributes:
                        attributes[attr_name] = child.get('attributeValue', 'Not Specified')

        # Handle direct ConditionAttributes
        elif condition.get('conditionType') == 'ConditionAttributes':
            if condition.get('dictionaryName') == 'EndPoints':
                attr_name = condition.get('attributeName')
                if attr_name in attributes:
                    attributes[attr_name] = condition.get('attributeValue', 'Not Specified')

        return attributes

    def is_endpoint_rule(self, attributes: Dict[str, Optional[str]]) -> bool:
        """Check if a rule uses any endpoint attributes"""
        return any(v is not None for v in attributes.values())

    def analyze_rules(self, data: Dict):
        """Analyze all authorization rules and categorize them"""
        print("Analyzing authorization rules...")

        for policy_set in data.get('policy_sets', []):
            policy_set_name = policy_set.get('name', 'Unknown')

            for auth_policy in policy_set.get('authorization_policies', []):
                rule = auth_policy.get('rule', {})
                condition = rule.get('condition')

                # Extract endpoint attributes
                attributes = self.extract_endpoint_attributes(condition)

                # Build rule info
                rule_info = {
                    'policy_set': policy_set_name,
                    'rule_id': rule.get('id'),
                    'rule_name': rule.get('name'),
                    'rank': rule.get('rank'),
                    'state': rule.get('state'),
                    'profile': auth_policy.get('profile', []),
                    'profile_str': ', '.join(auth_policy.get('profile', [])),
                    'attributes': attributes,
                    'condition': condition
                }

                # Categorize rule
                if self.is_endpoint_rule(attributes):
                    self.endpoint_rules.append(rule_info)

                    # Track unique values
                    for attr_name, attr_value in attributes.items():
                        if attr_value and attr_value != 'Not Specified':
                            self.unique_values[attr_name].add(attr_value)
                else:
                    self.other_rules.append(rule_info)

        # Sort endpoint rules by rank
        self.endpoint_rules.sort(key=lambda x: (x['rank'] if x['rank'] is not None else float('inf'), x['rule_name']))
        self.other_rules.sort(key=lambda x: (x['rank'] if x['rank'] is not None else float('inf'), x['rule_name']))

        print(f"  Found {len(self.endpoint_rules)} endpoint attribute-based rules")
        print(f"  Found {len(self.other_rules)} other rules")

    def build_tree_structure(self) -> Dict:
        """Build hierarchical tree structure: rVLAN → NetworkZone → Tenant → Result"""
        print("Building hierarchical tree structure...")
        tree = {}

        for rule in self.endpoint_rules:
            attrs = rule['attributes']
            rvlan = attrs.get('rVLAN') or 'Not Specified'
            network_zone = attrs.get('NetworkZone') or 'Not Specified'
            tenant = attrs.get('Tenant') or 'Not Specified'

            # Build nested structure
            if rvlan not in tree:
                tree[rvlan] = {}

            if network_zone not in tree[rvlan]:
                tree[rvlan][network_zone] = {}

            if tenant not in tree[rvlan][network_zone]:
                tree[rvlan][network_zone][tenant] = []

            # Add result
            tree[rvlan][network_zone][tenant].append({
                'result': rule['profile_str'],
                'rule_rank': rule['rank'],
                'rule_name': rule['rule_name'],
                'rule_id': rule['rule_id'],
                'policy_set': rule['policy_set']
            })

        return tree

    def build_paths(self) -> List[Dict]:
        """Build list of all paths through the decision tree"""
        print("Building evaluation paths...")
        paths = []

        for idx, rule in enumerate(self.endpoint_rules, 1):
            path = {
                'path_id': idx,
                'conditions': {
                    'rVLAN': rule['attributes'].get('rVLAN') or 'Not Specified',
                    'NetworkZone': rule['attributes'].get('NetworkZone') or 'Not Specified',
                    'Tenant': rule['attributes'].get('Tenant') or 'Not Specified'
                },
                'rule_rank': rule['rank'],
                'rule_name': rule['rule_name'],
                'rule_id': rule['rule_id'],
                'profile': rule['profile_str'],
                'policy_set': rule['policy_set'],
                'state': rule['state']
            }
            paths.append(path)

        return paths

    def generate_mermaid_flowchart(self, tree: Dict) -> str:
        """Generate Mermaid flowchart syntax for the decision tree"""
        print("Generating Mermaid flowchart...")

        lines = ['flowchart TD']
        lines.append('    Start([ISE Authorization<br/>rVLAN → NetworkZone → Tenant])')
        lines.append('')

        node_counter = 1
        node_map = {}
        connections = []

        # Generate nodes for rVLAN level
        rvlan_nodes = {}
        for rvlan in sorted(tree.keys()):
            node_id = f'N{node_counter}'
            node_counter += 1
            rvlan_nodes[rvlan] = node_id
            node_map[node_id] = 'rvlan'
            label = f'<b>rVLAN</b><br/>{rvlan}'
            lines.append(f'    {node_id}{{{{{label}}}}}')
            connections.append(f'    Start --> {node_id}')

        lines.append('')

        # Generate nodes for NetworkZone level
        zone_nodes = {}
        for rvlan in sorted(tree.keys()):
            for network_zone in sorted(tree[rvlan].keys()):
                node_id = f'N{node_counter}'
                node_counter += 1
                zone_key = (rvlan, network_zone)
                zone_nodes[zone_key] = node_id
                node_map[node_id] = 'zone'
                label = f'<b>NetworkZone</b><br/>{network_zone}'
                lines.append(f'    {node_id}{{{{{label}}}}}')
                connections.append(f'    {rvlan_nodes[rvlan]} --> {node_id}')

        lines.append('')

        # Generate nodes for Tenant level
        tenant_nodes = {}
        for rvlan in sorted(tree.keys()):
            for network_zone in sorted(tree[rvlan].keys()):
                for tenant in sorted(tree[rvlan][network_zone].keys()):
                    node_id = f'N{node_counter}'
                    node_counter += 1
                    tenant_key = (rvlan, network_zone, tenant)
                    tenant_nodes[tenant_key] = node_id
                    node_map[node_id] = 'tenant'
                    label = f'<b>Tenant</b><br/>{tenant}'
                    lines.append(f'    {node_id}{{{{{label}}}}}')
                    zone_key = (rvlan, network_zone)
                    connections.append(f'    {zone_nodes[zone_key]} --> {node_id}')

        lines.append('')

        # Generate result nodes
        result_nodes = []
        for rvlan in sorted(tree.keys()):
            for network_zone in sorted(tree[rvlan].keys()):
                for tenant in sorted(tree[rvlan][network_zone].keys()):
                    results = tree[rvlan][network_zone][tenant]
                    for result in results:
                        node_id = f'N{node_counter}'
                        node_counter += 1
                        result_nodes.append(node_id)
                        node_map[node_id] = 'result'

                        profile = result['result']
                        rule_name = result['rule_name']
                        rank = result['rule_rank']

                        lines.append(f'    {node_id}[<b>Profile:</b> {profile}<br/><b>Rule:</b> {rule_name}<br/><b>Rank:</b> {rank}]')

                        tenant_key = (rvlan, network_zone, tenant)
                        connections.append(f'    {tenant_nodes[tenant_key]} --> {node_id}')

        lines.append('')
        lines.append('    %% Connections')
        lines.extend(connections)

        lines.append('')
        lines.append('    %% Styling')
        lines.append('    classDef startStyle fill:#e1f5ff,stroke:#01579b,stroke-width:3px,color:#000')
        lines.append('    classDef rvlanStyle fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000')
        lines.append('    classDef zoneStyle fill:#f3e5f5,stroke:#4a148c,stroke-width:2px,color:#000')
        lines.append('    classDef tenantStyle fill:#e8f5e9,stroke:#1b5e20,stroke-width:2px,color:#000')
        lines.append('    classDef resultStyle fill:#ffebee,stroke:#b71c1c,stroke-width:2px,color:#000')
        lines.append('')
        lines.append('    class Start startStyle')

        # Apply styles
        for node_id, node_type in node_map.items():
            if node_type == 'rvlan':
                lines.append(f'    class {node_id} rvlanStyle')
            elif node_type == 'zone':
                lines.append(f'    class {node_id} zoneStyle')
            elif node_type == 'tenant':
                lines.append(f'    class {node_id} tenantStyle')
            elif node_type == 'result':
                lines.append(f'    class {node_id} resultStyle')

        return '\n'.join(lines)

    def format_condition_for_display(self, condition: Dict) -> str:
        """Format a condition object for human-readable display"""
        if not condition:
            return "No conditions"

        if condition.get('conditionType') == 'ConditionAndBlock':
            children = condition.get('children', [])
            parts = []
            for child in children:
                dict_name = child.get('dictionaryName', '')
                attr_name = child.get('attributeName', '')
                operator = child.get('operator', '')
                attr_value = child.get('attributeValue', '')
                parts.append(f"{dict_name}.{attr_name} {operator} {attr_value}")
            return " AND ".join(parts)

        elif condition.get('conditionType') == 'ConditionAttributes':
            dict_name = condition.get('dictionaryName', '')
            attr_name = condition.get('attributeName', '')
            operator = condition.get('operator', '')
            attr_value = condition.get('attributeValue', '')
            return f"{dict_name}.{attr_name} {operator} {attr_value}"

        return "Complex condition"

    def build_other_rules_list(self) -> List[Dict]:
        """Build formatted list of non-endpoint-attribute rules"""
        print("Formatting other rules...")
        formatted_rules = []

        for rule in self.other_rules:
            formatted_rules.append({
                'rank': rule['rank'],
                'name': rule['rule_name'],
                'profile': rule['profile_str'],
                'policy_set': rule['policy_set'],
                'state': rule['state'],
                'conditions': self.format_condition_for_display(rule['condition'])
            })

        return formatted_rules

    def generate_decision_tree(self):
        """Main method to generate the decision tree analysis"""
        print("\n" + "=" * 60)
        print("ISE Decision Tree Generator")
        print("=" * 60 + "\n")

        # Load data
        data = self.load_data()

        # Analyze rules
        self.analyze_rules(data)

        # Build structures
        tree_structure = self.build_tree_structure()
        paths = self.build_paths()
        mermaid_flowchart = self.generate_mermaid_flowchart(tree_structure)
        other_rules = self.build_other_rules_list()

        # Build output
        output = {
            'metadata': {
                'generated_at': datetime.utcnow().isoformat() + 'Z',
                'source_file': str(self.input_file),
                'total_rules': len(self.endpoint_rules) + len(self.other_rules)
            },
            'summary': {
                'total_rules': len(self.endpoint_rules) + len(self.other_rules),
                'endpoint_attribute_rules': len(self.endpoint_rules),
                'other_rules': len(self.other_rules),
                'unique_values': {
                    'rVLAN': sorted(list(self.unique_values['rVLAN'])),
                    'NetworkZone': sorted(list(self.unique_values['NetworkZone'])),
                    'Tenant': sorted(list(self.unique_values['Tenant']))
                }
            },
            'mermaid_flowchart': mermaid_flowchart,
            'paths': paths,
            'tree_structure': tree_structure,
            'other_rules': other_rules
        }

        # Save output
        print(f"\nSaving decision tree to {self.output_file}...")
        with open(self.output_file, 'w') as f:
            json.dump(output, f, indent=2)

        print("\n" + "=" * 60)
        print("Decision Tree Generation Complete!")
        print("=" * 60)
        print(f"\nOutput file: {self.output_file}")
        print(f"Total rules analyzed: {len(self.endpoint_rules) + len(self.other_rules)}")
        print(f"  - Endpoint attribute rules: {len(self.endpoint_rules)}")
        print(f"  - Other rules: {len(self.other_rules)}")
        print(f"\nUnique attribute values:")
        print(f"  - rVLAN: {len(self.unique_values['rVLAN'])} values")
        print(f"  - NetworkZone: {len(self.unique_values['NetworkZone'])} values")
        print(f"  - Tenant: {len(self.unique_values['Tenant'])} values")
        print()


def main():
    """Main entry point"""
    # Define paths
    script_dir = Path(__file__).parent
    config_dir = script_dir.parent / 'configs'

    input_file = config_dir / 'processed_data.json'
    output_file = config_dir / 'decision_tree.json'

    # Check if input file exists
    if not input_file.exists():
        print(f"Error: Input file not found: {input_file}")
        print("Please run the data collection scripts first.")
        return 1

    # Generate decision tree
    try:
        generator = ISEDecisionTreeGenerator(input_file, output_file)
        generator.generate_decision_tree()
        return 0
    except Exception as e:
        print(f"\nError generating decision tree: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    exit(main())
