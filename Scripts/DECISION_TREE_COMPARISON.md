# ISE Decision Tree Scripts - Comparison Guide

This document helps you understand the differences between `tree.py` and `dynamic_tree.py` and when to use each.

## Quick Comparison Table

| Aspect | tree.py | dynamic_tree.py |
|--------|---------|-----------------|
| **Purpose** | Fixed hierarchy decision tree (rVLAN → NetworkZone → Tenant) | Dynamic multi-policy-set analysis |
| **Attribute Discovery** | Hardcoded (EndPoints.rVLAN, EndPoints.NetworkZone, EndPoints.Tenant) | Fully dynamic - discovers ALL attributes |
| **Scope** | Global analysis (all rules together) | Per-policy-set analysis (separate trees) |
| **Hierarchy** | Fixed: rVLAN → NetworkZone → Tenant | Flexible: Most frequent attributes first |
| **Flowcharts** | Single global flowchart | Separate flowchart per policy set |
| **Output Focus** | Endpoint segmentation rules | All authorization rules across all policy sets |
| **Best For** | Network segmentation use cases | Complex multi-policy environments |
| **Complexity** | Simple, focused | Advanced, comprehensive |

## Output Files

- **tree.py** → `/configs/decision_tree.json`
- **dynamic_tree.py** → `/configs/dynamic_decision_tree.json`

Both scripts read from: `/configs/processed_data.json`

## When to Use tree.py

### Ideal Scenarios:
1. **Network Segmentation Focus**: Your policies primarily use rVLAN, NetworkZone, and Tenant
2. **Simple Visualization**: You want one clean flowchart showing endpoint-based decisions
3. **Quick Analysis**: You need a fast overview of endpoint attribute rules
4. **Specific Use Case**: You're specifically implementing location-based network access

### Example Use Cases:
- Campus network with multiple VLANs and zones
- Multi-tenant environments (healthcare, education)
- Physical location-based access control
- Endpoint segmentation by department/building

### What You Get:
```
- Single decision tree: rVLAN → NetworkZone → Tenant → Profile
- Focus on 4 endpoint rules (from your sample data)
- One Mermaid flowchart showing the hierarchy
- List of other rules (11 rules) documented separately
```

## When to Use dynamic_tree.py

### Ideal Scenarios:
1. **Comprehensive Analysis**: You want to see ALL attributes being used
2. **Multiple Policy Sets**: You have different policy sets for different purposes
3. **Unknown Configuration**: You inherited an ISE deployment and need to understand it
4. **Policy Audit**: You're auditing what attributes and conditions are actually deployed
5. **Complex Policies**: Your policies use authentication, posture, identity groups, etc.

### Example Use Cases:
- Full ISE policy audit
- Migration from another NAC solution
- Multi-policy environments (wireless, wired, VPN, guest)
- Understanding inherited configurations
- Compliance documentation
- Policy optimization projects

### What You Get:
```
- 13 discovered attributes (from your sample data)
- 3 separate policy set analyses
- Separate flowchart for each policy set
- Different hierarchies per policy set:
  * PolicySet1: Tenant → NetworkZone → rVLAN
  * Default: AuthenticationStatus → RadiusFlowType → PostureStatus
- Attribute frequency analysis
- Global summary across all policy sets
```

## Output Structure Comparison

### tree.py Output:
```json
{
  "metadata": {...},
  "summary": {
    "total_rules": 18,
    "endpoint_attribute_rules": 4,
    "other_rules": 14,
    "unique_values": {...}
  },
  "mermaid_flowchart": "...",
  "paths": [...],
  "tree_structure": {...},
  "other_rules": [...]
}
```

### dynamic_tree.py Output:
```json
{
  "metadata": {...},
  "discovered_attributes": {
    "all_attributes": [...],
    "attribute_frequency": {...},
    "attribute_values": {...}
  },
  "policy_sets": {
    "PolicySet1": {
      "summary": {...},
      "mermaid_flowchart": "...",
      "tree_structure": {...},
      "paths": [...],
      "rules": [...]
    },
    "PolicySet2": {...},
    "Default": {...}
  },
  "global_summary": {...}
}
```

## Real-World Example from Your Data

### Scenario: Your ISE Configuration

Your configuration has:
- **PolicySet1**: Endpoint segmentation rules (4 rules using rVLAN/NetworkZone/Tenant)
- **PolicySet2**: Simple deny rule (1 rule)
- **Default**: Complex authentication/posture rules (11 rules using various attributes)

### Using tree.py:
✓ Shows the 4 endpoint rules nicely in a tree
✓ Lists the other 14 rules separately
✓ One flowchart focused on endpoint attributes
⚠ Doesn't show Default policy set's complexity
⚠ Doesn't reveal authentication/posture flow

### Using dynamic_tree.py:
✓ Shows all 13 unique attributes used
✓ Separate analysis for each policy set
✓ PolicySet1 flowchart: Endpoint-based decisions
✓ Default flowchart: Authentication/posture-based decisions
✓ Reveals PolicySet2 is trivial (just deny)
✓ Shows which attributes are most commonly used

## Recommendation: Use Both!

For comprehensive understanding:

1. **Start with dynamic_tree.py**:
   - Discover what attributes are actually being used
   - Understand each policy set's purpose
   - Identify which policy sets are most complex

2. **Then use tree.py**:
   - Deep dive into endpoint segmentation (if that's your focus)
   - Get clean visualization of rVLAN/NetworkZone/Tenant flow
   - Focus on network location-based policies

## Performance

Both scripts are fast:
- **tree.py**: ~1 second (simpler analysis)
- **dynamic_tree.py**: ~2 seconds (recursive parsing, per-policy-set analysis)

Since both are included in `parent.py` (steps 11 and 12), you get both analyses automatically!

## For Developers / API Consumers

### Consume tree.py output when:
- Building UI for endpoint segmentation
- Implementing network location-based flows
- You need fixed structure (always rVLAN → NetworkZone → Tenant)

### Consume dynamic_tree.py output when:
- Building generic ISE policy visualization
- Need to support any ISE configuration
- Building policy comparison tools
- Implementing policy audit reports
- Need per-policy-set filtering in UI

## Summary

| If you need... | Use... |
|----------------|--------|
| Fixed hierarchy (rVLAN → NetworkZone → Tenant) | tree.py |
| Dynamic attribute discovery | dynamic_tree.py |
| Single global view | tree.py |
| Per-policy-set analysis | dynamic_tree.py |
| Focus on endpoint rules only | tree.py |
| See all authorization rules | dynamic_tree.py |
| Simple, focused output | tree.py |
| Comprehensive, detailed analysis | dynamic_tree.py |
| Quick endpoint segmentation overview | tree.py |
| Full ISE policy audit | dynamic_tree.py |

## Next Steps

1. Run `parent.py` to generate both outputs
2. Open `decision_tree.json` to see focused endpoint analysis
3. Open `dynamic_decision_tree.json` to see comprehensive multi-policy analysis
4. Copy Mermaid flowcharts to https://mermaid.live/ to visualize
5. Use the JSON outputs to build custom dashboards or reports

Both scripts complement each other and provide different perspectives on your ISE authorization policies!
