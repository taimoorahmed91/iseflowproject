# Dynamic Tree Update - Tree Structure Fix

## What Was Fixed

Updated `dynamic_tree.py` to include **attribute names at each level** of the tree structure, making it self-documenting for UI consumption.

## Changes Made

### Modified Methods

1. **`build_tree_for_policy_set()` (lines 196-247)**
   - Changed tree structure to include attribute names as keys at each level
   - Format: `{attr_name: {value: {next_attr_name: {value: ...}}}}`

2. **`generate_mermaid_for_policy_set()` (lines 249-348)**
   - Updated `build_nodes()` inner function to work with new tree structure
   - Now correctly navigates attribute names → values → next level

## Old Structure (Before Fix)

```json
{
  "Value1": {
    "Value2": {
      "Value3": [
        {
          "result": "PermitAccess",
          "rule_rank": 0,
          ...
        }
      ]
    }
  }
}
```

**Problem**: UI doesn't know what "Value1", "Value2", "Value3" represent.

## New Structure (After Fix)

```json
{
  "EndPoints.Tenant": {
    "Value1": {
      "EndPoints.rVLAN": {
        "Value1": {
          "EndPoints.NetworkZone": {
            "Value1": [
              {
                "result": "PermitAccess",
                "rule_rank": 0,
                "rule_name": "Authorization Rule 1",
                "rule_id": "85c935eb-4e05-436c-9916-d64922fc5ae3",
                "attributes": {
                  "EndPoints.Tenant": "Value1",
                  "EndPoints.rVLAN": "Value1",
                  "EndPoints.NetworkZone": "Value1"
                }
              }
            ]
          }
        }
      }
    }
  }
}
```

**Solution**: UI can see that each level represents:
- Level 1: `EndPoints.Tenant` → Value1
- Level 2: `EndPoints.rVLAN` → Value1
- Level 3: `EndPoints.NetworkZone` → Value1
- Result: PermitAccess

## Benefits

### 1. Self-Documenting Structure
The tree structure now explicitly shows what attribute each level represents.

### 2. UI-Friendly
Frontend developers can easily parse the tree and display:
```javascript
// Example: Parse tree in JavaScript
for (const [attributeName, attributeValues] of Object.entries(tree)) {
  console.log(`Attribute: ${attributeName}`);
  for (const [value, nextLevel] of Object.entries(attributeValues)) {
    console.log(`  Value: ${value}`);
    // Recurse to next level...
  }
}
```

### 3. Works with Any Attributes
Different policy sets can have different attributes at each level:

**PolicySet1:**
```
EndPoints.Tenant → EndPoints.rVLAN → EndPoints.NetworkZone
```

**Default Policy Set:**
```
Network Access.AuthenticationStatus → Normalised Radius.RadiusFlowType → Session.PostureStatus
```

### 4. No Ambiguity
Each level is clearly labeled with its attribute name, eliminating confusion.

## Example Output

### PolicySet1 Tree Structure
```
EndPoints.Tenant:
  Value1:
    EndPoints.rVLAN:
      Value1:
        EndPoints.NetworkZone:
          Value1: [1 result(s)]
  Value2:
    EndPoints.rVLAN:
      Value2:
        EndPoints.NetworkZone:
          Value2: [1 result(s)]
          Not Specified: [1 result(s)]
```

### Default Policy Set Tree Structure
```
Network Access.AuthenticationStatus:
  Not Specified:
    Normalised Radius.RadiusFlowType:
      Not Specified:
        Session.PostureStatus:
          Not Specified: [4 result(s)]
  AuthenticationPassed:
    Normalised Radius.RadiusFlowType:
      Not Specified:
        Session.PostureStatus:
          Unknown: [1 result(s)]
          NonCompliant: [1 result(s)]
          Compliant: [1 result(s)]
```

## Testing

Script was tested and confirmed working:
```bash
cd /Users/taimoorahmed/Desktop/iseflowproject/Scripts
python3 dynamic_tree.py
```

**Results:**
- ✓ Tree structure includes attribute names at each level
- ✓ Mermaid flowcharts still generate correctly
- ✓ All 3 policy sets analyzed successfully
- ✓ Output file `dynamic_decision_tree.json` updated

## Usage for UI Development

### Parsing the Tree (Python)
```python
import json

with open('dynamic_decision_tree.json') as f:
    data = json.load(f)

# Get tree for a specific policy set
tree = data['policy_sets']['PolicySet1']['tree_structure']

# Navigate tree with attribute names
for attr_name, attr_values in tree.items():
    print(f"Attribute: {attr_name}")
    for value, next_level in attr_values.items():
        print(f"  Value: {value}")
        # Continue navigation...
```

### Parsing the Tree (JavaScript)
```javascript
// Recursive function to traverse tree
function traverseTree(tree, level = 0) {
  for (const [key, value] of Object.entries(tree)) {
    const indent = '  '.repeat(level);

    if (Array.isArray(value)) {
      // Leaf node - results
      console.log(`${indent}${key}: ${value.length} result(s)`);
      value.forEach(result => {
        console.log(`${indent}  → ${result.rule_name}: ${result.result}`);
      });
    } else {
      // Intermediate node - attribute or value
      console.log(`${indent}${key}:`);
      traverseTree(value, level + 1);
    }
  }
}

// Load and traverse
fetch('dynamic_decision_tree.json')
  .then(res => res.json())
  .then(data => {
    const tree = data.policy_sets.PolicySet1.tree_structure;
    traverseTree(tree);
  });
```

## Backwards Compatibility

**Breaking Change**: This update changes the tree structure format.

If you have existing code that parses `tree_structure` from `dynamic_decision_tree.json`, you'll need to update it to account for attribute names at each level.

**Old parsing:**
```python
for value in tree.keys():  # Direct values
    ...
```

**New parsing:**
```python
for attr_name, attr_values in tree.items():  # Attribute name first
    for value in attr_values.keys():  # Then values
        ...
```

## Files Updated

- `/Scripts/dynamic_tree.py` (lines 196-326)
  - `build_tree_for_policy_set()` method
  - `generate_mermaid_for_policy_set()` method (inner `build_nodes()` function)

## Files Generated

- `/configs/dynamic_decision_tree.json` (regenerated with new structure)

## Summary

The tree structure now includes attribute names at each level, making it:
- ✓ Self-documenting
- ✓ UI-friendly
- ✓ Clear and unambiguous
- ✓ Easy to parse programmatically

The structure clearly shows what each level represents, enabling frontend developers to build intuitive decision tree visualizations without guessing what each level means.

---

**Update Applied**: 2026-02-01
**Status**: Tested and working
**Impact**: Breaking change for tree_structure format
