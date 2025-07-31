from typing import Dict, List, Optional, Any
# Import license FIRST before any pysmile objects
import bn_creator.pysmile_license
import pysmile
from pysmile import NodeType
from bn_creator.fuzzy_tactics_system import FuzzyTacticsSystem
from bn_creator.noisy_adder import NoisyAdder


class FuzzyBNBuilder:
    """
    Enhanced BNBuilder that incorporates fuzzy logic for MITRE ATT&CK tactics.
    Extends the original BNBuilder with fuzzy-based probability calculations.
    """
    
    def __init__(self,
                 used_ids,
                 graph_edges,
                 partition_groups,
                 divorce_groups,
                 logic_groups,
                 recommendations,
                 id_to_obj=None,
                 parent_map=None,
                 child_map=None,
                 fuzzy_params=None):
        
        # Initialize base BNBuilder attributes
        self.used_ids = set(used_ids)
        self.graph_edges = graph_edges
        self.partition_groups = partition_groups
        self.divorce_groups = divorce_groups
        self.logic_groups = logic_groups
        self.recs_by_node = {
            rec["node_id"]: rec["recommendations"]
            for rec in recommendations
        }
        self.id_to_obj = id_to_obj or {}
        self.parent_map = parent_map or {}
        self.child_map = child_map or {}
        self.net = pysmile.Network()
        self.handle_by_id = {}
        
        # Initialize fuzzy system
        self.fuzzy_system = FuzzyTacticsSystem()
        self.fuzzy_params = fuzzy_params or {}
        
        # Track nodes with tactics for fuzzy processing
        self.tactic_nodes = {}
        self._identify_tactic_nodes()
    
    def _identify_tactic_nodes(self):
        """Identify nodes that have tactic_id attributes."""
        print(f"DEBUG: Identifying tactic nodes from {len(self.used_ids)} total nodes...")
        for node_id in self.used_ids:
            obj = self.id_to_obj.get(node_id)
            if obj and hasattr(obj, 'tactic_id') and obj.tactic_id:
                self.tactic_nodes[node_id] = obj.tactic_id
                print(f"DEBUG: Found tactic node {node_id} -> {obj.tactic_id}")
            else:
                # Debug why node wasn't identified as tactic
                if not obj:
                    print(f"DEBUG: Node {node_id} has no object in id_to_obj")
                elif not hasattr(obj, 'tactic_id'):
                    print(f"DEBUG: Node {node_id} object has no tactic_id attribute")
                elif not obj.tactic_id:
                    print(f"DEBUG: Node {node_id} has empty tactic_id: {obj.tactic_id}")
        print(f"DEBUG: Total tactic nodes identified: {len(self.tactic_nodes)}")
        print(f"DEBUG: Tactic nodes: {list(self.tactic_nodes.keys())[:5]}...")
    
    def _add_cpt_node(self, node_id, label=None, comment=None, is_fuzzy_tactic=False):
        """Add a CPT node to the network."""
        h = self.net.add_node(NodeType.CPT, node_id)
        
        if label:
            self.net.set_node_name(node_id, label)
        if comment:
            self.net.set_node_description(node_id, comment)
        
        if is_fuzzy_tactic:
            # Create 5 fuzzy states for tactic nodes
            fuzzy_states = ["Very_Low", "Low", "Medium", "High", "Very_High"]
            
            # First add the additional outcomes (PySmile nodes start with 2 outcomes by default)
            for i in range(2, len(fuzzy_states)):
                self.net.add_outcome(node_id, fuzzy_states[i])
            
            # Then set the outcome IDs
            for i, state in enumerate(fuzzy_states):
                self.net.set_outcome_id(node_id, i, state)
        else:
            # Standard binary states for non-tactic nodes
            self.net.set_outcome_id(node_id, 0, "False")
            self.net.set_outcome_id(node_id, 1, "True")
        
        return h
    
    def _build_node_comment(self, node_id):
        """Build descriptive comment for a node."""
        lines = []
        obj = self.id_to_obj.get(node_id)
        if obj:
            if getattr(obj, "name", None):
                lines.append(f"Name: {obj.name}")
            if getattr(obj, "description", None):
                lines.append(f"Description: {obj.description}")
            if getattr(obj, "tactic_id", None):
                lines.append(f"Tactic: {obj.tactic_id}")
            if getattr(obj, "technique_id", None):
                lines.append(f"Technique: {obj.technique_id}")
        
        parents = self.parent_map.get(node_id, [])
        children = self.child_map.get(node_id, [])
        if parents:
            lines.append(f"Parents: {parents}")
        if children:
            lines.append(f"Children: {children}")
        
        recs = self.recs_by_node.get(node_id)
        if recs:
            lines.append("Recommendations: " + ", ".join(recs))
        
        # Add fuzzy system info if applicable
        if node_id in self.tactic_nodes:
            tactic = self.tactic_nodes[node_id]
            tactic_name = self.fuzzy_system.tactic_definitions.get(tactic, tactic)
            lines.append(f"Fuzzy Tactic: {tactic_name}")
        
        return "\n".join(lines) if lines else None
    
    def _get_fuzzy_parameters_for_node(self, node_id: str) -> Dict[str, float]:
        """Get fuzzy parameters for a specific node."""
        if node_id in self.fuzzy_params:
            return self.fuzzy_params[node_id]
        
        # Use tactic-specific defaults - FIXED: Use the exact parameter names each tactic expects
        tactic_id = self.tactic_nodes.get(node_id)
        if tactic_id:
            # Get the default parameters with correct names for this tactic
            defaults = self.fuzzy_system.get_default_fuzzy_params(tactic_id)
            
            # Adjust based on node characteristics, but only modify parameters that exist for this tactic
            obj = self.id_to_obj.get(node_id)
            if obj:
                # Adjust skill requirement based on technique complexity (if this tactic uses skill_requirement)
                if 'skill_requirement' in defaults and hasattr(obj, 'technique_id') and obj.technique_id:
                    # More complex techniques require higher skill
                    if any(x in obj.technique_id.lower() for x in ['rootkit', 'kernel', 'driver']):
                        defaults['skill_requirement'] = min(100, defaults['skill_requirement'] + 30)
                    elif any(x in obj.technique_id.lower() for x in ['script', 'macro', 'email']):
                        defaults['skill_requirement'] = max(0, defaults['skill_requirement'] - 20)
                
                # Adjust detection difficulty based on description (if this tactic uses detection_difficulty)
                if 'detection_difficulty' in defaults and hasattr(obj, 'description') and obj.description:
                    desc_lower = obj.description.lower()
                    if any(x in desc_lower for x in ['stealth', 'hidden', 'covert']):
                        defaults['detection_difficulty'] = min(100, defaults['detection_difficulty'] + 20)
                    elif any(x in desc_lower for x in ['obvious', 'visible', 'logged']):
                        defaults['detection_difficulty'] = max(0, defaults['detection_difficulty'] - 20)
            
            return defaults
        
        # Generic defaults for non-tactic nodes (fallback only)
        return {
            "detection_difficulty": 50,
            "skill_requirement": 50,
            "resource_availability": 50,
            "time_constraint": 50
        }
    
    def _handle_mixed_parent_cpt(self, safe_node_id: str, tactic_id: str, fuzzy_params: Dict):
        """Handle CPT generation when parents are a mix of fuzzy and binary nodes."""
        parents = self.net.get_parents(safe_node_id)
        
        # Determine parent types and state counts
        parent_info = []
        for parent_handle in parents:
            parent_id = self.net.get_node_id(parent_handle)
            parent_states = self.net.get_outcome_count(parent_id)
            parent_info.append((parent_id, parent_states))
        
        if not parent_info:
            # No parents - use base fuzzy distribution
            base_membership = self.fuzzy_system.get_fuzzy_membership_distribution(tactic_id, **fuzzy_params)
            print(f"DEBUG: Setting CPT for {safe_node_id} (no parents) - Fuzzy distribution: {[f'{x:.4f}' for x in base_membership]}")
            self.net.set_node_definition(safe_node_id, base_membership)
            return
        
        # Calculate total number of parent combinations
        total_combinations = 1
        for _, states in parent_info:
            total_combinations *= states
        
        cpt = []
        base_membership = self.fuzzy_system.get_fuzzy_membership_distribution(tactic_id, **fuzzy_params)
        
        for combination in range(total_combinations):
            # Decode the parent state combination - FIXED ordering
            temp_combo = combination
            parent_states = []
            
            # Process parents in forward order to match PySmile's CPT ordering
            for _, num_states in parent_info:
                parent_states.append(temp_combo % num_states)
                temp_combo //= num_states
            
            # Calculate influence based on parent states
            total_influence = 0.0
            for state, (_, num_states) in zip(parent_states, parent_info):
                if num_states == 2:
                    # Binary parent: 0=False, 1=True
                    influence = state  # 0 or 1
                else:
                    # Fuzzy parent: normalize to 0-1 scale
                    influence = state / (num_states - 1)
                total_influence += influence
            
            # Normalize influence by number of parents
            avg_influence = total_influence / len(parent_info) if parent_info else 0.5
            
            # Adjust membership distribution based on parent influence
            adjusted_membership = base_membership.copy()
        
            if avg_influence < 0.3:
                # Low parent influence - subtle shift toward lower states
                shift_factor = (0.3 - avg_influence) * 0.3
                adjusted_membership[0] += shift_factor * 0.2
                adjusted_membership[1] += shift_factor * 0.15
                adjusted_membership[2] -= shift_factor * 0.1
                adjusted_membership[3] -= shift_factor * 0.15
                adjusted_membership[4] -= shift_factor * 0.1
                
            elif avg_influence > 0.7:
                # High parent influence - subtle shift toward higher states
                shift_factor = (avg_influence - 0.7) * 0.3
                adjusted_membership[0] -= shift_factor * 0.1
                adjusted_membership[1] -= shift_factor * 0.15
                adjusted_membership[2] -= shift_factor * 0.1
                adjusted_membership[3] += shift_factor * 0.15
                adjusted_membership[4] += shift_factor * 0.2
                
            # Ensure all probabilities are non-negative and sum to 1
            adjusted_membership = [max(0.01, p) for p in adjusted_membership]
            total = sum(adjusted_membership)
            adjusted_membership = [p / total for p in adjusted_membership]
            
            cpt.extend(adjusted_membership)
        
        # Debug output to compare with terminal fuzzy distributions
        print(f"DEBUG: Setting CPT for {safe_node_id} (with parents) - Base fuzzy: {[f'{x:.4f}' for x in base_membership]}")
        print(f"DEBUG: Final CPT length: {len(cpt)}, First combination: {[f'{x:.4f}' for x in cpt[:5]]}")
        self.net.set_node_definition(safe_node_id, cpt)
    
    def _set_fuzzy_cpt(self, node_id: str):
        """Set CPT for a node using fuzzy logic with multi-state outcomes."""
        safe_node_id = node_id.replace("-", "_")
        tactic_id = self.tactic_nodes.get(node_id)
        
        print(f"DEBUG: _set_fuzzy_cpt called for {node_id} -> {tactic_id}")
        
        if not tactic_id:
            # No tactic - use default probabilities
            print(f"DEBUG: No tactic ID found for {node_id}, using default CPT")
            self._set_default_cpt(safe_node_id)
            return
        
        # Get fuzzy parameters for this node
        fuzzy_params = self._get_fuzzy_parameters_for_node(node_id)
        print(f"DEBUG: Fuzzy params for {node_id}: {fuzzy_params}")
        
        # Use the mixed parent handler for proper CPT generation
        try:
            print(f"DEBUG: Calling _handle_mixed_parent_cpt for {safe_node_id}")
            self._handle_mixed_parent_cpt(safe_node_id, tactic_id, fuzzy_params)
            
            # Verify what was actually set
            actual_cpt = self.net.get_node_definition(safe_node_id)
            print(f"DEBUG: Final CPT set for {safe_node_id}: {[f'{x:.4f}' for x in actual_cpt[:5]]}")
            
            # Add fuzzy info to node comment
            current_comment = self.net.get_node_description(safe_node_id)
            fuzzy_info = f"\nFuzzy Parameters: {fuzzy_params}"
            base_membership = self.fuzzy_system.get_fuzzy_membership_distribution(tactic_id, **fuzzy_params)
            fuzzy_info += f"\nFuzzy Membership Distribution:"
            states = ["Very_Low", "Low", "Medium", "High", "Very_High"]
            for state, membership in zip(states, base_membership):
                fuzzy_info += f"\n  {state}: {membership:.3f}"
            
            if current_comment:
                updated_comment = current_comment + fuzzy_info
            else:
                updated_comment = fuzzy_info.strip()
            
            self.net.set_node_description(safe_node_id, updated_comment)
            
        except Exception as e:
            print(f"Error setting fuzzy CPT for {node_id}: {e}")
            self._set_default_cpt(safe_node_id)
    
    def _set_default_cpt(self, safe_node_id: str):
        """Set default CPT probabilities for nodes without tactics."""
        parents = self.net.get_parents(safe_node_id)
        num_parents = len(parents)
        
        # Check if this is a tactic node (has 5 states) or regular node (2 states)
        num_outcomes = self.net.get_outcome_count(safe_node_id)
        
        if num_outcomes == 5:
            # This is a fuzzy tactic node but couldn't get fuzzy CPT
            # Use uniform distribution with slight bias toward medium
            if num_parents == 0:
                self.net.set_node_definition(safe_node_id, [0.15, 0.2, 0.3, 0.2, 0.15])
            else:
                # Generate proper CPT for mixed parents
                parent_info = []
                for parent_handle in parents:
                    parent_id = self.net.get_node_id(parent_handle)
                    parent_states = self.net.get_outcome_count(parent_id)
                    parent_info.append(parent_states)
                
                total_combinations = 1
                for states in parent_info:
                    total_combinations *= states
                
                cpt = []
                for combo in range(total_combinations):
                    # For each parent combination, use default fuzzy distribution
                    cpt.extend([0.15, 0.2, 0.3, 0.2, 0.15])
                
                self.net.set_node_definition(safe_node_id, cpt)
        else:
            # Regular binary node
            if num_parents == 0:
                # Prior probability - moderate uncertainty
                self.net.set_node_definition(safe_node_id, [0.7, 0.3])
            else:
                # Get parent state counts for proper CPT generation
                parent_info = []
                for parent_handle in parents:
                    parent_id = self.net.get_node_id(parent_handle)
                    parent_states = self.net.get_outcome_count(parent_id)
                    parent_info.append(parent_states)
                
                total_combinations = 1
                for states in parent_info:
                    total_combinations *= states
                
                cpt = []
                for combo in range(total_combinations):
                    # Decode combination to determine influence
                    temp_combo = combo
                    parent_states = []
                    
                    for num_states in parent_info:
                        parent_states.append(temp_combo % num_states)
                        temp_combo //= num_states
                    
                    # Calculate influence (normalize fuzzy states to 0-1)
                    total_influence = 0.0
                    for state, num_states in zip(parent_states, parent_info):
                        if num_states == 2:
                            influence = state  # 0 or 1
                        else:
                            influence = state / (num_states - 1)  # 0 to 1
                        total_influence += influence
                    
                    avg_influence = total_influence / len(parent_info) if parent_info else 0.5
                    
                    # Simple OR-like behavior with fuzzy influence
                    prob = max(0.1, min(0.9, 0.2 + avg_influence * 0.7))
                    cpt.extend([1.0 - prob, prob])
                
                self.net.set_node_definition(safe_node_id, cpt)
    
    def build(self):
        """Build the Bayesian Network with fuzzy logic integration."""
        safe = lambda x: x.replace("-", "_")
        
        # Create all nodes first
        for nid in self.used_ids:
            sid = safe(nid)
            obj = self.id_to_obj.get(nid)
            label = getattr(obj, "name", nid) if obj else nid
            comment = self._build_node_comment(nid)
            
            # Check if this node has a tactic (should be fuzzy multi-state)
            is_fuzzy_tactic = nid in self.tactic_nodes
            
            self._add_cpt_node(sid, label=label, comment=comment, is_fuzzy_tactic=is_fuzzy_tactic)
        
        # Handle partition groups with improved parent strength configuration
        logic_ids = {lg["node_id"] for lg in self.logic_groups}
        for pg in self.partition_groups:
            if pg["node_id"] in logic_ids:
                continue
            
            parent = pg["node_id"]
            parent_sid = safe(parent)
            for idx, group in enumerate(pg["groups"], start=1):
                inter_orig = f"{parent}_grp{idx}"
                inter_sid = safe(inter_orig)
                comment = f"Partition of {parent}: {group}"
                
                # Create Noisy-MAX gate
                h = self.net.add_node(NodeType.NOISY_MAX, inter_sid)
                self.net.set_node_name(inter_sid, inter_orig)
                self.net.set_node_description(inter_sid, comment)
                
                # Wire each member → intermediate and configure strengths
                for pid in group:
                    parent_safe_id = safe(pid)
                    self.net.add_arc(parent_safe_id, inter_sid)
                    
                    # Configure parent strengths based on parent node type
                    try:
                        parent_states = self.net.get_outcome_count(parent_safe_id)
                        if parent_states == 5:
                            # Fuzzy node - use 5-element strength array
                            self.net.set_noisy_parent_strengths(inter_sid, parent_safe_id, [0, 1, 2, 3, 4])
                        else:
                            # Binary node - use 2-element strength array
                            self.net.set_noisy_parent_strengths(inter_sid, parent_safe_id, [0, 1])
                    except Exception as e:
                        print(f"Warning: Could not configure noisy parent strengths for {pid} -> {inter_sid}: {e}")
                        # Try default binary configuration
                        try:
                            self.net.set_noisy_parent_strengths(inter_sid, parent_safe_id, [0, 1])
                        except:
                            continue
                
                # Wire intermediate → original parent
                self.net.add_arc(inter_sid, parent_sid)
        
        # Handle logic groups with improved mixed-state support
        for lg in self.logic_groups:
            orig_op = lg["node_id"]
            members = lg["members"]
            op_sid = safe(orig_op)
            comment = self._build_node_comment(orig_op)
            label = getattr(self.id_to_obj.get(orig_op), "name", orig_op)
            
            if lg["logic"] == "AND":
                try:
                    h = self.net.add_node(NodeType.CPT, op_sid)
                except pysmile.SMILEException:
                    pass
                
                self.net.set_node_name(op_sid, label)
                if comment:
                    self.net.set_node_description(op_sid, comment)
                
                # Wire parents
                for pid in members:
                    self.net.add_arc(safe(pid), op_sid)
                
                # Build AND CPT with proper mixed-state handling
                parent_states = []
                for pid in members:
                    parent_safe_id = safe(pid)
                    try:
                        states = self.net.get_outcome_count(parent_safe_id)
                        parent_states.append(states)
                    except:
                        parent_states.append(2)  # Default to binary
                
                # Generate CPT for AND logic
                total_combinations = 1
                for states in parent_states:
                    total_combinations *= states
                
                table = []
                for combo in range(total_combinations):
                    # Decode combination
                    temp = combo
                    parent_values = []
                    for states in parent_states:
                        parent_values.append(temp % states)
                        temp //= states
                    
                    # Calculate AND result (minimum of normalized parent values)
                    min_activation = 1.0
                    for i, val in enumerate(parent_values):
                        if parent_states[i] == 5:  # Fuzzy parent
                            activation = val / 4.0  # 0, 0.25, 0.5, 0.75, 1.0
                        else:  # Binary parent
                            activation = float(val)  # 0.0 or 1.0
                        min_activation = min(min_activation, activation)
                    
                    # AND logic: result is minimum of all inputs
                    prob_true = min_activation
                    prob_false = 1.0 - prob_true
                    table.extend([prob_false, prob_true])
                
                self.net.set_node_definition(op_sid, table)
            
            else:  # OR logic with Noisy-MAX
                try:
                    h = self.net.add_node(NodeType.NOISY_MAX, op_sid)
                except pysmile.SMILEException:
                    # Handle existing node
                    existing_handles = [h for h in self.net.get_all_nodes() if self.net.get_node_id(h) == op_sid]
                    if existing_handles:
                        h = existing_handles[0]
                        if self.net.get_node_type(h) != NodeType.NOISY_MAX:
                            self.net.delete_node(op_sid)
                            h = self.net.add_node(NodeType.NOISY_MAX, op_sid)
                    else:
                        h = self.net.add_node(NodeType.NOISY_MAX, op_sid)
                
                self.net.set_node_name(op_sid, label)
                if comment:
                    self.net.set_node_description(op_sid, comment)
                
                # Wire parents and configure strengths
                for pid in members:
                    parent_safe_id = safe(pid)
                    self.net.add_arc(parent_safe_id, op_sid)
                    
                    # Configure Noisy-OR links based on parent type
                    try:
                        parent_states = self.net.get_outcome_count(parent_safe_id)
                        if parent_states == 5:
                            # Fuzzy node - use 5-element strength array
                            self.net.set_noisy_parent_strengths(op_sid, parent_safe_id, [0, 1, 2, 3, 4])
                        else:
                            # Binary node - use 2-element strength array
                            self.net.set_noisy_parent_strengths(op_sid, parent_safe_id, [0, 1])
                    except Exception as e:
                        print(f"Warning: Could not configure noisy parent strengths for {pid} in logic group: {e}")
                        # Try default binary configuration
                        try:
                            self.net.set_noisy_parent_strengths(op_sid, parent_safe_id, [0, 1])
                        except:
                            continue
        
        # Handle divorce groups with proper CPT generation
        partitioned = {pg["node_id"] for pg in self.partition_groups}
        divorce_children = {
            c for dg in self.divorce_groups
            if dg["node_id"] not in partitioned
            for c in dg["children"]
        }
        
        for dg in self.divorce_groups:
            children = [c for c in dg["children"] if c not in partitioned]
            if not children:
                continue
            
            parent = dg["node_id"]
            parent_sid = safe(parent)
            
            hub_orig = f"{parent}_div"
            hub_sid = safe(hub_orig)
            comment = f"Divorce of {parent}: splits to {children}"
            
            # Create binary CPT hub
            h = self._add_cpt_node(hub_sid, label=hub_orig, comment=comment, is_fuzzy_tactic=False)
            self.net.add_arc(parent_sid, hub_sid)
            
            # Hub → each child with proper CPT based on child type
            for cid in children:
                c_sid = safe(cid)
                self.net.add_arc(hub_sid, c_sid)
                
                # Get all parents of this child to build proper CPT
                all_parents = self.net.get_parents(c_sid)
                parent_info = []
                hub_parent_index = None
                
                for i, parent_handle in enumerate(all_parents):
                    parent_id = self.net.get_node_id(parent_handle)
                    parent_states = self.net.get_outcome_count(parent_id)
                    parent_info.append(parent_states)
                    
                    if parent_id == hub_sid:
                        hub_parent_index = i
                
                if hub_parent_index is None:
                    continue  # Hub not found among parents
                
                # Calculate total combinations
                total_combinations = 1
                for states in parent_info:
                    total_combinations *= states
                
                child_states = self.net.get_outcome_count(c_sid)
                
                if child_states == 5:
                    # Fuzzy child - create proper 5-state CPT
                    cpt = []
                    for combo in range(total_combinations):
                        # Decode combination
                        temp = combo
                        parent_states = []
                        for states in parent_info:
                            parent_states.append(temp % states)
                            temp //= states
                        
                        # Get hub value
                        hub_value = parent_states[hub_parent_index]
                        
                        if hub_value == 0:
                            # Hub = False: bias toward lower states
                            cpt.extend([0.4, 0.3, 0.2, 0.08, 0.02])
                        else:
                            # Hub = True: bias toward higher states
                            cpt.extend([0.02, 0.08, 0.2, 0.3, 0.4])
                    
                    self.net.set_node_definition(c_sid, cpt)
                    
                elif child_states == 2:
                    # Binary child - create proper 2-state CPT
                    cpt = []
                    for combo in range(total_combinations):
                        # Decode combination
                        temp = combo
                        parent_states = []
                        for states in parent_info:
                            parent_states.append(temp % states)
                            temp //= states
                        
                        # Get hub value
                        hub_value = parent_states[hub_parent_index]
                        
                        if hub_value == 0:
                            # Hub = False
                            cpt.extend([1.0, 0.0])
                        else:
                            # Hub = True
                            cpt.extend([0.0, 1.0])
                    
                    self.net.set_node_definition(c_sid, cpt)
        
        # Add remaining edges with validation
        clean_edges = []
        for e in self.graph_edges:
            if (isinstance(e, (tuple, list)) and len(e) == 2 and 
                isinstance(e[0], str) and isinstance(e[1], str)):
                clean_edges.append((e[0], e[1]))
        self.graph_edges = clean_edges
        
        valid_nodes = set()
        for handle in self.net.get_all_nodes():
            valid_nodes.add(self.net.get_node_id(handle))
        
        # Track covered edges to avoid duplicates
        covered = set()
        for pg in self.partition_groups:
            for grp in pg["groups"]:
                for pid in grp:
                    covered.add((pid, pg["node_id"]))
        for lg in self.logic_groups:
            for pid in lg["members"]:
                covered.add((pid, lg["node_id"]))
        for dg in self.divorce_groups:
            for cid in dg["children"]:
                covered.add((dg["node_id"], cid))
        
        # Add remaining graph edges
        for s, t in self.graph_edges:
            ks, kt = safe(s), safe(t)
            if kt in divorce_children:
                continue
            if (s, t) in covered:
                continue
            if ks not in valid_nodes or kt not in valid_nodes:
                continue
            try:
                self.net.add_arc(ks, kt)
            except pysmile.SMILEException as ex:
                print(f"Could not add arc {ks}→{kt}: {ex}")
        
        # Set CPT probabilities using fuzzy logic
        self._set_all_cpts()
        
        # Layout the network
        self._layout_network()
        
        return self.net
    
    def _set_all_cpts(self):
        """Set CPT probabilities for all nodes, using fuzzy logic where applicable."""
        for node_id in self.used_ids:
            safe_node_id = node_id.replace("-", "_")
            
            # Skip non-CPT nodes
            try:
                if self.net.get_node_type(safe_node_id) != NodeType.CPT:
                    continue
            except:
                continue
            
            # Always set fuzzy CPT for tactic nodes, even if already defined by group handlers
            if node_id in self.tactic_nodes:
                print(f"DEBUG: Force setting fuzzy CPT for tactic node {node_id} (overriding any existing definition)")
                self._set_fuzzy_cpt(node_id)
            else:
                # For non-tactic nodes, skip if already set by logic/partition/divorce handling
                try:
                    existing_def = self.net.get_node_definition(safe_node_id)
                    if existing_def and len(existing_def) > 0:
                        continue
                except:
                    pass
                
                self._set_default_cpt(safe_node_id)
    
    def _layout_network(self):
        """Layout the network nodes spatially."""
        from collections import deque, defaultdict
        
        safe = lambda x: x.replace("-", "_")
        
        # Build adjacency list
        arcs = []
        logic_ids = {lg["node_id"] for lg in self.logic_groups}
        
        # Collect all arcs
        for pg in self.partition_groups:
            if pg["node_id"] not in logic_ids:
                p = safe(pg["node_id"])
                for idx, grp in enumerate(pg["groups"], 1):
                    inter = safe(f"{pg['node_id']}_grp{idx}")
                    for m in grp:
                        arcs.append((safe(m), inter))
                    arcs.append((inter, p))
        
        for lg in self.logic_groups:
            op = safe(lg["node_id"])
            for m in lg["members"]:
                arcs.append((safe(m), op))
        
        for dg in self.divorce_groups:
            p = safe(dg["node_id"])
            hub = safe(f"{dg['node_id']}_div")
            arcs.append((p, hub))
            for c in dg["children"]:
                arcs.append((hub, safe(c)))
        
        for s, t in self.graph_edges:
            arcs.append((safe(s), safe(t)))
        
        # Build children map
        children = defaultdict(list)
        incoming = set()
        for s, t in arcs:
            children[s].append(t)
            incoming.add(t)
        
        # Find roots and compute levels
        handles = self.net.get_all_nodes()
        handle_by_id = {self.net.get_node_id(h): h for h in handles}
        all_ids = set(handle_by_id)
        roots = [n for n in all_ids if n not in incoming] or [next(iter(all_ids))]
        
        # BFS for levels
        level = {}
        q = deque((r, 0) for r in roots)
        while q:
            nid, d = q.popleft()
            if nid in level:
                continue
            level[nid] = d
            for c in children.get(nid, []):
                q.append((c, d + 1))
        
        # Group by level
        by_level = defaultdict(list)
        for nid, d in level.items():
            by_level[d].append(nid)
        
        # Layout parameters
        node_w, node_h = 120, 60
        h_gap, v_gap = 40, 100
        left_margin, top_margin = 50, 50
        
        # Compute uniform width
        max_per_row = max(len(grp) for grp in by_level.values()) if by_level else 1
        total_w = max_per_row * (node_w + h_gap) - h_gap
        
        # Position nodes
        for d in sorted(by_level):
            row = sorted(by_level[d])
            n = len(row)
            row_w = n * (node_w + h_gap) - h_gap if n > 0 else 0
            x0 = left_margin + (total_w - row_w) / 2
            y = top_margin + d * (node_h + v_gap)
            
            for i, nid in enumerate(row):
                if nid in handle_by_id:
                    h = handle_by_id[nid]
                    x1 = x0 + i * (node_w + h_gap)
                    y1 = y
                    x2, y2 = x1 + node_w, y1 + node_h
                    self.net.set_node_position(h, int(x1), int(y1), int(x2), int(y2))
    
    def write_xdsl(self, filename):
        """Write the network to an XDSL file."""
        self.net.write_file(filename)
    
    def set_custom_fuzzy_params(self, node_id: str, params: Dict[str, float]):
        """Set custom fuzzy parameters for a specific node."""
        self.fuzzy_params[node_id] = params
    
    def get_node_fuzzy_info(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Get fuzzy information for a node."""
        if node_id not in self.tactic_nodes:
            return None
        
        tactic_id = self.tactic_nodes[node_id]
        params = self._get_fuzzy_parameters_for_node(node_id)
        base_membership = self.fuzzy_system.get_fuzzy_membership_distribution(tactic_id, **params)
        
        return {
            "tactic_id": tactic_id,
            "tactic_name": self.fuzzy_system.tactic_definitions.get(tactic_id, tactic_id),
            "fuzzy_parameters": params,
            "fuzzy_states": self.fuzzy_system.get_fuzzy_states(tactic_id),
            "membership_distribution": base_membership,
            "base_success_probability": self.fuzzy_system.get_fuzzy_probability(tactic_id, **params)
        }