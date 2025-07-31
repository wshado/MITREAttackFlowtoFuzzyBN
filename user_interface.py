"""
Updated user_interface.py that integrates the fuzzy MITRE ATT&CK tactics system
with the existing Bayesian Network creation workflow.
"""

import os, sys, re
from bn_creator.attack_flow_parser import AttackFlowProcessor
from bn_creator.grouping_util import GroupingUtil
# UPDATED: Import fuzzy-enhanced BN builder instead of original
from bn_creator.fuzzy_bn_integration  import FuzzyBNBuilder
from bn_creator.fuzzy_tactics_system import FuzzyTacticsSystem
from dashboard_generator import GrafanaDashboardGenerator


class UserInterface:
    def __init__(self, corpus_folder="downloaded_attack_flow_jsons"):
        self.processor = AttackFlowProcessor()
        self.corpus_folder = corpus_folder
        self.fuzzy_system = FuzzyTacticsSystem()  # Initialize fuzzy system

    def list_corpus_files(self):
        all_files = [f for f in os.listdir(self.corpus_folder) if f.endswith(".json")]
        if not all_files:
            print(" No .json files found in corpus folder.")
            exit(1)
        return all_files

    def select_file(self, all_files):
        print("Available corpus files:")
        for idx, f in enumerate(all_files, start=1):
            print(f"{idx}. {f}")

        try:
            choice = int(input("Select a file by number: "))
            if 1 <= choice <= len(all_files):
                selected_file = all_files[choice - 1]
            else:
                print("Invalid selection.")
                exit(1)
        except ValueError:
            print("Please enter a valid number.")
            exit(1)

        selected_path = os.path.join(self.corpus_folder, selected_file)
        print(f"\nYou selected: {selected_file}")
        print(f"Full path: {selected_path}")
        return selected_path

    def get_security_posture_input(self):
        """Get security posture input from user to customize fuzzy parameters."""
        print("\n=== Security Posture Configuration ===")
        print("This will adjust the fuzzy logic parameters based on your organization's security maturity.")
        print("Options:")
        print("  1. Low    - Minimal security controls, limited monitoring")
        print("  2. Medium - Standard security controls, moderate monitoring") 
        print("  3. High   - Advanced security controls, comprehensive monitoring")
        
        while True:
            try:
                choice = input("Select your organization's security posture (1-3) [default: 2]: ").strip()
                if not choice:
                    return "medium"
                
                choice_int = int(choice)
                if choice_int == 1:
                    return "low"
                elif choice_int == 2:
                    return "medium"
                elif choice_int == 3:
                    return "high"
                else:
                    print("Please enter 1, 2, or 3.")
            except ValueError:
                print("Please enter a valid number.")

    def configure_fuzzy_parameters(self, used_ids, id_to_obj, security_posture="medium"):
        """Configure fuzzy parameters based on security posture and node characteristics."""
        fuzzy_params = {}
        
        # Security posture adjustments
        posture_adjustments = {
            "low": {
                "detection_difficulty": -20,
                "skill_requirement": -15,
                "resource_availability": +15,
                "monitoring_coverage": 25,
                "security_hardening": 30,
                "network_segmentation": 25
            },
            "medium": {
                "detection_difficulty": 0,
                "skill_requirement": 0,
                "resource_availability": 0,
                "monitoring_coverage": 50,
                "security_hardening": 50,
                "network_segmentation": 50
            },
            "high": {
                "detection_difficulty": +25,
                "skill_requirement": +10,
                "resource_availability": -10,
                "monitoring_coverage": 80,
                "security_hardening": 75,
                "network_segmentation": 80
            }
        }
        
        base_adjustments = posture_adjustments.get(security_posture, posture_adjustments["medium"])
        
        for node_id in used_ids:
            obj = id_to_obj.get(node_id)
            if not obj or not hasattr(obj, 'tactic_id') or not obj.tactic_id:
                continue
            
            tactic_id = obj.tactic_id
            
            # Get default parameters for this tactic
            params = self.fuzzy_system.get_default_fuzzy_params(tactic_id)
            
            # Apply security posture adjustments
            for param, adjustment in base_adjustments.items():
                if param in params:
                    if param in ["detection_difficulty", "skill_requirement", "resource_availability"]:
                        # These are relative adjustments
                        params[param] = max(0, min(100, params[param] + adjustment))
                    else:
                        # These are absolute values
                        params[param] = adjustment
            
            # Technique-specific adjustments based on description/name
            if hasattr(obj, 'name') and obj.name:
                name_lower = obj.name.lower()
                
                # Advanced techniques require higher skill
                if any(x in name_lower for x in ['rootkit', 'kernel', 'driver', 'firmware']):
                    params['skill_requirement'] = min(100, params.get('skill_requirement', 50) + 25)
                
                # Common techniques are easier
                elif any(x in name_lower for x in ['phishing', 'script', 'macro', 'registry']):
                    params['skill_requirement'] = max(0, params.get('skill_requirement', 50) - 15)
                
                # Stealth techniques are harder to detect
                if any(x in name_lower for x in ['stealth', 'hidden', 'covert', 'living off']):
                    params['detection_difficulty'] = min(100, params.get('detection_difficulty', 50) + 20)
            
            # Technique ID specific adjustments
            if hasattr(obj, 'technique_id') and obj.technique_id:
                technique_id = obj.technique_id.upper()
                
                # Well-known, commonly detected techniques
                common_techniques = ['T1566', 'T1059', 'T1003', 'T1055', 'T1083']
                if any(technique_id.startswith(t) for t in common_techniques):
                    params['detection_difficulty'] = max(0, params.get('detection_difficulty', 50) - 10)
                
                # Advanced, less common techniques
                advanced_techniques = ['T1014', 'T1542', 'T1601', 'T1014']
                if any(technique_id.startswith(t) for t in advanced_techniques):
                    params['skill_requirement'] = min(100, params.get('skill_requirement', 50) + 20)
                    params['detection_difficulty'] = min(100, params.get('detection_difficulty', 50) + 15)
            
            fuzzy_params[node_id] = params
        
        return fuzzy_params

    def print_fuzzy_analysis(self, builder, used_ids):
        """Print analysis of fuzzy parameters and probabilities."""
        print("\n" + "="*60)
        print("FUZZY LOGIC ANALYSIS")
        print("="*60)
        
        tactic_summary = {}
        
        for node_id in used_ids:
            fuzzy_info = builder.get_node_fuzzy_info(node_id)
            if fuzzy_info:
                tactic_name = fuzzy_info['tactic_name']
                membership_dist = fuzzy_info['membership_distribution']
                
                if tactic_name not in tactic_summary:
                    tactic_summary[tactic_name] = []
                tactic_summary[tactic_name].append(membership_dist)
                
                obj = builder.id_to_obj.get(node_id)
                node_name = getattr(obj, 'name', node_id) if obj else node_id
                
                print(f"\nNode: {node_name}")
                print(f"  Tactic: {tactic_name}")
                print(f"  Fuzzy State Distribution:")
                
                states = fuzzy_info['fuzzy_states']
                for state, membership in zip(states, membership_dist):
                    bar_length = int(membership * 20)  # Scale to 20 characters
                    bar = "█" * bar_length + "░" * (20 - bar_length)
                    print(f"    {state:10s}: {membership:.3f} |{bar}|")
                
                # Show most likely state
                max_idx = membership_dist.index(max(membership_dist))
                most_likely_state = states[max_idx]
                print(f"  Most Likely State: {most_likely_state} ({membership_dist[max_idx]:.3f})")
        
        print(f"\n{'='*60}")
        print("TACTIC SUMMARY")
        print("="*60)
        
        for tactic_name, membership_lists in tactic_summary.items():
            print(f"\n{tactic_name}:")
            print(f"  Techniques: {len(membership_lists)}")
            
            # Calculate average membership distribution
            avg_membership = [0.0] * 5
            for membership_list in membership_lists:
                for i, val in enumerate(membership_list):
                    avg_membership[i] += val
            avg_membership = [val / len(membership_lists) for val in avg_membership]
            
            print(f"  Average Distribution:")
            states = ["Very_Low", "Low", "Medium", "High", "Very_High"]
            for state, avg_val in zip(states, avg_membership):
                bar_length = int(avg_val * 15)
                bar = "█" * bar_length + "░" * (15 - bar_length)
                print(f"    {state:10s}: {avg_val:.3f} |{bar}|")

    def run(self):
        all_files = self.list_corpus_files()
        selected_path = self.select_file(all_files)

        # Process the attack flow file
        out_name, new_bundle, used_ids, parent_map, child_map, condition_nodes, recommendations, id_to_obj, relationships = self.processor.process_file(selected_path)

        return new_bundle, used_ids, parent_map, child_map, condition_nodes, recommendations, id_to_obj, relationships

if __name__ == "__main__":
    ui = UserInterface()
    new_bundle, used_ids, parent_map, child_map, condition_nodes, recommendations, id_to_obj, relationships = ui.run()
    
    # Instantiate the grouping utility
    util = GroupingUtil(
        parent_map=parent_map,
        child_map=child_map,
        recommendations=recommendations,
        id_to_obj=id_to_obj
    )
    
    graph_edges = [(src['id'], tgt['id']) for src, tgt in relationships]
    print(f"Graph edges: {len(graph_edges)} edges found")
    
    # Compute partition and divorce groups
    partitioned = util.get_partition_groups()
    divorced = util.get_divorce_groups()
    logic_groups = util.get_logic_groups()
    
    print(f"Partitioned groups: {len(partitioned)}")
    print(f"Divorced groups: {len(divorced)}")
    print(f"Logic groups: {len(logic_groups)}")
    
    # Get security posture configuration
    security_posture = ui.get_security_posture_input()
    print(f"\nSelected security posture: {security_posture}")
    
    # Configure fuzzy parameters based on security posture
    print("Configuring fuzzy parameters based on MITRE ATT&CK tactics...")
    fuzzy_params = ui.configure_fuzzy_parameters(used_ids, id_to_obj, security_posture)
    
    # Count nodes with tactics
    tactic_nodes = [node_id for node_id in used_ids 
                   if node_id in fuzzy_params]
    print(f"Found {len(tactic_nodes)} nodes with MITRE ATT&CK tactics")
    
    # UPDATED: Build Bayesian Network using fuzzy-enhanced builder
    print("Building Bayesian Network with fuzzy logic integration...")
    builder = FuzzyBNBuilder(
        used_ids=used_ids,
        graph_edges=graph_edges,
        partition_groups=partitioned,
        divorce_groups=divorced,  
        logic_groups=logic_groups,
        recommendations=recommendations,
        id_to_obj=id_to_obj,
        parent_map=parent_map,
        child_map=child_map,
        fuzzy_params=fuzzy_params  # NEW: Add fuzzy parameters
    )
    
    net = builder.build()
    builder.write_xdsl("attack_flow_model.xdsl")
    print("Attack flow Bayesian Network with fuzzy logic available at attack_flow_model.xdsl")
    
    # Print fuzzy analysis
    ui.print_fuzzy_analysis(builder, used_ids)
    
    # Ask if user wants detailed fuzzy information
    show_details = input("\nShow detailed fuzzy parameter information? [y/N]: ").strip().lower()
    if show_details == "y":
        print("\n" + "="*80)
        print("DETAILED FUZZY PARAMETER INFORMATION")
        print("="*80)
        
        for node_id in used_ids:
            fuzzy_info = builder.get_node_fuzzy_info(node_id)
            if fuzzy_info:
                obj = id_to_obj.get(node_id)
                node_name = getattr(obj, 'name', node_id) if obj else node_id
                technique_id = getattr(obj, 'technique_id', 'N/A') if obj else 'N/A'
                
                print(f"\n{'-'*60}")
                print(f"Node ID: {node_id}")
                print(f"Name: {node_name}")
                print(f"Technique ID: {technique_id}")
                print(f"Tactic: {fuzzy_info['tactic_name']} ({fuzzy_info['tactic_id']})")
                print(f"Base Success Probability: {fuzzy_info['base_success_probability']:.4f}")
                
                print("Fuzzy State Distribution:")
                states = fuzzy_info['fuzzy_states']
                membership_dist = fuzzy_info['membership_distribution']
                for state, membership in zip(states, membership_dist):
                    bar_length = int(membership * 30)
                    bar = "█" * bar_length + "░" * (30 - bar_length)
                    print(f"  {state:10s}: {membership:.4f} |{bar}|")
                
                print("Fuzzy Parameters:")
                for param, value in sorted(fuzzy_info['fuzzy_parameters'].items()):
                    print(f"  {param.replace('_', ' ').title()}: {value:.1f}")

    print("\n" + "="*80)
    print("BAYESIAN NETWORK CREATION COMPLETE")
    print("="*80)
    print(f"✅ XDSL file created: attack_flow_model.xdsl")
    print(f"✅ Network contains {len(used_ids)} nodes:")
    fuzzy_count = len([nid for nid in used_ids if builder.get_node_fuzzy_info(nid)])
    binary_count = len(used_ids) - fuzzy_count
    print(f"   - {fuzzy_count} fuzzy nodes (5-state)")
    print(f"   - {binary_count} binary nodes (2-state)")
    
    print("\n" + "="*80)
    print("NEXT STEP: START THE WEB SERVICE")
    print("="*80)
    print("🚀 Please start the BN Web Service in a SEPARATE terminal:")
    print("")
    print("   python flask_app/bn-ws.py")
    print("")
    print("Then open your browser to: http://localhost:8000")
    print("")
    print("💡 The web service supports:")
    print("   - All node states (not just true/false)")
    print("   - Fuzzy nodes: Very_Low, Low, Medium, High, Very_High")
    print("   - Binary nodes: False, True")
    print("   - Enhanced belief display with state labels and probabilities")
    print("")
    print("📊 You can set evidence and observe real-time belief updates!")
    
    # Wait for user to start Flask app
    input("\n🔄 Press ENTER when you have started the Flask app and it's running...")
    
    # Now prompt for Grafana dashboard creation
    print("\n" + "="*80)
    print("OPTIONAL: GRAFANA DASHBOARD CREATION")
    print("="*80)
    
    create_dashboard = input("📈 Would you like to create a Grafana dashboard now? [y/N]: ").strip().lower()
    
    if create_dashboard == "y":
        print("\n🔧 Setting up Grafana dashboard...")
        print("")
        print("Make sure you have:")
        print("   - Grafana running at http://localhost:3000")
        print("   - Prometheus datasource configured with UID 'Prometheus'")
        print("")
        
        # Get Grafana API key from user
        api_key = input("Enter your Grafana API key (or press ENTER for default): ").strip()
        if not api_key:
            api_key = "eyJrIjoiQ1VpMXp6blBJbnpSZktHaFpteFNKSHM3dzVhcFRMTXciLCJuIjoiRlVDS0pZT1VUT08iLCJpZCI6MX0="
        
        try:
            from dashboard_generator import GrafanaDashboardGenerator
            gen = GrafanaDashboardGenerator(
                grafana_url="http://localhost:3000",
                api_key=api_key,
                prom_node_list_url="http://localhost:8000",
                xdsl_path="attack_flow_model.xdsl",
                prometheus_datasource_uid="Prometheus",
                node_prefixes=None,  # Include ALL nodes
                panels_per_row=4
            )
            
            print("🚀 Creating dashboard...")
            gen.generate_dashboard()
            print(f"✅ Dashboard created successfully!")
            print(f"🌐 View at: http://localhost:3000")
            print("")
            print("📊 The dashboard shows:")
            print("   - Mission risk assessment panel")
            print("   - Individual node beliefs (e.g., 'Medium: 0.400', 'High: 0.588')")
            print("   - Color-coded risk visualization")
            print("   - Real-time updates every 5 seconds")
            
        except Exception as e:
            print(f"⚠️ Error creating dashboard: {e}")
            print("")
            print("You can create it manually later with:")
            print("")
            print("from dashboard_generator import GrafanaDashboardGenerator")
            print("gen = GrafanaDashboardGenerator(")
            print("    grafana_url='http://localhost:3000',")
            print(f"    api_key='{api_key}',")
            print("    prom_node_list_url='http://localhost:8000',")
            print("    xdsl_path='attack_flow_model.xdsl',")
            print("    prometheus_datasource_uid='Prometheus')")
            print("gen.generate_dashboard()")
    
    else:
        print("\n📝 Dashboard creation skipped.")
        print("You can create it later using the dashboard_generator.py script.")
    print(f"✓ Used {security_posture} security posture configuration")
    print(f"✓ Generated attack_flow_model.xdsl with enhanced probability distributions")
    print("✓ Ready for analysis and monitoring")