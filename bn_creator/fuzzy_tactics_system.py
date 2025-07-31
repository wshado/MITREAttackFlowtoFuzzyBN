import numpy as np
from typing import Dict, List, Tuple, Optional
import skfuzzy as fuzz
from skfuzzy import control as ctrl


class FuzzyTacticsSystem:
    """
    Creates fuzzy membership functions and fuzzy rules for MITRE ATT&CK tactics.
    Generates fuzzy-based probability distributions for Bayesian Network nodes.
    """
    
    def __init__(self):
        self.tactic_systems = {}
        self.tactic_definitions = {
            "TA0043": "Reconnaissance",
            "TA0042": "Resource Development", 
            "TA0001": "Initial Access",
            "TA0002": "Execution",
            "TA0003": "Persistence",
            "TA0004": "Privilege Escalation",
            "TA0005": "Defense Evasion",
            "TA0006": "Credential Access",
            "TA0007": "Discovery",
            "TA0008": "Lateral Movement",
            "TA0009": "Collection",
            "TA0011": "Command and Control",
            "TA0010": "Exfiltration",
            "TA0040": "Impact"
        }
        self._initialize_fuzzy_systems()
    
    def _create_common_inputs(self) -> Dict[str, ctrl.Antecedent]:
        """Create common input variables used across tactics."""
        # Detection difficulty (0-100)
        detection_difficulty = ctrl.Antecedent(np.arange(0, 101, 1), 'detection_difficulty')
        detection_difficulty['low'] = fuzz.trimf(detection_difficulty.universe, [0, 0, 40])
        detection_difficulty['medium'] = fuzz.trimf(detection_difficulty.universe, [20, 50, 80])
        detection_difficulty['high'] = fuzz.trimf(detection_difficulty.universe, [60, 100, 100])
        
        # Skill requirement (0-100)
        skill_requirement = ctrl.Antecedent(np.arange(0, 101, 1), 'skill_requirement')
        skill_requirement['novice'] = fuzz.trimf(skill_requirement.universe, [0, 0, 30])
        skill_requirement['intermediate'] = fuzz.trimf(skill_requirement.universe, [20, 50, 80])
        skill_requirement['expert'] = fuzz.trimf(skill_requirement.universe, [70, 100, 100])
        
        # Resource availability (0-100)
        resource_availability = ctrl.Antecedent(np.arange(0, 101, 1), 'resource_availability')
        resource_availability['limited'] = fuzz.trimf(resource_availability.universe, [0, 0, 40])
        resource_availability['moderate'] = fuzz.trimf(resource_availability.universe, [30, 50, 70])
        resource_availability['abundant'] = fuzz.trimf(resource_availability.universe, [60, 100, 100])
        
        # Time constraint (0-100, where 0 is no time pressure, 100 is extreme time pressure)
        time_constraint = ctrl.Antecedent(np.arange(0, 101, 1), 'time_constraint')
        time_constraint['relaxed'] = fuzz.trimf(time_constraint.universe, [0, 0, 40])
        time_constraint['moderate'] = fuzz.trimf(time_constraint.universe, [30, 50, 70])
        time_constraint['urgent'] = fuzz.trimf(time_constraint.universe, [60, 100, 100])
        
        return {
            'detection_difficulty': detection_difficulty,
            'skill_requirement': skill_requirement,
            'resource_availability': resource_availability,
            'time_constraint': time_constraint
        }
    
    def _create_success_probability_output(self) -> ctrl.Consequent:
        """Create the output variable for success probability."""
        success_prob = ctrl.Consequent(np.arange(0, 101, 1), 'success_probability')
        success_prob['very_low'] = fuzz.trimf(success_prob.universe, [0, 0, 20])
        success_prob['low'] = fuzz.trimf(success_prob.universe, [10, 25, 40])
        success_prob['medium'] = fuzz.trimf(success_prob.universe, [30, 50, 70])
        success_prob['high'] = fuzz.trimf(success_prob.universe, [60, 75, 90])
        success_prob['very_high'] = fuzz.trimf(success_prob.universe, [80, 100, 100])
        return success_prob
    
    def _create_reconnaissance_system(self) -> ctrl.ControlSystem:
        """Create fuzzy system for Reconnaissance (TA0043)."""
        inputs = self._create_common_inputs()
        output = self._create_success_probability_output()
        
        # Reconnaissance-specific input
        target_exposure = ctrl.Antecedent(np.arange(0, 101, 1), 'target_exposure')
        target_exposure['minimal'] = fuzz.trimf(target_exposure.universe, [0, 0, 30])
        target_exposure['moderate'] = fuzz.trimf(target_exposure.universe, [20, 50, 80])
        target_exposure['extensive'] = fuzz.trimf(target_exposure.universe, [70, 100, 100])
        
        rules = [
            ctrl.Rule(target_exposure['extensive'] & inputs['skill_requirement']['novice'], output['high']),
            ctrl.Rule(target_exposure['moderate'] & inputs['skill_requirement']['intermediate'], output['medium']),
            ctrl.Rule(target_exposure['minimal'] & inputs['skill_requirement']['expert'], output['medium']),
            ctrl.Rule(target_exposure['minimal'] & inputs['skill_requirement']['novice'], output['low']),
            ctrl.Rule(inputs['detection_difficulty']['low'] & target_exposure['extensive'], output['very_high']),
            ctrl.Rule(inputs['detection_difficulty']['high'] & target_exposure['minimal'], output['very_low']),
        ]
        
        return ctrl.ControlSystem(rules)
    
    def _create_resource_development_system(self) -> ctrl.ControlSystem:
        """Create fuzzy system for Resource Development (TA0042)."""
        inputs = self._create_common_inputs()
        output = self._create_success_probability_output()
        
        rules = [
            ctrl.Rule(inputs['resource_availability']['abundant'] & inputs['skill_requirement']['expert'], output['very_high']),
            ctrl.Rule(inputs['resource_availability']['moderate'] & inputs['skill_requirement']['intermediate'], output['high']),
            ctrl.Rule(inputs['resource_availability']['limited'] & inputs['skill_requirement']['novice'], output['low']),
            ctrl.Rule(inputs['time_constraint']['urgent'] & inputs['resource_availability']['limited'], output['very_low']),
            ctrl.Rule(inputs['time_constraint']['relaxed'] & inputs['resource_availability']['abundant'], output['very_high']),
        ]
        
        return ctrl.ControlSystem(rules)
    
    def _create_initial_access_system(self) -> ctrl.ControlSystem:
        """Create fuzzy system for Initial Access (TA0001)."""
        inputs = self._create_common_inputs()
        output = self._create_success_probability_output()
        
        # Initial Access specific
        attack_surface = ctrl.Antecedent(np.arange(0, 101, 1), 'attack_surface')
        attack_surface['small'] = fuzz.trimf(attack_surface.universe, [0, 0, 30])
        attack_surface['medium'] = fuzz.trimf(attack_surface.universe, [20, 50, 80])
        attack_surface['large'] = fuzz.trimf(attack_surface.universe, [70, 100, 100])
        
        rules = [
            ctrl.Rule(attack_surface['large'] & inputs['detection_difficulty']['high'], output['high']),
            ctrl.Rule(attack_surface['small'] & inputs['skill_requirement']['expert'], output['medium']),
            ctrl.Rule(attack_surface['medium'] & inputs['skill_requirement']['intermediate'], output['medium']),
            ctrl.Rule(attack_surface['small'] & inputs['skill_requirement']['novice'], output['very_low']),
            ctrl.Rule(inputs['detection_difficulty']['low'] & attack_surface['large'], output['very_high']),
        ]
        
        return ctrl.ControlSystem(rules)
    
    def _create_execution_system(self) -> ctrl.ControlSystem:
        """Create fuzzy system for Execution (TA0002)."""
        # Create only the inputs that Execution actually uses
        detection_difficulty = ctrl.Antecedent(np.arange(0, 101, 1), 'detection_difficulty')
        detection_difficulty['low'] = fuzz.trimf(detection_difficulty.universe, [0, 0, 40])
        detection_difficulty['medium'] = fuzz.trimf(detection_difficulty.universe, [20, 50, 80])
        detection_difficulty['high'] = fuzz.trimf(detection_difficulty.universe, [60, 100, 100])
        
        skill_requirement = ctrl.Antecedent(np.arange(0, 101, 1), 'skill_requirement')
        skill_requirement['novice'] = fuzz.trimf(skill_requirement.universe, [0, 0, 30])
        skill_requirement['intermediate'] = fuzz.trimf(skill_requirement.universe, [20, 50, 80])
        skill_requirement['expert'] = fuzz.trimf(skill_requirement.universe, [70, 100, 100])
        
        output = self._create_success_probability_output()
        
        # Execution happens after initial access, so generally higher success
        rules = [
            ctrl.Rule(skill_requirement['expert'] & detection_difficulty['high'], output['very_high']),
            ctrl.Rule(skill_requirement['intermediate'] & detection_difficulty['medium'], output['high']),
            ctrl.Rule(skill_requirement['novice'] & detection_difficulty['low'], output['medium']),
            ctrl.Rule(detection_difficulty['low'], output['high']),
        ]
        
        return ctrl.ControlSystem(rules)
    
    def _create_persistence_system(self) -> ctrl.ControlSystem:
        """Create fuzzy system for Persistence (TA0003)."""
        inputs = self._create_common_inputs()
        output = self._create_success_probability_output()
        
        system_complexity = ctrl.Antecedent(np.arange(0, 101, 1), 'system_complexity')
        system_complexity['simple'] = fuzz.trimf(system_complexity.universe, [0, 0, 40])
        system_complexity['moderate'] = fuzz.trimf(system_complexity.universe, [30, 50, 70])
        system_complexity['complex'] = fuzz.trimf(system_complexity.universe, [60, 100, 100])
        
        rules = [
            ctrl.Rule(system_complexity['simple'] & inputs['skill_requirement']['intermediate'], output['high']),
            ctrl.Rule(system_complexity['complex'] & inputs['skill_requirement']['expert'], output['medium']),
            ctrl.Rule(inputs['detection_difficulty']['high'] & system_complexity['moderate'], output['high']),
            ctrl.Rule(inputs['detection_difficulty']['low'] & system_complexity['simple'], output['medium']),
            ctrl.Rule(system_complexity['complex'] & inputs['skill_requirement']['novice'], output['very_low']),
        ]
        
        return ctrl.ControlSystem(rules)
    
    def _create_privilege_escalation_system(self) -> ctrl.ControlSystem:
        """Create fuzzy system for Privilege Escalation (TA0004)."""
        inputs = self._create_common_inputs()
        output = self._create_success_probability_output()
        
        security_hardening = ctrl.Antecedent(np.arange(0, 101, 1), 'security_hardening')
        security_hardening['weak'] = fuzz.trimf(security_hardening.universe, [0, 0, 30])
        security_hardening['moderate'] = fuzz.trimf(security_hardening.universe, [20, 50, 80])
        security_hardening['strong'] = fuzz.trimf(security_hardening.universe, [70, 100, 100])
        
        rules = [
            ctrl.Rule(security_hardening['weak'] & inputs['skill_requirement']['intermediate'], output['very_high']),
            ctrl.Rule(security_hardening['moderate'] & inputs['skill_requirement']['expert'], output['high']),
            ctrl.Rule(security_hardening['strong'] & inputs['skill_requirement']['expert'], output['medium']),
            ctrl.Rule(security_hardening['strong'] & inputs['skill_requirement']['novice'], output['very_low']),
            ctrl.Rule(inputs['detection_difficulty']['high'] & security_hardening['weak'], output['very_high']),
        ]
        
        return ctrl.ControlSystem(rules)
    
    def _create_defense_evasion_system(self) -> ctrl.ControlSystem:
        """Create fuzzy system for Defense Evasion (TA0005)."""
        inputs = self._create_common_inputs()
        output = self._create_success_probability_output()
        
        monitoring_coverage = ctrl.Antecedent(np.arange(0, 101, 1), 'monitoring_coverage')
        monitoring_coverage['sparse'] = fuzz.trimf(monitoring_coverage.universe, [0, 0, 30])
        monitoring_coverage['moderate'] = fuzz.trimf(monitoring_coverage.universe, [20, 50, 80])
        monitoring_coverage['comprehensive'] = fuzz.trimf(monitoring_coverage.universe, [70, 100, 100])
        
        rules = [
            ctrl.Rule(monitoring_coverage['sparse'] & inputs['skill_requirement']['intermediate'], output['very_high']),
            ctrl.Rule(monitoring_coverage['comprehensive'] & inputs['skill_requirement']['expert'], output['medium']),
            ctrl.Rule(monitoring_coverage['moderate'] & inputs['skill_requirement']['expert'], output['high']),
            ctrl.Rule(monitoring_coverage['comprehensive'] & inputs['skill_requirement']['novice'], output['very_low']),
            ctrl.Rule(inputs['detection_difficulty']['high'], output['high']),
        ]
        
        return ctrl.ControlSystem(rules)
    
    def _create_credential_access_system(self) -> ctrl.ControlSystem:
        """Create fuzzy system for Credential Access (TA0006)."""
        inputs = self._create_common_inputs()
        output = self._create_success_probability_output()
        
        password_policy = ctrl.Antecedent(np.arange(0, 101, 1), 'password_policy')
        password_policy['weak'] = fuzz.trimf(password_policy.universe, [0, 0, 30])
        password_policy['moderate'] = fuzz.trimf(password_policy.universe, [20, 50, 80])
        password_policy['strong'] = fuzz.trimf(password_policy.universe, [70, 100, 100])
        
        rules = [
            ctrl.Rule(password_policy['weak'] & inputs['skill_requirement']['novice'], output['high']),
            ctrl.Rule(password_policy['moderate'] & inputs['skill_requirement']['intermediate'], output['medium']),
            ctrl.Rule(password_policy['strong'] & inputs['skill_requirement']['expert'], output['medium']),
            ctrl.Rule(password_policy['strong'] & inputs['skill_requirement']['novice'], output['low']),
            ctrl.Rule(inputs['resource_availability']['abundant'] & password_policy['moderate'], output['high']),
        ]
        
        return ctrl.ControlSystem(rules)
    
    def _create_discovery_system(self) -> ctrl.ControlSystem:
        """Create fuzzy system for Discovery (TA0007)."""
        # Create only the inputs that Discovery actually uses
        detection_difficulty = ctrl.Antecedent(np.arange(0, 101, 1), 'detection_difficulty')
        detection_difficulty['low'] = fuzz.trimf(detection_difficulty.universe, [0, 0, 40])
        detection_difficulty['medium'] = fuzz.trimf(detection_difficulty.universe, [20, 50, 80])
        detection_difficulty['high'] = fuzz.trimf(detection_difficulty.universe, [60, 100, 100])
        
        skill_requirement = ctrl.Antecedent(np.arange(0, 101, 1), 'skill_requirement')
        skill_requirement['novice'] = fuzz.trimf(skill_requirement.universe, [0, 0, 30])
        skill_requirement['intermediate'] = fuzz.trimf(skill_requirement.universe, [20, 50, 80])
        skill_requirement['expert'] = fuzz.trimf(skill_requirement.universe, [70, 100, 100])
        
        output = self._create_success_probability_output()
        
        # Discovery is generally easier once inside
        rules = [
            ctrl.Rule(skill_requirement['novice'], output['medium']),
            ctrl.Rule(skill_requirement['intermediate'], output['high']),
            ctrl.Rule(skill_requirement['expert'], output['very_high']),
            ctrl.Rule(detection_difficulty['low'], output['high']),
            ctrl.Rule(detection_difficulty['high'] & skill_requirement['expert'], output['high']),
        ]
        
        return ctrl.ControlSystem(rules)
    
    def _create_lateral_movement_system(self) -> ctrl.ControlSystem:
        """Create fuzzy system for Lateral Movement (TA0008)."""
        # Create only the inputs that Lateral Movement actually uses
        detection_difficulty = ctrl.Antecedent(np.arange(0, 101, 1), 'detection_difficulty')
        detection_difficulty['low'] = fuzz.trimf(detection_difficulty.universe, [0, 0, 40])
        detection_difficulty['medium'] = fuzz.trimf(detection_difficulty.universe, [20, 50, 80])
        detection_difficulty['high'] = fuzz.trimf(detection_difficulty.universe, [60, 100, 100])
        
        skill_requirement = ctrl.Antecedent(np.arange(0, 101, 1), 'skill_requirement')
        skill_requirement['novice'] = fuzz.trimf(skill_requirement.universe, [0, 0, 30])
        skill_requirement['intermediate'] = fuzz.trimf(skill_requirement.universe, [20, 50, 80])
        skill_requirement['expert'] = fuzz.trimf(skill_requirement.universe, [70, 100, 100])
        
        network_segmentation = ctrl.Antecedent(np.arange(0, 101, 1), 'network_segmentation')
        network_segmentation['poor'] = fuzz.trimf(network_segmentation.universe, [0, 0, 30])
        network_segmentation['moderate'] = fuzz.trimf(network_segmentation.universe, [20, 50, 80])
        network_segmentation['strong'] = fuzz.trimf(network_segmentation.universe, [70, 100, 100])
        
        output = self._create_success_probability_output()
        
        rules = [
            ctrl.Rule(network_segmentation['poor'] & skill_requirement['intermediate'], output['very_high']),
            ctrl.Rule(network_segmentation['moderate'] & skill_requirement['expert'], output['high']),
            ctrl.Rule(network_segmentation['strong'] & skill_requirement['expert'], output['medium']),
            ctrl.Rule(network_segmentation['strong'] & skill_requirement['novice'], output['very_low']),
            ctrl.Rule(detection_difficulty['high'] & network_segmentation['poor'], output['very_high']),
        ]
        
        return ctrl.ControlSystem(rules)
    
    def _create_collection_system(self) -> ctrl.ControlSystem:
        """Create fuzzy system for Collection (TA0009)."""
        inputs = self._create_common_inputs()
        output = self._create_success_probability_output()
        
        data_accessibility = ctrl.Antecedent(np.arange(0, 101, 1), 'data_accessibility')
        data_accessibility['restricted'] = fuzz.trimf(data_accessibility.universe, [0, 0, 30])
        data_accessibility['moderate'] = fuzz.trimf(data_accessibility.universe, [20, 50, 80])
        data_accessibility['open'] = fuzz.trimf(data_accessibility.universe, [70, 100, 100])
        
        rules = [
            ctrl.Rule(data_accessibility['open'] & inputs['skill_requirement']['novice'], output['high']),
            ctrl.Rule(data_accessibility['moderate'] & inputs['skill_requirement']['intermediate'], output['high']),
            ctrl.Rule(data_accessibility['restricted'] & inputs['skill_requirement']['expert'], output['medium']),
            ctrl.Rule(data_accessibility['restricted'] & inputs['skill_requirement']['novice'], output['low']),
            ctrl.Rule(inputs['detection_difficulty']['high'] & data_accessibility['open'], output['very_high']),
        ]
        
        return ctrl.ControlSystem(rules)
    
    def _create_command_control_system(self) -> ctrl.ControlSystem:
        """Create fuzzy system for Command and Control (TA0011)."""
        inputs = self._create_common_inputs()
        output = self._create_success_probability_output()
        
        network_monitoring = ctrl.Antecedent(np.arange(0, 101, 1), 'network_monitoring')
        network_monitoring['minimal'] = fuzz.trimf(network_monitoring.universe, [0, 0, 30])
        network_monitoring['moderate'] = fuzz.trimf(network_monitoring.universe, [20, 50, 80])
        network_monitoring['extensive'] = fuzz.trimf(network_monitoring.universe, [70, 100, 100])
        
        rules = [
            ctrl.Rule(network_monitoring['minimal'] & inputs['skill_requirement']['intermediate'], output['very_high']),
            ctrl.Rule(network_monitoring['moderate'] & inputs['skill_requirement']['expert'], output['high']),
            ctrl.Rule(network_monitoring['extensive'] & inputs['skill_requirement']['expert'], output['medium']),
            ctrl.Rule(network_monitoring['extensive'] & inputs['skill_requirement']['novice'], output['very_low']),
            ctrl.Rule(inputs['detection_difficulty']['high'], output['high']),
        ]
        
        return ctrl.ControlSystem(rules)
    
    def _create_exfiltration_system(self) -> ctrl.ControlSystem:
        """Create fuzzy system for Exfiltration (TA0010)."""
        # Create only the inputs that Exfiltration actually uses
        detection_difficulty = ctrl.Antecedent(np.arange(0, 101, 1), 'detection_difficulty')
        detection_difficulty['low'] = fuzz.trimf(detection_difficulty.universe, [0, 0, 40])
        detection_difficulty['medium'] = fuzz.trimf(detection_difficulty.universe, [20, 50, 80])
        detection_difficulty['high'] = fuzz.trimf(detection_difficulty.universe, [60, 100, 100])
        
        skill_requirement = ctrl.Antecedent(np.arange(0, 101, 1), 'skill_requirement')
        skill_requirement['novice'] = fuzz.trimf(skill_requirement.universe, [0, 0, 30])
        skill_requirement['intermediate'] = fuzz.trimf(skill_requirement.universe, [20, 50, 80])
        skill_requirement['expert'] = fuzz.trimf(skill_requirement.universe, [70, 100, 100])
        
        data_loss_prevention = ctrl.Antecedent(np.arange(0, 101, 1), 'data_loss_prevention')
        data_loss_prevention['weak'] = fuzz.trimf(data_loss_prevention.universe, [0, 0, 30])
        data_loss_prevention['moderate'] = fuzz.trimf(data_loss_prevention.universe, [20, 50, 80])
        data_loss_prevention['strong'] = fuzz.trimf(data_loss_prevention.universe, [70, 100, 100])
        
        output = self._create_success_probability_output()
        
        rules = [
            ctrl.Rule(data_loss_prevention['weak'] & skill_requirement['intermediate'], output['very_high']),
            ctrl.Rule(data_loss_prevention['moderate'] & skill_requirement['expert'], output['high']),
            ctrl.Rule(data_loss_prevention['strong'] & skill_requirement['expert'], output['medium']),
            ctrl.Rule(data_loss_prevention['strong'] & skill_requirement['novice'], output['low']),
            ctrl.Rule(detection_difficulty['high'] & data_loss_prevention['weak'], output['very_high']),
        ]
        
        return ctrl.ControlSystem(rules)
    
    def _create_impact_system(self) -> ctrl.ControlSystem:
        """Create fuzzy system for Impact (TA0040)."""
        # Create only the inputs that Impact actually uses
        detection_difficulty = ctrl.Antecedent(np.arange(0, 101, 1), 'detection_difficulty')
        detection_difficulty['low'] = fuzz.trimf(detection_difficulty.universe, [0, 0, 40])
        detection_difficulty['medium'] = fuzz.trimf(detection_difficulty.universe, [20, 50, 80])
        detection_difficulty['high'] = fuzz.trimf(detection_difficulty.universe, [60, 100, 100])
        
        skill_requirement = ctrl.Antecedent(np.arange(0, 101, 1), 'skill_requirement')
        skill_requirement['novice'] = fuzz.trimf(skill_requirement.universe, [0, 0, 30])
        skill_requirement['intermediate'] = fuzz.trimf(skill_requirement.universe, [20, 50, 80])
        skill_requirement['expert'] = fuzz.trimf(skill_requirement.universe, [70, 100, 100])
        
        backup_recovery = ctrl.Antecedent(np.arange(0, 101, 1), 'backup_recovery')
        backup_recovery['poor'] = fuzz.trimf(backup_recovery.universe, [0, 0, 30])
        backup_recovery['moderate'] = fuzz.trimf(backup_recovery.universe, [20, 50, 80])
        backup_recovery['excellent'] = fuzz.trimf(backup_recovery.universe, [70, 100, 100])
        
        output = self._create_success_probability_output()
        
        rules = [
            ctrl.Rule(backup_recovery['poor'] & skill_requirement['intermediate'], output['very_high']),
            ctrl.Rule(backup_recovery['moderate'] & skill_requirement['expert'], output['high']),
            ctrl.Rule(backup_recovery['excellent'] & skill_requirement['expert'], output['medium']),
            ctrl.Rule(backup_recovery['excellent'] & skill_requirement['novice'], output['low']),
            ctrl.Rule(detection_difficulty['high'] & backup_recovery['poor'], output['very_high']),
        ]
        
        return ctrl.ControlSystem(rules)
    
    def _initialize_fuzzy_systems(self):
        """Initialize all fuzzy control systems for each tactic."""
        system_creators = {
            "TA0043": self._create_reconnaissance_system,
            "TA0042": self._create_resource_development_system,
            "TA0001": self._create_initial_access_system,
            "TA0002": self._create_execution_system,
            "TA0003": self._create_persistence_system,
            "TA0004": self._create_privilege_escalation_system,
            "TA0005": self._create_defense_evasion_system,
            "TA0006": self._create_credential_access_system,
            "TA0007": self._create_discovery_system,
            "TA0008": self._create_lateral_movement_system,
            "TA0009": self._create_collection_system,
            "TA0011": self._create_command_control_system,
            "TA0010": self._create_exfiltration_system,
            "TA0040": self._create_impact_system,
        }
        
        for tactic_id, creator_func in system_creators.items():
            try:
                system = creator_func()
                simulation = ctrl.ControlSystemSimulation(system)
                self.tactic_systems[tactic_id] = simulation
            except Exception as e:
                print(f"Error creating fuzzy system for {tactic_id}: {e}")
                # Fallback to default system
                self.tactic_systems[tactic_id] = None
    
    def get_fuzzy_probability(self, tactic_id: str, 
                            detection_difficulty: float = 50.0,
                            skill_requirement: float = 50.0,  
                            resource_availability: float = 50.0,
                            time_constraint: float = 50.0,
                            **kwargs) -> float:
        """
        Get fuzzy-based success probability for a given tactic.
        
        Args:
            tactic_id: MITRE ATT&CK tactic ID (e.g., "TA0001")
            detection_difficulty: How hard it is to detect (0-100)
            skill_requirement: Required skill level (0-100) 
            resource_availability: Available resources (0-100)
            time_constraint: Time pressure (0-100, higher = more pressure)
            **kwargs: Additional tactic-specific parameters
            
        Returns:
            Success probability (0.0-1.0)
        """
        if tactic_id not in self.tactic_systems:
            return 0.5  # Default probability
            
        sim = self.tactic_systems[tactic_id]
        if sim is None:
            return 0.5  # Fallback for failed system creation
        
        try:
            # Get available input parameters for this tactic
            try:
                # Try the newer API first
                input_names = []
                if hasattr(sim.ctrl, 'antecedents'):
                    # Handle both dict-like and generator-like access
                    antecedents = sim.ctrl.antecedents
                    try:
                        if hasattr(antecedents, 'keys'):
                            input_names = list(antecedents.keys())
                        else:
                            # If it's not dict-like, try to iterate
                            input_names = [name for name, _ in antecedents.items()]
                    except Exception:
                        # Fallback to expected parameters
                        input_names = list(self.get_default_fuzzy_params(tactic_id).keys())
                elif hasattr(sim.ctrl, 'antecedents_all'):
                    # Handle both dict-like and generator-like access
                    antecedents_all = sim.ctrl.antecedents_all
                    try:
                        if hasattr(antecedents_all, 'keys'):
                            input_names = list(antecedents_all.keys())
                        else:
                            # If it's not dict-like, try to iterate
                            input_names = [name for name, _ in antecedents_all.items()]
                    except Exception:
                        # Fallback to expected parameters
                        input_names = list(self.get_default_fuzzy_params(tactic_id).keys())
                else:
                    # Fallback - try to get from the simulation object
                    if hasattr(sim, 'input'):
                        try:
                            input_names = list(sim.input.keys())
                        except Exception:
                            input_names = list(self.get_default_fuzzy_params(tactic_id).keys())
                    else:
                        input_names = list(self.get_default_fuzzy_params(tactic_id).keys())
                        
                # If we still don't have input names, use expected parameters
                if not input_names:
                    input_names = list(self.get_default_fuzzy_params(tactic_id).keys())
                    
            except Exception:
                # Get the expected parameters for this specific tactic
                input_names = list(self.get_default_fuzzy_params(tactic_id).keys())
            
            # Set all parameters that are expected by this tactic
            expected_params = self.get_default_fuzzy_params(tactic_id)
            provided_params = {
                'detection_difficulty': detection_difficulty,
                'skill_requirement': skill_requirement,
                'resource_availability': resource_availability,
                'time_constraint': time_constraint
            }
            
            # Add any additional parameters from kwargs
            provided_params.update(kwargs)
            
            # Set all expected parameters
            for param_name in expected_params:
                if param_name in provided_params:
                    sim.input[param_name] = max(0, min(100, provided_params[param_name]))
                else:
                    # Set default value if not provided
                    sim.input[param_name] = expected_params[param_name]
            
            # Compute the result
            sim.compute()
            
            # Return probability as 0-1 scale
            try:
                output_value = sim.output['success_probability']
            except Exception:
                # Try alternative access methods
                try:
                    if hasattr(sim.output, 'get'):
                        output_value = sim.output.get('success_probability', 50.0)
                    else:
                        # Try to find it in the output
                        output_value = 50.0  # Default fallback
                        for name, value in sim.output.items():
                            if name == 'success_probability':
                                output_value = value
                                break
                except Exception:
                    output_value = 50.0  # Default fallback
            
            return output_value / 100.0
            
        except Exception as e:
            print(f"Error computing fuzzy probability for {tactic_id}: {e}")
            return 0.5
    
    def get_fuzzy_states(self, tactic_id: str) -> List[str]:
        """
        Get fuzzy state names for a tactic node.
        
        Args:
            tactic_id: MITRE ATT&CK tactic ID
            
        Returns:
            List of state names for the fuzzy system
        """
        return ["Very_Low", "Low", "Medium", "High", "Very_High"]
    
    def get_fuzzy_membership_distribution(self, tactic_id: str, **fuzzy_params) -> List[float]:
        """
        Get fuzzy membership distribution across all states.
        
        Args:
            tactic_id: MITRE ATT&CK tactic ID
            **fuzzy_params: Parameters for fuzzy system
            
        Returns:
            List of membership values for each fuzzy state
        """
        if tactic_id not in self.tactic_systems:
            # Default uniform distribution for unknown tactics
            return [0.2, 0.2, 0.2, 0.2, 0.2]
            
        sim = self.tactic_systems[tactic_id]
        if sim is None:
            return [0.2, 0.2, 0.2, 0.2, 0.2]
        
        try:
            # Get available input parameters for this tactic
            try:
                # Try the newer API first
                input_names = []
                if hasattr(sim.ctrl, 'antecedents'):
                    # Handle both dict-like and generator-like access
                    antecedents = sim.ctrl.antecedents
                    try:
                        if hasattr(antecedents, 'keys'):
                            input_names = list(antecedents.keys())
                        else:
                            # If it's not dict-like, try to iterate
                            input_names = [name for name, _ in antecedents.items()]
                    except Exception:
                        # Fallback to expected parameters
                        input_names = list(self.get_default_fuzzy_params(tactic_id).keys())
                elif hasattr(sim.ctrl, 'antecedents_all'):
                    # Handle both dict-like and generator-like access
                    antecedents_all = sim.ctrl.antecedents_all
                    try:
                        if hasattr(antecedents_all, 'keys'):
                            input_names = list(antecedents_all.keys())
                        else:
                            # If it's not dict-like, try to iterate
                            input_names = [name for name, _ in antecedents_all.items()]
                    except Exception:
                        # Fallback to expected parameters
                        input_names = list(self.get_default_fuzzy_params(tactic_id).keys())
                else:
                    # Fallback - try to get from the simulation object
                    if hasattr(sim, 'input'):
                        try:
                            input_names = list(sim.input.keys())
                        except Exception:
                            input_names = list(self.get_default_fuzzy_params(tactic_id).keys())
                    else:
                        input_names = list(self.get_default_fuzzy_params(tactic_id).keys())
                        
                # If we still don't have input names, use expected parameters
                if not input_names:
                    input_names = list(self.get_default_fuzzy_params(tactic_id).keys())
                    
            except Exception:
                # Get the expected parameters for this specific tactic
                input_names = list(self.get_default_fuzzy_params(tactic_id).keys())
            
            # Set all parameters that are expected by this tactic
            expected_params = self.get_default_fuzzy_params(tactic_id)
            for param_name in expected_params:
                if param_name in fuzzy_params:
                    sim.input[param_name] = max(0, min(100, fuzzy_params[param_name]))
                else:
                    # Set default value if not provided
                    sim.input[param_name] = expected_params[param_name]
            
            # Also set any additional parameters that might be provided
            for param_name, value in fuzzy_params.items():
                if param_name in input_names and param_name not in expected_params:
                    sim.input[param_name] = max(0, min(100, value))
            
            # Compute the result
            sim.compute()
            
            # Get the output fuzzy set
            try:
                output_value = sim.output['success_probability']
            except Exception:
                # Try alternative access methods
                try:
                    if hasattr(sim.output, 'get'):
                        output_value = sim.output.get('success_probability', 50.0)
                    else:
                        # Try to find it in the output
                        output_value = 50.0  # Default fallback
                        for name, value in sim.output.items():
                            if name == 'success_probability':
                                output_value = value
                                break
                except Exception:
                    output_value = 50.0  # Default fallback
            
            # Calculate membership in each linguistic term
            try:
                # Try to get the output variable - different ways depending on scikit-fuzzy version
                output_var = None
                try:
                    if hasattr(sim.ctrl, 'consequents'):
                        # Handle both dict-like and generator-like access
                        consequents = sim.ctrl.consequents
                        if hasattr(consequents, 'get'):
                            output_var = consequents.get('success_probability')
                        else:
                            # Try to find it in the consequents
                            for name, var in consequents.items():
                                if name == 'success_probability':
                                    output_var = var
                                    break
                    elif hasattr(sim.ctrl, 'consequents_all'):
                        # Handle both dict-like and generator-like access
                        consequents_all = sim.ctrl.consequents_all
                        if hasattr(consequents_all, 'get'):
                            output_var = consequents_all.get('success_probability')
                        else:
                            # Try to find it in the consequents_all
                            for name, var in consequents_all.items():
                                if name == 'success_probability':
                                    output_var = var
                                    break
                except Exception:
                    output_var = None
                
                if output_var is None:
                    # If we can't access the output variable, return a computed distribution
                    return self._compute_membership_from_value(output_value)
                
                memberships = []
                for state in ['very_low', 'low', 'medium', 'high', 'very_high']:
                    try:
                        membership = fuzz.interp_membership(
                            output_var.universe, 
                            output_var[state].mf, 
                            output_value
                        )
                        memberships.append(membership)
                    except Exception:
                        # Fallback if we can't compute membership for this state
                        memberships.append(0.2)
                
                # Normalize to ensure they sum to 1
                total = sum(memberships)
                if total > 0:
                    memberships = [m / total for m in memberships]
                else:
                    memberships = [0.2, 0.2, 0.2, 0.2, 0.2]
                
                return memberships
                
            except Exception as inner_e:
                print(f"Error accessing output variable for {tactic_id}: {inner_e}")
                return self._compute_membership_from_value(output_value)
            
        except Exception as e:
            print(f"Error computing fuzzy membership for {tactic_id}: {e}")
            return [0.2, 0.2, 0.2, 0.2, 0.2]
    
    def _compute_membership_from_value(self, output_value: float) -> List[float]:
        """
        Compute fuzzy membership distribution from a single output value.
        This is a fallback when we can't access the fuzzy output variable directly.
        """
        # Map output value (0-100) to fuzzy states
        if output_value <= 20:
            # Very Low
            return [0.8, 0.15, 0.05, 0.0, 0.0]
        elif output_value <= 40:
            # Low
            return [0.2, 0.6, 0.2, 0.0, 0.0]
        elif output_value <= 60:
            # Medium
            return [0.05, 0.25, 0.4, 0.25, 0.05]
        elif output_value <= 80:
            # High
            return [0.0, 0.0, 0.2, 0.6, 0.2]
        else:
            # Very High
            return [0.0, 0.0, 0.05, 0.15, 0.8]

    def get_fuzzy_cpt_probabilities(self, tactic_id: str, 
                                  num_parents: int = 0,
                                  **fuzzy_params) -> List[float]:
        """
        Generate CPT probabilities for a multi-state fuzzy BN node.
        This method assumes all parents are fuzzy (5-state) nodes.
        For mixed parent scenarios, use the BNBuilder's _handle_mixed_parent_cpt method.
        
        Args:
            tactic_id: MITRE ATT&CK tactic ID
            num_parents: Number of parent nodes (assumed to be fuzzy)
            **fuzzy_params: Parameters for fuzzy system
            
        Returns:
            List of probabilities for CPT table with 5 fuzzy states
        """
        base_membership = self.get_fuzzy_membership_distribution(tactic_id, **fuzzy_params)
        
        if num_parents == 0:
            # Prior probability - return base fuzzy distribution
            return base_membership
        
        # For multi-parent scenarios with all fuzzy parents
        # Each parent can be in any of 5 states, so we have 5^num_parents combinations
        cpt = []
        num_states = 5
        total_combinations = num_states ** num_parents
        
        for row in range(total_combinations):
            # Decode parent state combination
            parent_states = []
            temp_row = row
            for _ in range(num_parents):
                parent_states.append(temp_row % num_states)
                temp_row //= num_states
            
            # Calculate influence based on parent states
            # Higher state values (3,4) increase success, lower values (0,1) decrease it
            parent_influence = sum(parent_states) / (num_parents * 4.0)  # Normalize to 0-1
            
            # Adjust base membership based on parent influence
            adjusted_membership = base_membership.copy()
            
            if parent_influence < 0.3:
                # Low parent influence - shift toward lower states
                shift_factor = (0.3 - parent_influence) * 2
                adjusted_membership[0] += shift_factor * 0.3  # Very_Low
                adjusted_membership[1] += shift_factor * 0.2  # Low
                adjusted_membership[2] -= shift_factor * 0.1  # Medium
                adjusted_membership[3] -= shift_factor * 0.2  # High
                adjusted_membership[4] -= shift_factor * 0.2  # Very_High
                
            elif parent_influence > 0.7:
                # High parent influence - shift toward higher states
                shift_factor = (parent_influence - 0.7) * 2
                adjusted_membership[0] -= shift_factor * 0.2  # Very_Low
                adjusted_membership[1] -= shift_factor * 0.2  # Low
                adjusted_membership[2] -= shift_factor * 0.1  # Medium
                adjusted_membership[3] += shift_factor * 0.2  # High
                adjusted_membership[4] += shift_factor * 0.3  # Very_High
            
            # Ensure all probabilities are non-negative and sum to 1
            adjusted_membership = [max(0.01, p) for p in adjusted_membership]
            total = sum(adjusted_membership)
            adjusted_membership = [p / total for p in adjusted_membership]
            
            cpt.extend(adjusted_membership)
        
        return cpt
    
    def get_default_fuzzy_params(self, tactic_id: str) -> Dict[str, float]:
        """Get reasonable default parameters for a tactic - FIXED: Only return parameters each tactic actually expects."""
        # Each tactic only expects specific input parameters based on their fuzzy system definition
        defaults = {
            "TA0043": {"detection_difficulty": 70, "skill_requirement": 30, "target_exposure": 60},
            "TA0042": {"resource_availability": 60, "skill_requirement": 50, "time_constraint": 40},
            "TA0001": {"attack_surface": 50, "detection_difficulty": 60, "skill_requirement": 60},
            "TA0002": {"detection_difficulty": 40, "skill_requirement": 40},  # Only these 2 inputs
            "TA0003": {"system_complexity": 50, "detection_difficulty": 70, "skill_requirement": 70},
            "TA0004": {"security_hardening": 60, "skill_requirement": 80, "detection_difficulty": 80},
            "TA0005": {"monitoring_coverage": 50, "skill_requirement": 70, "detection_difficulty": 80},
            "TA0006": {"password_policy": 50, "skill_requirement": 60, "resource_availability": 70},
            "TA0007": {"skill_requirement": 40, "detection_difficulty": 50},  # Only these 2 inputs
            "TA0008": {"network_segmentation": 50, "skill_requirement": 70, "detection_difficulty": 70},
            "TA0009": {"data_accessibility": 60, "skill_requirement": 50, "detection_difficulty": 60},
            "TA0011": {"network_monitoring": 50, "skill_requirement": 60, "detection_difficulty": 70},
            "TA0010": {"data_loss_prevention": 50, "skill_requirement": 70, "detection_difficulty": 80},
            "TA0040": {"backup_recovery": 50, "skill_requirement": 60, "detection_difficulty": 70},
        }
        
        # Return exact parameters for this tactic, or minimal fallback
        return defaults.get(tactic_id, {
            "detection_difficulty": 50,
            "skill_requirement": 50
        })