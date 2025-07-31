#noisy_adder.py
from itertools import product

class NoisyAdder:
    def __init__(self, parent_weights, child_states, thresholds):
        """
        parent_weights: dict of {parent_id: weight if True}
        child_states: ordered list like ["Low", "Medium", "High"]
        thresholds: list of numeric thresholds separating child states
        """
        self.parent_weights = parent_weights
        self.child_states = child_states
        self.thresholds = thresholds

    def compute_score(self, parent_values):
        return sum(
            self.parent_weights[parent] if state == "True" else 0
            for parent, state in parent_values.items()
        )

    def get_child_distribution(self, score):
        """Return one-hot distribution based on threshold"""
        for i, threshold in enumerate(self.thresholds):
            if score < threshold:
                return [1.0 if j == i else 0.0 for j in range(len(self.child_states))]
        return [1.0 if j == len(self.child_states) - 1 else 0.0 for j in range(len(self.child_states))]

    def generate_cpt(self):
        """Generate a full CPT for the child node"""
        parents = list(self.parent_weights.keys())
        cpt = []
        for values in product(["True", "False"], repeat=len(parents)):
            assignment = dict(zip(parents, values))
            score = self.compute_score(assignment)
            dist = self.get_child_distribution(score)
            cpt.extend(dist)
        return cpt
