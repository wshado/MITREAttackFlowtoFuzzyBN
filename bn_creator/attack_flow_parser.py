#attack_flow_parser.py
import os
import json
from stix2 import parse, Bundle
from attack_flow.model import AttackFlow

class AttackFlowProcessor:
    def __init__(self, reference_file="bn_creator/reference.json"):
        with open(reference_file, "r") as f:
            self.reference = json.load(f)

    def build_object_info(self, obj):

        type = getattr(obj, "type", None)
        display_name = (
            getattr(obj, "name", None)
            or getattr(obj, "user_id", None)
            or getattr(obj, "value", None)
            or getattr(obj, "path", None)
            or getattr(obj, "id", "Unknown")
        )
        tactic_id = getattr(obj, "tactic_id", None)
        tactic_lookup = {item["tactic_id"]: item["tactic_name"] for item in self.reference}
        tactic_name = tactic_lookup.get(tactic_id, "Unknown")
        technique_id = getattr(obj, "technique_id", None)
        description = getattr(obj, "description", None)
        id = getattr(obj, "id", None)
        return {
            "type": type,
            "relevance": display_name,
            "tactic_id": tactic_id,
            "tactic_name": tactic_name,
            "technique_id": technique_id,
            "description": description,
            "id": id
        }

    def read_file(self, file):
        with open(file, 'r', encoding='utf-8') as f:
            return f.read()

    def process_file(self, input_path):
        print(f"📄 Reading: {input_path}")
        attack_flow = self.read_file(input_path)

        bundle = parse(attack_flow, allow_custom=True)
        relationships = []
        condition_nodes = {}

        if isinstance(bundle, Bundle):
            print(f"Parsed {len(bundle.objects)} objects from the bundle.")
            id_to_obj = {obj.id: obj for obj in bundle.objects}

            graph_edges = []

            for stix_object in bundle.objects:
                if stix_object.type == "attack-condition":
                    condition_type = getattr(stix_object, "condition_type", "UNKNOWN")
                    condition_nodes[stix_object.id] = condition_type
                    print(f"Detected Condition Node: {stix_object.id}, Type: {condition_type}")

                elif stix_object.type == "attack-operator":
                    operator_type = getattr(stix_object, "operator", "UNKNOWN")
                    condition_nodes[stix_object.id] = operator_type
                    print(f"Detected Operator Node: {stix_object.id}, Type: {operator_type}")

                if getattr(stix_object, "type", None) == "relationship":
                    source_ref = getattr(stix_object, "source_ref", None)
                    target_ref = getattr(stix_object, "target_ref", None)
                    if source_ref and target_ref:
                        graph_edges.append((source_ref, target_ref))

                    src_obj = id_to_obj.get(source_ref)
                    tgt_obj = id_to_obj.get(target_ref)
                    src_info = self.build_object_info(src_obj)
                    tgt_info = self.build_object_info(tgt_obj)
                    relationships.append([src_info, tgt_info])

                elif hasattr(stix_object, "object_refs"):
                    for ref in getattr(stix_object, "object_refs", []):
                        graph_edges.append((stix_object.id, ref))
                        tgt_obj = id_to_obj.get(ref)
                        src_info = self.build_object_info(stix_object)
                        tgt_info = self.build_object_info(tgt_obj)
                        relationships.append([src_info, tgt_info])

                for attr_name in stix_object._inner.keys() if hasattr(stix_object,
                                                                      "_inner") else stix_object.__dict__.keys():
                    if attr_name.endswith("_refs") and attr_name not in ["object_refs", "start_refs"]:
                        refs_list = getattr(stix_object, attr_name, [])
                        for ref_id in refs_list:
                            graph_edges.append((stix_object.id, ref_id))
                            tgt_obj = id_to_obj.get(ref_id)
                            src_info = self.build_object_info(stix_object)
                            tgt_info = self.build_object_info(tgt_obj)
                            relationships.append([src_info, tgt_info])

                command_ref = getattr(stix_object, "command_ref", None)
                if command_ref:
                    graph_edges.append((stix_object.id, command_ref))
                    tgt_obj = id_to_obj.get(command_ref)
                    if tgt_obj:
                        src_info = self.build_object_info(stix_object)
                        tgt_info = self.build_object_info(tgt_obj)
                        relationships.append([src_info, tgt_info])

            parent_map = {}
            child_map = {}
            all_nodes = set()

            for src, tgt in graph_edges:
                parent_map.setdefault(tgt, []).append(src)
                child_map.setdefault(src, []).append(tgt)
                all_nodes.update([src, tgt])

            recommendations = []

            for node_id in all_nodes:
                num_parents = len(parent_map.get(node_id, []))
                num_children = len(child_map.get(node_id, []))

                node_recs = []

                if num_parents >= 3:
                    rec = f"Partition recommended (parents: {num_parents})"
                    node_recs.append(rec)
                    print(f"{rec} for node {node_id}")

                if num_children >= 3:
                    rec = f"Divorce recommended (children: {num_children})"
                    node_recs.append(rec)
                    print(f"{rec} for node {node_id}")

                if node_id in condition_nodes:
                    condition_type = condition_nodes[node_id]
                    if condition_type == "AND":
                        logic_msg = "Noisy adder logic node (AND) detected"
                        node_recs.append(logic_msg)
                        print(f"{logic_msg}: {node_id}")
                    elif condition_type == "OR":
                        logic_msg = "Noisy-OR logic node detected"
                        node_recs.append(logic_msg)
                        print(f"{logic_msg}: {node_id}")
                    else:
                        unknown_msg = f"Unknown condition type: {condition_type}"
                        node_recs.append(unknown_msg)
                        print(f"{unknown_msg} on node {node_id}")

                if node_recs:
                    recommendations.append({
                        "node_id": node_id,
                        "num_parents": num_parents,
                        "num_children": num_children,
                        "recommendations": node_recs
                    })

            used_ids = set()
            for src_obj, tgt_obj in relationships:
                if src_obj:
                    used_ids.add(src_obj["id"])
                if tgt_obj:
                    used_ids.add(tgt_obj["id"])

            new_objects = []
            for obj in bundle.objects:
                if obj.id in used_ids or getattr(obj, "type", None) in ["relationship", "extension-definition",
                                                                        "attack-flow", "identity", "attack-asset",
                                                                        "attack-action", "attack-condition"]:
                    new_objects.append(obj)

            new_bundle = Bundle(objects=new_objects, allow_custom=True)

            base_name = os.path.basename(input_path).split('.')[0].replace(" ", "_")
            out_name = f"{base_name}_rebuilt.json"
            
            # with open(out_name, "w") as f:
            #     f.write(new_bundle.serialize(pretty=True))
            
            # print(f"Rebuilt attack flow saved to: {out_name}")

            return out_name, new_bundle, used_ids, parent_map, child_map, condition_nodes, recommendations, id_to_obj, relationships
