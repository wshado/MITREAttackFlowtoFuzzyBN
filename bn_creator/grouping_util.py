#grouping_util.py
import json
from collections import defaultdict

class GroupingUtil:
    """
    Utility to compute partition, divorce, and logic operator groups based on a recommendations list,
    parent and child maps, and optional semantic bucketing (e.g., by tactic_id).
    """
    def __init__(self, parent_map, child_map, recommendations, id_to_obj=None, max_size=3, bucket_key='tactic_id'):
        self.parent_map = parent_map or {}
        self.child_map = child_map or {}
        self.recommendations = recommendations or []
        self.id_to_obj = id_to_obj or {}
        self.max_size = max_size
        self.bucket_key = bucket_key

    def partition_parents(self, parents):
        buckets = defaultdict(list)
        for pid in parents:
            obj = self.id_to_obj.get(pid)
            key = getattr(obj, self.bucket_key, 'UNKNOWN') if obj else 'UNKNOWN'
            buckets[key].append(pid)

        groups = []
        for members in buckets.values():
            for i in range(0, len(members), self.max_size):
                groups.append(members[i:i + self.max_size])

        while len(groups) > self.max_size:
            groups = sorted(groups, key=len)
            g1 = groups.pop(0)
            g2 = groups.pop(0)
            groups.append(g1 + g2)

        return groups

    def get_partition_groups(self):
        partitioned = []
        for rec in self.recommendations:
            if any('Partition recommended' in r for r in rec.get('recommendations', [])):
                node_id = rec['node_id']
                parents = self.parent_map.get(node_id, [])
                groups = self.partition_parents(parents)
                partitioned.append({'node_id': node_id, 'groups': groups})
        return partitioned

    def get_divorce_groups(self):
        divorced = []
        for rec in self.recommendations:
            if any('Divorce recommended' in r for r in rec.get('recommendations', [])):
                node_id = rec['node_id']
                children = self.child_map.get(node_id, [])
                divorced.append({'node_id': node_id, 'children': children})
        return divorced

    def get_logic_groups(self):
        logic_groups = []
        for rec in self.recommendations:
            for msg in rec.get('recommendations', []):
                if 'AND' in msg and 'Noisy adder' in msg:
                    logic_groups.append({'node_id': rec['node_id'], 'logic': 'AND', 'members': self.parent_map.get(rec['node_id'], [])})
                elif 'OR' in msg and 'Noisy-OR' in msg or 'Unknown' in msg:
                    logic_groups.append({'node_id': rec['node_id'], 'logic': 'OR', 'members': self.parent_map.get(rec['node_id'], [])})
        return logic_groups

    @classmethod
    def from_context_file(cls, context_file, max_size=3, bucket_key='tactic_id'):

        with open(context_file) as f:
            ctx = json.load(f)
        return cls(
            parent_map=ctx.get('parent_map'),
            child_map=ctx.get('child_map'),
            recommendations=ctx.get('recommendations'),
            id_to_obj=ctx.get('id_to_obj'),
            max_size=max_size,
            bucket_key=bucket_key
        )
