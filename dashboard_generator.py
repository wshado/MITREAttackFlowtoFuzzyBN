import requests
import xml.etree.ElementTree as ET

class GrafanaDashboardGenerator:
    """
    Auto-generate a Grafana dashboard showing P(True) for each
    'attack_action__…' node in your BN, using the node's <Name>
    from the XDSL as the panel title, and displaying the value as a %.

    Example usage:
        gen = GrafanaDashboardGenerator(
            grafana_url="http://localhost:3000",
            api_key="eyJrIjoi…",
            prom_node_list_url="http://localhost:8000/ttps",
            xdsl_path="attack_flow_model.xdsl",
            prometheus_datasource_uid="Prometheus",
            node_prefix="attack_action__",
            panels_per_row=4
        )
        slug = gen.generate_dashboard()
        print("Dashboard URL:", f"{gen.grafana_url}/d/{slug}")
    """
    def __init__(self,
                 grafana_url: str,
                 api_key: str,
                 prom_node_list_url: str,
                 xdsl_path: str,
                 prometheus_datasource_uid: str = "Prometheus",
                 node_prefix: str = "attack_action__",
                 panels_per_row: int = 4):
        self.grafana_url        = grafana_url.rstrip("/")
        self.api_key            = api_key
        self.prom_node_list_url = prom_node_list_url
        self.datasource_uid     = prometheus_datasource_uid
        self.prefix             = node_prefix
        self.panels_per_row     = panels_per_row
        self.node_names         = self._load_node_names(xdsl_path)

    def _load_node_names(self, xdsl_path: str):
        """Parse the XDSL file and return a dict { node_id: Name_text }."""
        tree = ET.parse(xdsl_path)
        root = tree.getroot()
        names = {}
        # every element with an 'id' attribute and a <Name> child
        for elem in root.iter():
            node_id = elem.get("id")
            if not node_id:
                continue
            name_elem = elem.find("name")
            if name_elem is not None and name_elem.text:
                names[node_id] = name_elem.text
        return names

    def _fetch_nodes(self):
        r = requests.get(self.prom_node_list_url)
        r.raise_for_status()
        return r.json()

    def generate_dashboard(self) -> str:
        # 1) Fetch & filter
        all_nodes = requests.get(self.prom_node_list_url).json()
        # filter only the ones whose id starts with your prefix,
        # then sort by that id:
        attack_nodes = sorted(
            (node for node in all_nodes if node["id"].startswith(self.prefix)),
            key=lambda node: node["id"],
        )
        # 2) Build one stat panel per node
        panels = []
        for idx, node in enumerate(attack_nodes):
            row, col = divmod(idx, self.panels_per_row)
            panels.append({
                "type": "stat",
                "title": node["label"],
                "gridPos": {"x": col*6, "y": row*4, "w": 6, "h": 4},
                "datasource": None,
                "targets": [{
                    "expr": f"bn_{node['id']}",
                    "refId": "A",
                    "instant": True
                }],
                "fieldConfig": {
                    "defaults": {
                        "unit":     "percent",
                        "decimals": 2,
                        "min":      0,
                        "max":      100
                    }
                },
                "options": {
                    "orientation":    "auto",
                    "textMode":       "value_and_name",
                    "colorMode":      "value"
                }
            })
        # 3) Wrap into a full dashboard payload
        payload = {
            "dashboard": {
                "id":            None,
                "uid":           None,
                "title":         "Attack-Action True Probabilities",
                "tags":          ["auto-generated","bn"],
                "schemaVersion": 36,
                "version":       0,
                "panels":        panels
            },
            "overwrite": True
        }

        # 4) Push to Grafana
        url = f"{self.grafana_url}/api/dashboards/db"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type":  "application/json",
        }
        resp = requests.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()["slug"]
