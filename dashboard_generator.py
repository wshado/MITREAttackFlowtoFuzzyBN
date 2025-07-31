#dashboard_generator.py - Fixed for Grafana Dashboard Data Display
import requests
import xml.etree.ElementTree as ET
import json

class GrafanaDashboardGenerator:
    """
    Auto-generate a Grafana dashboard for Fuzzy Bayesian Networks.
    Supports both fuzzy (5-state) and binary (2-state) nodes with appropriate visualizations.
    Fixed to properly display data in Grafana panels.
    """
    def __init__(self,
                 grafana_url: str,
                 api_key: str,
                 prom_node_list_url: str,
                 xdsl_path: str,
                 prometheus_datasource_uid: str,
                 node_prefixes: list = None,  # Use None to include ALL nodes
                 panels_per_row: int = 4):
        self.grafana_url        = grafana_url.rstrip("/")
        self.api_key            = api_key
        self.prom_node_list_url = prom_node_list_url
        self.datasource_uid     = prometheus_datasource_uid
        self.prefixes           = node_prefixes
        self.panels_per_row     = panels_per_row
        self.node_names         = self._load_node_names(xdsl_path)
        self.node_info          = self._get_node_info()

    def _load_node_names(self, xdsl_path: str):
        """Parse the XDSL file and return a dict { node_id: Name_text }."""
        try:
            tree = ET.parse(xdsl_path)
            root = tree.getroot()
            names = {}
            for elem in root.iter():
                node_id = elem.get("id")
                if not node_id:
                    continue
                name_elem = elem.find("name")
                if name_elem is not None and name_elem.text:
                    names[node_id] = name_elem.text
            return names
        except Exception as e:
            print(f"Warning: Could not parse XDSL file: {e}")
            return {}

    def _get_node_info(self):
        """Get node information from the BN service."""
        try:
            response = requests.get(f"{self.prom_node_list_url}/ttps")
            return {node["id"]: node for node in response.json()}
        except Exception as e:
            print(f"Warning: Could not fetch node info: {e}")
            return {}
    
    def _get_node_beliefs(self):
        """Get current belief states and probabilities for all nodes."""
        try:
            response = requests.get(f"{self.prom_node_list_url}/beliefs")
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Warning: Could not fetch beliefs, status: {response.status_code}")
                return {}
        except Exception as e:
            print(f"Warning: Could not fetch node beliefs: {e}")
            return {}
    
    def _format_belief_display(self, node_id: str, beliefs: dict) -> tuple:
        """Format belief information for display.
        Returns (display_text, probability_value, state_label)
        """
        if node_id not in beliefs:
            return "Unknown", 0.5, "Unknown"
        
        belief_data = beliefs[node_id]
        
        # Handle different belief data formats
        if isinstance(belief_data, dict):
            if "most_likely_state" in belief_data and "probability" in belief_data:
                state = belief_data["most_likely_state"]
                prob = belief_data["probability"]
                return f"{state}: {prob:.3f}", prob, state
            elif "state" in belief_data and "value" in belief_data:
                state = belief_data["state"]
                prob = belief_data["value"]
                return f"{state}: {prob:.3f}", prob, state
        elif isinstance(belief_data, (int, float)):
            # Simple probability value
            prob = float(belief_data)
            if prob >= 0.7:
                state = "High"
            elif prob >= 0.4:
                state = "Medium"
            else:
                state = "Low"
            return f"{state}: {prob:.3f}", prob, state
        
        return "Unknown", 0.5, "Unknown"
    
    def _create_mission_risk_panel(self, beliefs: dict) -> dict:
        """Create mission risk assessment panel using the mission_risk_assessment metric."""
        # Use the mission risk assessment metric from Flask app
        mission_risk_metric = "mission_risk_assessment"
        
        # Default values
        avg_risk = 0.5
        mission_risk = "Medium"
        color = "yellow"
        
        if beliefs:
            # Calculate maximum risk from all node beliefs (matches Flask logic)
            max_risk = 0.0
            
            for nid, belief_data in beliefs.items():
                if isinstance(belief_data, dict) and "probability" in belief_data:
                    max_risk = max(max_risk, belief_data["probability"])
                elif isinstance(belief_data, (int, float)):
                    max_risk = max(max_risk, belief_data)
            
            avg_risk = max_risk
            
            # Classify mission risk (matches Flask classification)
            if avg_risk >= 0.8:
                mission_risk = "Very High"
                color = "red"
            elif avg_risk >= 0.6:
                mission_risk = "High" 
                color = "orange"
            elif avg_risk >= 0.4:
                mission_risk = "Medium"
                color = "yellow"
            elif avg_risk >= 0.2:
                mission_risk = "Low"
                color = "green"
            else:
                mission_risk = "Very Low"
                color = "green"
        else:
            mission_risk = "Very Low"
            color = "green"
        
        return {
            "datasource": "Prometheus",
            "fieldConfig": {
                "defaults": {
                    "unit": "percentunit",  # Changed from "short" to "percentunit"
                    "min": 0,
                    "max": 1,
                    "decimals": 3,
                    "thresholds": {
                        "mode": "absolute",
                        "steps": [
                            {
                                "color": "green",
                                "value": None
                            },
                            {
                                "color": "yellow",
                                "value": 0.3
                            },
                            {
                                "color": "red",
                                "value": 0.5
                            }
                        ]
                    },
                    "custom": {
                        "displayMode": "basic",
                        "orientation": "auto"
                    },
                    "mappings": [],
                    "color": {
                        "mode": "thresholds"
                    }
                },
                "overrides": []
            },
            "gridPos": {
                "h": 8,
                "w": 24,  # Full width
                "x": 0,
                "y": 0     # Top of dashboard
            },
            "id": 999,  # High ID to avoid conflicts
            "options": {
                "reduceOptions": {
                    "values": False,
                    "calcs": [
                        "lastNotNull"
                    ],
                    "fields": ""
                },
                "orientation": "auto",
                "textMode": "value_and_name",
                "colorMode": "background",
                "graphMode": "none",
                "justifyMode": "center",
                "displayMode": "basic"
            },
            "pluginVersion": "9.0.0",
            "targets": [
                {
                    "datasource": "Prometheus",
                    "expr": "mission_risk_assessment",  # Use the actual metric from Flask app
                    "interval": "",
                    "legendFormat": f"Mission Risk: {mission_risk}",
                    "refId": "A",
                    "intervalFactor": 1,
                    "step": 15
                }
            ],
            "title": "🚨 MISSION RISK ASSESSMENT",
            "description": f"Overall Mission Risk: {mission_risk} | Max Risk: {avg_risk:.3f} | Based on highest node belief value",
            "type": "stat"
        }

    def _node_matches_prefixes(self, node_id: str) -> bool:
        """Check if node_id should be included based on prefixes."""
        # If no prefixes specified, include ALL nodes
        if self.prefixes is None:
            return True
        # Otherwise check if it matches any prefix
        return any(node_id.startswith(prefix) for prefix in self.prefixes)

    def generate_dashboard(self) -> str:
        # 1) Fetch all nodes from Flask app
        print("Fetching nodes from Flask app...")
        ttps_url = f"{self.prom_node_list_url}/ttps" if not self.prom_node_list_url.endswith('/ttps') else self.prom_node_list_url
        all_nodes = requests.get(ttps_url).json()
        print(f"Total nodes available: {len(all_nodes)}")
        
        # 1.5) Fetch current belief states
        print("Fetching node beliefs...")
        beliefs = self._get_node_beliefs()
        print(f"Belief data available for {len(beliefs)} nodes")
        
        # 2) Filter nodes based on prefixes (or include all if no prefixes)
        if self.prefixes is None:
            filtered_nodes = all_nodes
            print("Including ALL nodes (no prefix filter)")
        else:
            filtered_nodes = [node for node in all_nodes if self._node_matches_prefixes(node["id"])]
            print(f"Filtered to {len(filtered_nodes)} nodes matching prefixes: {self.prefixes}")
        
        # Sort by ID for consistent ordering
        filtered_nodes = sorted(filtered_nodes, key=lambda node: node["id"])
        
        print(f"Creating dashboard with {len(filtered_nodes)} panels")
        print("Sample nodes:")
        for node in filtered_nodes[:10]:  # Show first 10
            print(f"  - {node['id']}: {node['label']}")
        
        # 3) Create mission risk assessment panel
        mission_panel = self._create_mission_risk_panel(beliefs)
        panels = [mission_panel]
        
        # Adjust y-position for subsequent panels to account for mission panel
        mission_panel_height = 8
        y_offset = mission_panel_height + 2  # Add some spacing
        
        # 4) Build node panels with 4-per-row layout
        
        for idx, node in enumerate(filtered_nodes):
            # Calculate position: 4 panels per row, each 6 units wide
            row_number = idx // self.panels_per_row
            col_number = idx % self.panels_per_row
            
            x_pos = col_number * 6  # 0, 6, 12, 18
            y_pos = (row_number * 8) + y_offset  # Stack rows with 8-unit spacing, offset for mission panel
            
            # Get belief information for this node
            belief_display, prob_value, state_label = self._format_belief_display(node['id'], beliefs)
            
            # Determine color based on probability and state
            if prob_value >= 0.7 or state_label == "High":
                color = "red"
            elif prob_value >= 0.4 or state_label == "Medium":
                color = "yellow"
            else:
                color = "green"
            
            panel = {
                "datasource": "Prometheus",
                "fieldConfig": {
                    "defaults": {
                        "unit": "percentunit",  # Changed from "short" to "percentunit" for better display
                        "min": 0,
                        "max": 1,
                        "decimals": 3,
                        "thresholds": {
                            "mode": "absolute",
                            "steps": [
                                {
                                    "color": "green",
                                    "value": None
                                },
                                {
                                    "color": "yellow",
                                    "value": 0.4
                                },
                                {
                                    "color": "red",
                                    "value": 0.7
                                }
                            ]
                        },
                        "custom": {
                            "displayMode": "basic",
                            "orientation": "auto"
                        },
                        "mappings": [],
                        "color": {
                            "mode": "thresholds"
                        }
                    },
                    "overrides": []
                },
                "gridPos": {
                    "h": 8,
                    "w": 6,
                    "x": x_pos,
                    "y": y_pos
                },
                "id": idx + 1,
                "options": {
                    "reduceOptions": {
                        "values": False,
                        "calcs": [
                            "lastNotNull"
                        ],
                        "fields": ""
                    },
                    "orientation": "auto",
                    "textMode": "value_and_name",
                    "colorMode": "background",
                    "graphMode": "none",
                    "justifyMode": "center",
                    "displayMode": "basic"
                },
                "pluginVersion": "9.0.0",
                "targets": [
                    {
                        "datasource": "Prometheus",
                        "expr": f'{{__name__=~"(binary_bn_|bn_|fuzzy_bn_){node["id"]}_.*",job="fuzzy_bn_service"}}',
                        "interval": "",
                        "legendFormat": "{{__name__}}",  # Use automatic legend formatting
                        "refId": "A",
                        "intervalFactor": 1,
                        "step": 15,  # Add step parameter for better query performance
                        "format": "time_series",  # Explicitly set format
                        "instant": False  # Use range query instead of instant
                    }
                ],
                "title": f"{node['label']}",
                "description": f"Node ID: {node['id']} | Current belief: {belief_display}",
                "type": "stat"
            }
            
            panels.append(panel)
        
        # Debug: Show grid positions for first few panels
        print("\nPanel positions (first 8):")
        for i, panel in enumerate(panels[:8]):
            pos = panel["gridPos"]
            title = panel.get("title", f"Panel {i+1}")
            print(f"Panel {i+1} ({title}): x={pos['x']}, y={pos['y']}, w={pos['w']}, h={pos['h']}")
        
        # 4) Create dashboard payload with enhanced metadata
        dashboard_payload = {
            "dashboard": {
                "title": "Fuzzy Bayesian Network - Node Beliefs",
                "panels": panels,
                "tags": ["auto-generated", "bn", "fuzzy", "beliefs"],
                "schemaVersion": 36,
                "version": 0,
                "refresh": "30s",  # Changed from 5s to 30s for better performance
                "time": {
                    "from": "now-15m",  # Extended time range
                    "to": "now"
                },
                "timepicker": {
                    "refresh_intervals": [
                        "5s",
                        "10s",
                        "30s",
                        "1m",
                        "5m",
                        "15m",
                        "30m",
                        "1h",
                        "2h",
                        "1d"
                    ]
                },
                "annotations": {
                    "list": [
                        {
                            "builtIn": 1,
                            "datasource": {
                                "type": "grafana",
                                "uid": "-- Grafana --"
                            },
                            "enable": True,
                            "hide": True,
                            "iconColor": "rgba(0, 211, 255, 1)",
                            "name": "Annotations & Alerts",
                            "type": "dashboard"
                        }
                    ]
                },
                "editable": True,
                "fiscalYearStartMonth": 0,
                "graphTooltip": 0,
                "links": [],
                "liveNow": False,
                "style": "dark",
                "timezone": "",
                "weekStart": ""
            },
            "overwrite": True
        }

        # 5) Push to Grafana
        url = f"{self.grafana_url}/api/dashboards/db"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        
        print(f"\nPushing dashboard with {len(panels)} panels to Grafana...")
        resp = requests.post(url, json=dashboard_payload, headers=headers)
        resp.raise_for_status()
        
        result = resp.json()
        print(f"Dashboard created successfully!")
        return result["slug"]

# Helper function to troubleshoot specific metrics
def troubleshoot_metric(prometheus_url: str, metric_name: str):
    """
    Troubleshoot a specific Prometheus metric to help debug dashboard issues.
    """
    import requests
    import json
    
    print(f"Troubleshooting metric: {metric_name}")
    print(f"Prometheus URL: {prometheus_url}")
    
    # Test if metric exists
    query_url = f"{prometheus_url}/api/v1/query"
    params = {
        "query": metric_name,
        "time": "now"
    }
    
    try:
        response = requests.get(query_url, params=params)
        response.raise_for_status()
        data = response.json()
        
        print(f"Status: {data['status']}")
        if data['status'] == 'success':
            result = data['data']['result']
            print(f"Found {len(result)} time series for this metric")
            
            if result:
                print("Sample data:")
                for i, ts in enumerate(result[:3]):  # Show first 3 time series
                    print(f"  {i+1}. Labels: {ts.get('metric', {})}")
                    print(f"     Value: {ts.get('value', ['N/A', 'N/A'])[1]}")
            else:
                print("No data found for this metric")
                
                # Try to find similar metrics
                print("\nSearching for similar metrics...")
                all_metrics_response = requests.get(f"{prometheus_url}/api/v1/label/__name__/values")
                if all_metrics_response.status_code == 200:
                    all_metrics = all_metrics_response.json()['data']
                    similar = [m for m in all_metrics if metric_name.split('_')[0] in m]
                    if similar:
                        print("Similar metrics found:")
                        for metric in similar[:10]:
                            print(f"  - {metric}")
                    else:
                        print("No similar metrics found")
        else:
            print(f"Error: {data.get('error', 'Unknown error')}")
            
    except Exception as e:
        print(f"Error querying Prometheus: {e}")
