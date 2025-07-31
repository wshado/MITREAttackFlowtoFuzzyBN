#bn-ws.py - Enhanced Fuzzy Bayesian Network Web Service

from flask import Flask, request, jsonify, redirect, url_for, render_template_string, abort
from prometheus_client import Gauge, generate_latest, CollectorRegistry, push_to_gateway
from pysmile import Network
import pysmile_license   # loads your SMILE license
import threading
import re
import json
import os
from typing import Dict, List, Any, Optional

app = Flask(__name__)

# — globals —
prob_gauges      = {}   # nid -> {state: Gauge} for fuzzy nodes, or single Gauge for binary
last_values      = {}   # nid -> {state: value} or single value
current_evidence = {}   # nid -> evidence state (int or bool)
current_beliefs  = {}   # nid -> full probability distribution or P(True)
node_info        = {}   # nid -> {type: 'fuzzy'|'binary', states: [state_names]}
log_lines        = []   # list of "📈 nid: old → new"
lock             = threading.Lock()

# — load your BN once —
net = Network()
# Fix path to work from flask_app directory
model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "attack_flow_model.xdsl")
if not os.path.exists(model_path):
    print(f"Warning: Model file not found at {model_path}")
    print("Please ensure attack_flow_model.xdsl exists in the project root")
else:
    net.read_file(model_path)
    print(f"Successfully loaded BN model from {model_path}")

# Prometheus push-gateway configuration
PUSH_GATEWAY_URL = os.getenv('PROMETHEUS_PUSHGATEWAY_URL', 'localhost:9091')
PUSH_JOB_NAME = os.getenv('PROMETHEUS_JOB_NAME', 'fuzzy_bn_service')
USE_PUSH_GATEWAY = os.getenv('USE_PUSH_GATEWAY', 'false').lower() == 'true'

# Fuzzy linguistic mappings
FUZZY_LINGUISTIC_MAP = {
    # Certainty/Likelihood terms
    "very_unlikely": 0, "very_low": 0, "minimal": 0, "none": 0,
    "unlikely": 1, "low": 1, "slight": 1, "minor": 1,
    "possible": 2, "medium": 2, "moderate": 2, "average": 2,
    "likely": 3, "high": 3, "significant": 3, "major": 3,
    "very_likely": 4, "very_high": 4, "extreme": 4, "critical": 4,
    
    # Binary terms
    "false": 0, "no": 0, "absent": 0, "disabled": 0,
    "true": 1, "yes": 1, "present": 1, "enabled": 1
}

# Custom registry for push-gateway
push_registry = CollectorRegistry()

# HTML template
HTML = """
<!doctype html>
<title>Bayes Net Evidence</title>
<style>
  body { margin:0; padding:0; display:flex; height:100vh; font-family:sans-serif; }
  section { flex:1; box-sizing:border-box; padding:1em; overflow:hidden; }
  #logs    { border-right:1px solid #ccc; }
  #set     { border-right:1px solid #ccc; overflow:auto; }
  #beliefs { overflow:auto; }
  h2 { margin-top:0; }
  #logs pre { background:#f7f7f7; height:calc(100% - 1.5em); overflow:auto; white-space:pre-wrap; word-break:break-word; margin:0; padding:0.5em; }
  table { border-collapse:collapse; width:100%; font-size:0.9em; }
  th, td { border:1px solid #ddd; padding:0.3em; text-align:left; }
  td:first-child { font-family:monospace; }
  td:nth-child(2) { text-align:right; }
  button { margin-top:0.5em; padding:0.5em 1em; }
</style>
<section id="logs">
  <h2>Logs</h2>
  <pre>{{ logs|join('\n') }}</pre>
</section>
<section id="set">
  <h2>Set Evidence</h2>
  <form action="{{ url_for('set_evidence') }}" method="post">
    <table>
      <tr><th>Node</th><th>Type</th><th>Available States</th></tr>
    {% for node in nodes %}
      {% set node_info_data = node_info.get(node.id, {'type': 'other', 'states': []}) %}
      <tr>
        <td style="font-family:monospace; font-size:0.8em;">{{ node.label }}</td>
        <td>{{ node_info_data.type }}</td>
        <td>
          <!-- Unset option -->
          <label><input type="radio" name="{{ node.id }}" value="" {% if evidence.get(node.id) is none %}checked{% endif %}> Unset</label>
          
          {% if node_info_data.type == 'fuzzy' %}
            <!-- Fuzzy node with 5 states -->
            {% for i in range(5) %}
              {% set state_name = node_info_data.states[i] if i < node_info_data.states|length else 'State_' + i|string %}
              <label><input type="radio" name="{{ node.id }}" value="{{ i }}" {% if evidence.get(node.id) == i %}checked{% endif %}> {{ state_name }} ({{ i }})</label>
            {% endfor %}
          {% elif node_info_data.type == 'binary' %}
            <!-- Binary node with 2 states -->
            {% for i in range(2) %}
              {% set state_name = node_info_data.states[i] if i < node_info_data.states|length else ('False' if i == 0 else 'True') %}
              <label><input type="radio" name="{{ node.id }}" value="{{ i }}" {% if evidence.get(node.id) == i %}checked{% endif %}> {{ state_name }} ({{ i }})</label>
            {% endfor %}
          {% else %}
            <!-- Other node types - show all available states -->
            {% for i in range(node_info_data.states|length) %}
              {% set state_name = node_info_data.states[i] %}
              <label><input type="radio" name="{{ node.id }}" value="{{ i }}" {% if evidence.get(node.id) == i %}checked{% endif %}> {{ state_name }} ({{ i }})</label>
            {% endfor %}
          {% endif %}
        </td>
      </tr>
    {% endfor %}
    </table>
    <button type="submit">Set Evidence</button>
  </form>
</section>
<section id="beliefs">
  <h2>Current Beliefs</h2>
  {% if beliefs %}
    <table>
      <tr><th>Node</th><th>Belief</th></tr>
    {% for node in nodes %}
      <tr>
        <td>{{ node.label }}</td>
        <td>
        {% set belief = beliefs.get(node.id, 0) %}
        {% if belief is mapping %}
          <!-- Fuzzy node - show most likely state -->
          {% set max_state = belief.items()|list|sort(attribute='1', reverse=true)|first %}
          {{ max_state[0] }}: {{ '%.3f'|format(max_state[1]) }}
        {% else %}
          <!-- Binary node - show P(True) -->
          {{ '%.4f'|format(belief) }}
        {% endif %}
        </td>
      </tr>
    {% endfor %}
    </table>
  {% else %}
    <p><em>— no beliefs computed yet —</em></p>
  {% endif %}
  <form action="{{ url_for('post_get_evidence') }}" method="post">
    <button type="submit">Update Beliefs</button>
  </form>
</section>
"""

def analyze_node_structure():
    """Analyze network structure to identify fuzzy vs binary nodes."""
    global node_info
    node_info.clear()
    
    for h in net.get_all_nodes():
        nid = net.get_node_id(h)
        outcome_count = net.get_outcome_count(h)
        state_names = [net.get_outcome_id(h, i) for i in range(outcome_count)]
        
        if outcome_count == 5 and all(state in ["Very_Low", "Low", "Medium", "High", "Very_High"] for state in state_names):
            node_info[nid] = {"type": "fuzzy", "states": state_names}
        elif outcome_count == 2:
            node_info[nid] = {"type": "binary", "states": state_names}
        else:
            node_info[nid] = {"type": "other", "states": state_names}

def push_metrics_to_gateway():
    """Push current metrics to Prometheus push-gateway."""
    if not USE_PUSH_GATEWAY:
        return
    
    try:
        # Create temporary gauges for push-gateway
        temp_gauges = {}
        
        with lock:
            for nid, gauge_data in prob_gauges.items():
                info = node_info.get(nid, {"type": "other"})
                
                if info["type"] == "fuzzy" and isinstance(gauge_data, dict):
                    # Push each fuzzy state
                    for state, gauge in gauge_data.items():
                        gauge_name = f"fuzzy_bn_{nid}_{state.lower()}"
                        temp_gauge = Gauge(gauge_name, f"P({state}) for {nid}", registry=push_registry)
                        temp_gauge.set(gauge._value._value)
                        temp_gauges[gauge_name] = temp_gauge
                        
                elif info["type"] == "binary" and hasattr(gauge_data, '_value'):
                    # Push binary state
                    gauge_name = f"binary_bn_{nid}"
                    temp_gauge = Gauge(gauge_name, f"P(True) for {nid}", registry=push_registry)
                    temp_gauge.set(gauge_data._value._value)
                    temp_gauges[gauge_name] = temp_gauge
        
        # Push to gateway
        push_to_gateway(PUSH_GATEWAY_URL, job=PUSH_JOB_NAME, registry=push_registry)
        print(f"Successfully pushed {len(temp_gauges)} metrics to push-gateway at {PUSH_GATEWAY_URL}")
        
    except Exception as e:
        print(f"Warning: Failed to push metrics to gateway: {e}")

def init_gauges():
    """Initialize gauges and last values for both fuzzy and binary nodes."""
    analyze_node_structure()
    net.update_beliefs()
    
    with lock:
        prob_gauges.clear()
        last_values.clear()
        
        for h in net.get_all_nodes():
            nid = net.get_node_id(h)
            info = node_info.get(nid, {"type": "other"})
            
            try:
                if info["type"] == "fuzzy":
                    # Create gauges for each fuzzy state
                    prob_gauges[nid] = {}
                    last_values[nid] = {}
                    beliefs = net.get_node_value(h)
                    
                    for i, state in enumerate(info["states"]):
                        gauge_name = f"bn_{nid}_{state.lower()}"
                        # Use appropriate registry
                        registry = push_registry if USE_PUSH_GATEWAY else None
                        prob_gauges[nid][state] = Gauge(gauge_name, f"P({state}) for {nid}", registry=registry)
                        prob_gauges[nid][state].set(beliefs[i])
                        last_values[nid][state] = beliefs[i]
                        
                elif info["type"] == "binary":
                    # Single gauge for P(True) for binary nodes
                    p_true = net.get_node_value(h)[1] if len(net.get_node_value(h)) > 1 else 0.5
                    registry = push_registry if USE_PUSH_GATEWAY else None
                    prob_gauges[nid] = Gauge(f"bn_{nid}", f"P(True) for {nid}", registry=registry)
                    prob_gauges[nid].set(p_true)
                    last_values[nid] = p_true
                    
            except Exception as e:
                print(f"Warning: Could not initialize gauge for {nid}: {e}")
                continue
    
    # Initial push to gateway if enabled
    if USE_PUSH_GATEWAY:
        push_metrics_to_gateway()

def parse_linguistic_input(linguistic_value: str) -> Optional[int]:
    """Convert linguistic input to numeric state index."""
    if isinstance(linguistic_value, (int, float)):
        return int(linguistic_value)
    
    if isinstance(linguistic_value, str):
        # Normalize input
        normalized = linguistic_value.lower().strip().replace(" ", "_")
        return FUZZY_LINGUISTIC_MAP.get(normalized)
    
    return None

def find_node_by_partial_name(partial_name: str) -> Optional[str]:
    """Find node ID by partial name matching."""
    partial_lower = partial_name.lower()
    
    # Try exact match first
    for nid in node_info.keys():
        if nid.lower() == partial_lower:
            return nid
    
    # Try partial match
    for nid in node_info.keys():
        if partial_lower in nid.lower():
            return nid
    
    # Try technique name matching
    for h in net.get_all_nodes():
        nid = net.get_node_id(h)
        try:
            node_name = net.get_node_name(h).lower()
            if partial_lower in node_name:
                return nid
        except:
            continue
    
    return None


def update_gauges_and_beliefs():
    """Rerun inference, update gauges, log changes, fill current_beliefs for fuzzy and binary nodes."""
    global current_beliefs, log_lines
    net.update_beliefs()

    log_lines.clear()
    current_beliefs.clear()
    
    # Calculate mission risk for aggregation
    all_risks = []

    with lock:
        for h in net.get_all_nodes():
            nid = net.get_node_id(h)
            info = node_info.get(nid, {"type": "other"})
            
            try:
                beliefs = net.get_node_value(h)
                
                if info["type"] == "fuzzy":
                    # Handle fuzzy nodes with unified metric naming
                    if nid not in prob_gauges:
                        prob_gauges[nid] = {}
                        last_values[nid] = {}
                        
                        # Create most likely probability gauge (for dashboard)
                        registry = push_registry if USE_PUSH_GATEWAY else None
                        prob_gauges[nid]['most_likely'] = Gauge(
                            f"bn_{nid}_most_likely_prob", 
                            f"Most likely state probability for {nid}", 
                            registry=registry
                        )
                        
                        # Create individual state gauges
                        for i, state in enumerate(info["states"]):
                            gauge_name = f"bn_{nid}_{state.lower()}"
                            prob_gauges[nid][state] = Gauge(gauge_name, f"P({state}) for {nid}", registry=registry)
                    
                    # Update each state probability
                    state_beliefs = {}
                    changes = []
                    max_prob = 0.0
                    
                    for i, state in enumerate(info["states"]):
                        new_prob = beliefs[i] if i < len(beliefs) else 0.0
                        old_prob = last_values[nid].get(state)
                        
                        if old_prob is None or abs(new_prob - old_prob) > 1e-6:
                            changes.append(f"{state}:{old_prob!r}→{new_prob:.4f}")
                            prob_gauges[nid][state].set(new_prob)
                            last_values[nid][state] = new_prob
                        
                        state_beliefs[state] = new_prob
                        max_prob = max(max_prob, new_prob)
                    
                    # Update most likely probability gauge
                    prob_gauges[nid]['most_likely'].set(max_prob)
                    all_risks.append(max_prob)
                    
                    if changes:
                        log_lines.append(f"📈 {nid}: {', '.join(changes)}")
                    
                    current_beliefs[nid] = state_beliefs
                    
                elif info["type"] == "binary":
                    # Handle binary nodes with unified naming
                    p_true = beliefs[1] if len(beliefs) > 1 else 0.5
                    
                    if nid not in prob_gauges:
                        registry = push_registry if USE_PUSH_GATEWAY else None
                        prob_gauges[nid] = {
                            'main': Gauge(f"bn_{nid}_most_likely_prob", f"P(True) for {nid}", registry=registry),
                            'binary': Gauge(f"bn_{nid}", f"P(True) for {nid}", registry=registry)  # Legacy compatibility
                        }
                        last_values[nid] = None

                    old = last_values.get(nid)
                    if old is None or abs(p_true - old) > 1e-6:
                        log_lines.append(f"📈 {nid}: {old!r} → {p_true:.4f}")
                        prob_gauges[nid]['main'].set(p_true)
                        prob_gauges[nid]['binary'].set(p_true)
                        last_values[nid] = p_true

                    current_beliefs[nid] = p_true
                    all_risks.append(p_true)
                    
            except Exception as e:
                print(f"Warning: Could not update beliefs for {nid}: {e}")
                continue
        
        # Calculate and update mission risk assessment
        if all_risks:
            mission_risk_value = max(all_risks)  # Highest risk determines mission risk
            
            # Create mission risk gauge if not exists
            if 'mission_risk' not in prob_gauges:
                registry = push_registry if USE_PUSH_GATEWAY else None
                prob_gauges['mission_risk'] = Gauge(
                    "mission_risk_assessment", 
                    "Overall mission risk assessment", 
                    registry=registry
                )
            
            prob_gauges['mission_risk'].set(mission_risk_value)
            
            # Log mission risk classification
            if mission_risk_value >= 0.8:
                risk_level = "Very High"
            elif mission_risk_value >= 0.6:
                risk_level = "High"
            elif mission_risk_value >= 0.4:
                risk_level = "Medium"
            elif mission_risk_value >= 0.2:
                risk_level = "Low"
            else:
                risk_level = "Very Low"
                
            log_lines.append(f"🚨 Mission Risk: {risk_level} ({mission_risk_value:.3f})")
    
    # Push updated metrics to gateway if enabled
    if USE_PUSH_GATEWAY:
        push_metrics_to_gateway()

@app.route("/reload", methods=["POST"])
def reload_net():
    """Reload network from file, reset state, re-init gauges/beliefs."""
    global net, prob_gauges, last_values, current_evidence, current_beliefs, log_lines
    filepath = request.args.get("file", "../attack_flow_model.xdsl")
    try:
        net = Network()
        net.read_file(filepath)

        # reset state
        prob_gauges.clear()
        last_values.clear()
        current_evidence.clear()
        current_beliefs.clear()
        log_lines.clear()

        init_gauges()
        update_gauges_and_beliefs()
        return f"Reloaded network from {filepath}", 200
    except Exception as e:
        return f"Failed to reload: {e}", 500

@app.route("/set_evidence", methods=["POST"])
def set_evidence():
    """Apply evidence from form, update beliefs, redirect."""
    global current_evidence
    
    try:
        # Ensure network is in a valid state
        if not net or len(list(net.get_all_nodes())) == 0:
            print("⚠️ Network not properly loaded, attempting to reload...")
            try:
                net.read_file(model_path)
                analyze_node_structure()
                init_gauges()
            except Exception as reload_error:
                print(f"⚠️ Failed to reload network: {reload_error}")
                return f"Network error: {reload_error}", 500
        
        ev = {}
        
        for h in net.get_all_nodes():
            try:
                nid = net.get_node_id(h)
                v = request.form.get(nid, "")
                
                # Skip if no value provided (unset)
                if not v:
                    continue
                    
                # Convert to integer state index
                state_index = int(v)
                info = node_info.get(nid, {"type": "other"})
                
                # Validate state index based on node type
                if info["type"] == "fuzzy" and 0 <= state_index <= 4:
                    ev[nid] = state_index
                elif info["type"] == "binary" and 0 <= state_index <= 1:
                    ev[nid] = state_index
                elif info["type"] == "other":
                    # For other node types, validate against available states
                    max_states = len(info.get("states", []))
                    if 0 <= state_index < max_states:
                        ev[nid] = state_index
                    else:
                        print(f"⚠️ Invalid state index {state_index} for node {nid} (max: {max_states-1})")
                        continue
                else:
                    print(f"⚠️ Invalid state index {state_index} for {info['type']} node {nid}")
                    continue
                    
            except ValueError as ve:
                print(f"⚠️ Invalid state value '{v}' for node {nid}: {ve}")
                continue
            except Exception as ne:
                print(f"⚠️ Error processing node {nid}: {ne}")
                continue

        current_evidence = ev
        
        # Clear all evidence first
        try:
            net.clear_all_evidence()
        except Exception as clear_error:
            print(f"⚠️ Failed to clear evidence: {clear_error}")
            return f"Evidence clearing error: {clear_error}", 500
        
        # Set evidence for each node
        evidence_errors = []
        for nid, state_index in current_evidence.items():
            try:
                # Validate node exists before setting evidence
                node_handle = None
                for h in net.get_all_nodes():
                    if net.get_node_id(h) == nid:
                        node_handle = h
                        break
                
                if node_handle is None:
                    evidence_errors.append(f"Node {nid} not found in network")
                    continue
                
                # Validate state index against actual node outcomes
                outcome_count = net.get_outcome_count(node_handle)
                if state_index >= outcome_count:
                    evidence_errors.append(f"State index {state_index} invalid for node {nid} (max: {outcome_count-1})")
                    continue
                
                net.set_evidence(nid, state_index)
                print(f"✅ Set evidence for {nid}: state {state_index}")
                
            except Exception as e:
                error_msg = f"Failed to set evidence for {nid}: {e}"
                print(f"⚠️ {error_msg}")
                evidence_errors.append(error_msg)

        # Update beliefs even if some evidence setting failed
        try:
            update_gauges_and_beliefs()
        except Exception as update_error:
            print(f"⚠️ Failed to update beliefs: {update_error}")
            return f"Belief update error: {update_error}", 500
        
        # If there were evidence errors, log them but don't fail the request
        if evidence_errors:
            print(f"⚠️ Evidence setting completed with {len(evidence_errors)} errors:")
            for error in evidence_errors:
                print(f"  - {error}")
        
        return redirect(url_for("index"))
        
    except Exception as e:
        error_msg = f"Internal error in set_evidence: {e}"
        print(f"⚠️ {error_msg}")
        import traceback
        traceback.print_exc()
        return f"Internal server error: {error_msg}", 500

@app.route("/get_evidence", methods=["POST"])
def post_get_evidence():
    """Legacy POST endpoint for updating beliefs."""
    update_gauges_and_beliefs()
    return redirect(url_for("index"))

@app.route("/report", methods=["POST"])
def report():
    """Accept linguistic evidence via JSON API."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    results = {"processed": {}, "errors": [], "updated_nodes": []}
    
    for key, linguistic_value in data.items():
        # Find matching node
        node_id = find_node_by_partial_name(key)
        if not node_id:
            results["errors"].append(f"Node not found for key: {key}")
            continue
        
        # Parse linguistic input
        evidence_state = parse_linguistic_input(linguistic_value)
        if evidence_state is None:
            results["errors"].append(f"Could not parse linguistic value '{linguistic_value}' for {key}")
            continue
        
        # Validate evidence state for node type
        info = node_info.get(node_id, {"type": "other"})
        if info["type"] == "fuzzy" and not (0 <= evidence_state <= 4):
            results["errors"].append(f"Invalid fuzzy state {evidence_state} for {key} (must be 0-4)")
            continue
        elif info["type"] == "binary" and evidence_state not in [0, 1]:
            results["errors"].append(f"Invalid binary state {evidence_state} for {key} (must be 0 or 1)")
            continue
        
        # Set evidence
        try:
            net.set_evidence(node_id, evidence_state)
            current_evidence[node_id] = evidence_state
            results["processed"][key] = {
                "node_id": node_id,
                "linguistic_input": linguistic_value,
                "evidence_state": evidence_state,
                "node_type": info["type"]
            }
            results["updated_nodes"].append(node_id)
        except Exception as e:
            results["errors"].append(f"Failed to set evidence for {key}: {str(e)}")
    
    # Update beliefs after setting all evidence
    if results["updated_nodes"]:
        update_gauges_and_beliefs()
    
    return jsonify({
        "status": "evidence processed",
        "results": results,
        "current_beliefs_sample": {nid: beliefs for nid, beliefs in list(current_beliefs.items())[:3]}
    })

@app.route("/inference", methods=["GET"])
def inference():
    """Query current node states and probabilities."""
    node_filter = request.args.get('nodes', '').split(',') if request.args.get('nodes') else []
    include_evidence = request.args.get('evidence', 'false').lower() == 'true'
    
    result = {
        "nodes": {},
        "evidence": current_evidence if include_evidence else {},
        "node_types": {}
    }
    
    nodes_to_include = node_filter if node_filter and node_filter[0] else list(current_beliefs.keys())
    
    for nid in nodes_to_include:
        if nid in current_beliefs:
            beliefs = current_beliefs[nid]
            info = node_info.get(nid, {"type": "other"})
            
            if info["type"] == "fuzzy":
                # Return full state distribution for fuzzy nodes
                result["nodes"][nid] = {
                    "type": "fuzzy",
                    "states": beliefs,
                    "most_likely": max(beliefs.items(), key=lambda x: x[1]) if beliefs else None
                }
            elif info["type"] == "binary":
                # Return P(True) and P(False) for binary nodes
                p_true = beliefs if isinstance(beliefs, (int, float)) else 0.5
                result["nodes"][nid] = {
                    "type": "binary",
                    "P(True)": p_true,
                    "P(False)": 1.0 - p_true
                }
            
            result["node_types"][nid] = info["type"]
    
    return jsonify(result)

@app.route("/evidence", methods=["GET"])
def get_evidence():
    """Legacy endpoint - returns current evidence."""
    return jsonify({
        "current_evidence": current_evidence,
        "note": "This endpoint is deprecated. Use /inference for comprehensive state queries."
    })

@app.route("/beliefs", methods=["GET"])
def get_beliefs():
    """Get current belief states for all nodes - used by dashboard generator."""
    result = {}
    
    for nid, beliefs in current_beliefs.items():
        info = node_info.get(nid, {"type": "other"})
        
        if info["type"] == "fuzzy" and isinstance(beliefs, dict):
            # For fuzzy nodes, find the most likely state
            if beliefs:
                most_likely_state, probability = max(beliefs.items(), key=lambda x: x[1])
                result[nid] = {
                    "most_likely_state": most_likely_state,
                    "probability": probability,
                    "full_distribution": beliefs,
                    "type": "fuzzy"
                }
            else:
                result[nid] = {
                    "most_likely_state": "Unknown",
                    "probability": 0.2,  # Default uniform for 5 states
                    "full_distribution": {},
                    "type": "fuzzy"
                }
        elif info["type"] == "binary":
            # For binary nodes, return P(True)
            p_true = beliefs if isinstance(beliefs, (int, float)) else 0.5
            if p_true >= 0.7:
                state = "High"
            elif p_true >= 0.4:
                state = "Medium" 
            else:
                state = "Low"
            
            result[nid] = {
                "most_likely_state": state,
                "probability": p_true,
                "p_true": p_true,
                "type": "binary"
            }
        else:
            # For other node types, provide basic information
            result[nid] = {
                "most_likely_state": "Unknown",
                "probability": 0.5,
                "type": info["type"]
            }
    
    return jsonify(result)

@app.route("/metrics")
def metrics():
    """Standard Prometheus metrics endpoint."""
    return generate_latest()

@app.route("/push_metrics", methods=["POST"])
def manual_push_metrics():
    """Manually push metrics to Prometheus push-gateway."""
    if not USE_PUSH_GATEWAY:
        return jsonify({
            "error": "Push-gateway not enabled",
            "note": "Set USE_PUSH_GATEWAY=true environment variable to enable"
        }), 400
    
    try:
        push_metrics_to_gateway()
        return jsonify({
            "status": "success",
            "message": f"Metrics pushed to {PUSH_GATEWAY_URL}",
            "job_name": PUSH_JOB_NAME,
            "metrics_count": len(prob_gauges)
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route("/status", methods=["GET"])
def status():
    """Service status and configuration."""
    return jsonify({
        "service": "Fuzzy Bayesian Network Web Service",
        "model_loaded": len(node_info) > 0,
        "total_nodes": len(node_info),
        "fuzzy_nodes": len([n for n in node_info.values() if n["type"] == "fuzzy"]),
        "binary_nodes": len([n for n in node_info.values() if n["type"] == "binary"]),
        "current_evidence_count": len(current_evidence),
        "prometheus_config": {
            "push_gateway_enabled": USE_PUSH_GATEWAY,
            "push_gateway_url": PUSH_GATEWAY_URL if USE_PUSH_GATEWAY else None,
            "job_name": PUSH_JOB_NAME if USE_PUSH_GATEWAY else None,
            "metrics_endpoint": "/metrics"
        },
        "api_endpoints": {
            "linguistic_input": "/report (POST)",
            "inference_query": "/inference (GET)",
            "manual_push": "/push_metrics (POST)",
            "status": "/status (GET)",
            "legacy_evidence": "/api/evidence (POST)"
        }
    })

@app.route("/api/evidence", methods=["POST"])
def api_evidence():
    """Legacy evidence API - deprecated in favor of /report."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data"}), 400

    for nid, value in data.items():
        if nid in node_info:
            try:
                if isinstance(value, bool):
                    net.set_evidence(nid, 1 if value else 0)
                    current_evidence[nid] = value
                elif value in [0, 1, 2, 3, 4]:  # Support fuzzy states
                    net.set_evidence(nid, value)
                    current_evidence[nid] = value
            except Exception as e:
                print(f"Warning: Could not set evidence for {nid}: {e}")

    update_gauges_and_beliefs()
    return jsonify({
        "status": "evidence updated", 
        "current": current_evidence,
        "note": "This endpoint is deprecated. Use /report for linguistic input."
    })

@app.route("/ttps", methods=["GET"])
def ttps():
    out = []
    for h in net.get_all_nodes():
        nid = net.get_node_id(h)
        label = net.get_node_name(h) or nid
        info = node_info.get(nid, {"type": "other"})
        out.append({
            "id": nid, 
            "label": label,
            "type": info["type"],
            "states": info.get("states", [])
        })
    return jsonify(out)

@app.route("/shutdown", methods=["POST"])
def shutdown():
    func = request.environ.get("werkzeug.server.shutdown")
    if not func:
        abort(500, "Not running with the Werkzeug Server")
    func()
    return "Server shutting down…", 200

@app.route("/", methods=["GET"])
def index():
    nodes = []
    for h in net.get_all_nodes():
        nid = net.get_node_id(h)
        label = net.get_node_name(h) or nid
        nodes.append({"id":nid, "label":label})
    return render_template_string(HTML, 
                                nodes=nodes, 
                                evidence=current_evidence, 
                                beliefs=current_beliefs, 
                                logs=log_lines,
                                node_info=node_info)

if __name__ == "__main__":
    print("Starting Fuzzy Bayesian Network Web Service...")
    print(f"Model path: {model_path}")
    print(f"Push-gateway enabled: {USE_PUSH_GATEWAY}")
    if USE_PUSH_GATEWAY:
        print(f"Push-gateway URL: {PUSH_GATEWAY_URL}")
        print(f"Job name: {PUSH_JOB_NAME}")
    
    init_gauges()
    update_gauges_and_beliefs()
    
    print(f"Initialized {len(node_info)} nodes:")
    fuzzy_count = len([n for n in node_info.values() if n["type"] == "fuzzy"])
    binary_count = len([n for n in node_info.values() if n["type"] == "binary"])
    print(f"  - {fuzzy_count} fuzzy nodes (5-state)")
    print(f"  - {binary_count} binary nodes (2-state)")
    
    print("\nAPI Endpoints:")
    print("  POST /report - Linguistic evidence input")
    print("  GET /inference - Query node states")
    print("  GET /metrics - Prometheus metrics")
    print("  POST /push_metrics - Manual push to gateway")
    print("  GET /status - Service status")
    
    app.run(host="0.0.0.0", port=8000)
