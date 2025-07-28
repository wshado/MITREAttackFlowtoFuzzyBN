import os, sys, subprocess, re, requests
from bn_creator.attack_flow_parser import AttackFlowProcessor
from bn_creator.grouping_util import GroupingUtil
from bn_creator.BN_creation import BNBuilder
from dashboard_generator import GrafanaDashboardGenerator

class UserInterface:
    def __init__(self, corpus_folder="downloaded_attack_flow_jsons"):
        self.processor = AttackFlowProcessor()
        self.corpus_folder = corpus_folder

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

    def run(self):
        all_files = self.list_corpus_files()
        selected_path = self.select_file(all_files)

        out_name, new_bundle, used_ids, parent_map, child_map, condition_nodes, recommendations, id_to_obj, relationships = self.processor.process_file(selected_path)

        # print(f"\nRebuilt file: {out_name}")
        # print(f"STIX Bundle object returned (you can inspect programmatically):\n{new_bundle}")

        return new_bundle, used_ids, parent_map, child_map, condition_nodes, recommendations, id_to_obj, relationships

if __name__ == "__main__":
    ui = UserInterface()
    new_bundle, used_ids, parent_map, child_map, condition_nodes, recommendations, id_to_obj, relationships = ui.run()
    ##CHECK JSON

    # Instantiate the grouping utility
    util = GroupingUtil(
        parent_map=parent_map,
        child_map=child_map,
        recommendations=recommendations,
        id_to_obj=id_to_obj
    )
    graph_edges = [(src['id'], tgt['id']) for src, tgt in relationships]
    # Compute partition and divorce groups
    partitioned = util.get_partition_groups()
    divorced   = util.get_divorce_groups()
    logic_groups = util.get_logic_groups()
    ##CHECK JSON
    #GET NAME FROM BUNDLE
    # Build and write BN
    builder = BNBuilder(
        used_ids, #ADD NAME
        graph_edges,
        partitioned,
        divorced,
        logic_groups,
        recommendations,
        id_to_obj=id_to_obj,
        parent_map=parent_map,
        child_map=child_map
    )
    net = builder.build()
    builder.write_xdsl("attack_flow_model.xdsl")
    print("Attack flow Bayseian Network available at attack_flow_model.xdsl")

    # try to shut down any existing server
    try:
        requests.post("http://localhost:8000/shutdown", timeout=2)
        print("Stopped previous BN web-service.")
    except Exception:
        # probably nothing was running
        pass

    host = input("Do you want to launch the BN web‐service now? [y/N]: ").strip().lower()
    if host == "y":
        print("Starting Flask web-service (bn-ws.py) in the background…")
        # sys.executable is the full path to the current interpreter (your venv python)
        cmd = [sys.executable, "-u", "./flask_app/bn-ws.py"]
        process = subprocess.Popen(
            cmd,
            cwd=os.path.dirname(__file__),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        # wait until we see Flask’s “Running on …:8000” banner
        for line in process.stdout:
            print(line, end="")
            if re.search(r"Running on .*:8000", line):
                break

        print("\nFlask server is up!  Browse to http://localhost:8000/\n")
    else:
        print("You can start it anytime with:\n    python bn-ws.py")


    print(
        "Next, make sure you have:\n"
        "  - Prometheus running with your scrape config pointing at http://localhost:8000/metrics\n"
        "  - Grafana installed and reachable at http://localhost:3000/ (login, add a Prometheus data-source with UID 'Prometheus')\n"
        )

    # Prompt to push the dashboard into Grafana
    push_dash = input("Push new Grafana dashboard now? [y/N]: ").strip().lower()
    if push_dash == "y":
        gen = GrafanaDashboardGenerator(
            grafana_url="http://localhost:3000",
            api_key="<GRAFANA ACCESS TOKEN",
            prom_node_list_url="http://localhost:8000/ttps",
            xdsl_path="attack_flow_model.xdsl",
            prometheus_datasource_uid="Prometheus",
            node_prefix="attack_action__",
            panels_per_row=4
        )
        slug = gen.generate_dashboard()
        print(f"Dashboard created: {gen.grafana_url}/d/{slug}\n")
    else:
        print(
            "To push later, run something like:\n"
            "  python -c \"from dashboard_generator import GrafanaDashboardGenerator; ...\""
        )

    print("All done.")