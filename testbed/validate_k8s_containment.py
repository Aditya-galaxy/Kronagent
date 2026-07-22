#!/usr/bin/env python3
"""
Automated validation of Kubernetes active pod containment using a Kind cluster.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time

KIND_CLUSTER_NAME = "aegis-testbed"
CALICO_MANIFEST = "https://raw.githubusercontent.com/projectcalico/calico/v3.25.0/manifests/calico.yaml"


def log(msg: str) -> None:
    print(f"\n>>> [TESTBED] {msg}", flush=True)


def check_prerequisites() -> None:
    log("Checking prerequisites...")
    for tool in ["docker", "kind", "kubectl"]:
        if not shutil.which(tool):
            print(f"Error: Required tool '{tool}' is not installed or not in PATH.")
            sys.exit(1)
    log("Prerequisites verified.")


def run_cmd(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(args)}", flush=True)
    return subprocess.run(args, check=check, capture_output=True, text=True)


def create_kind_cluster() -> None:
    log("Creating Kind cluster with custom config...")
    # Clean up existing cluster if it remains from a previous run
    run_cmd(["kind", "delete", "cluster", "--name", KIND_CLUSTER_NAME], check=False)

    config_path = os.path.join(os.path.dirname(__file__), "kind-config.yaml")
    run_cmd(["kind", "create", "cluster", "--config", config_path, "--name", KIND_CLUSTER_NAME])
    log("Kind cluster created successfully.")


def install_calico() -> None:
    log("Installing Calico CNI for NetworkPolicy enforcement...")
    run_cmd(["kubectl", "apply", "-f", CALICO_MANIFEST])

    log("Waiting for Calico daemonset rollout...")
    # Calico can take a few minutes to start up. Loop until it is rolled out.
    for _ in range(12):
        res = run_cmd(["kubectl", "rollout", "status", "daemonset/calico-node", "-n", "kube-system"], check=False)
        if res.returncode == 0:
            log("Calico CNI successfully installed and active.")
            return
        time.sleep(10)
    print("Warning: Calico node daemonset rollout timeout. Continuing test anyway.")


def deploy_test_pods() -> None:
    log("Deploying test workloads...")

    victim_manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "victim-server",
            "labels": {"app": "victim-server"},
        },
        "spec": {
            "containers": [{
                "name": "web",
                "image": "python:3.9-slim",
                "command": ["python3", "-m", "http.server", "8080"],
                "ports": [{"containerPort": 8080}],
            }]
        },
    }

    attacker_manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "attacker-client",
            "labels": {"app": "attacker-client"},
        },
        "spec": {
            "containers": [{
                "name": "curl",
                "image": "curlimages/curl:latest",
                "command": ["sleep", "3600"],
            }]
        },
    }

    # Write temporary manifests and apply
    for name, manifest in [("victim.json", victim_manifest), ("attacker.json", attacker_manifest)]:
        with open(name, "w") as fh:
            json.dump(manifest, fh)
        run_cmd(["kubectl", "apply", "-f", name])
        os.remove(name)

    log("Waiting for pods to be ready...")
    run_cmd(["kubectl", "wait", "--for=condition=Ready", "pod/victim-server", "pod/attacker-client", "--timeout=120s"])
    log("Workloads successfully deployed.")


def verify_containment() -> None:
    log("Resolving pod IP...")
    res = run_cmd(["kubectl", "get", "pod", "victim-server", "-o", "jsonpath={.status.podIP}"])
    victim_ip = res.stdout.strip()
    log(f"victim-server IP: {victim_ip}")

    # 1. Test baseline connection
    log("Asserting baseline connection (should succeed)...")
    res = run_cmd(["kubectl", "exec", "attacker-client", "--", "curl", "-s", "-m", "3", f"http://{victim_ip}:8080"])
    assert res.returncode == 0, f"Baseline connection failed: {res.stderr}"
    log("Baseline connection verified.")

    # 2. Trigger containment adapter
    log("Triggering Aegis K8sContainmentAdapter active isolation...")
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from aegis.providers.k8s import K8sContainmentAdapter
    from aegis.schemas import ActionClass, ProposedAction

    # Context format for Kind clusters is: kind-<cluster-name>
    adapter = K8sContainmentAdapter(context=f"kind-{KIND_CLUSTER_NAME}")
    action = ProposedAction(
        provider="kubernetes",
        action_class=ActionClass.ISOLATE_POD,
        target="victim-server",
        rationale="Isolate compromised server in validation run.",
        parameters={"namespace": "default"},
    )
    detail, rollback = adapter._perform_sync(action)
    log(f"Aegis Containment Response: {detail}")

    # 3. Test blocked connection
    log("Asserting connection is now blocked (should time out)...")
    # We expect curl connection to time out with exit code 28 (or non-zero)
    res = run_cmd(["kubectl", "exec", "attacker-client", "--", "curl", "-s", "-m", "5", f"http://{victim_ip}:8080"], check=False)
    assert res.returncode != 0, f"Error: connection succeeded after containment! Output: {res.stdout}"
    log("Pod containment successfully verified! Connection is blocked.")


def cleanup() -> None:
    log("Cleaning up testbed resources...")
    run_cmd(["kind", "delete", "cluster", "--name", KIND_CLUSTER_NAME])
    log("Cleanup completed.")


def main() -> None:
    check_prerequisites()
    try:
        create_kind_cluster()
        install_calico()
        deploy_test_pods()
        verify_containment()
        log("Test run: SUCCESS.")
    except Exception as exc:
        print(f"\n!!! Validation Failed: {exc}")
        sys.exit(1)
    finally:
        cleanup()


if __name__ == "__main__":
    main()
