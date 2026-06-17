"""BeaconButty demo webapp — Flask routes only, all data from demo_data.

No production dependencies: no Zeek, RITA, ClickHouse, Suricata, or live
packet capture. Every page renders fixtures from `demo_data.py`.
Mutating endpoints (FP add/remove, rule toggle, backup run, etc.)
return success without changing state.
"""

from flask import (
    Flask, render_template, jsonify, redirect, url_for, request, flash, abort,
)

import demo_data

app = Flask(__name__)
app.secret_key = "demo-mode-no-secrets"
app.config["DEMO_MODE"] = True


# ── Page routes ───────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("dashboard.html", **demo_data.DASHBOARD)


@app.route("/system")
def system():
    return render_template("system.html")


@app.route("/temperature")
def temperature_legacy():
    return redirect(url_for("system"), code=301)


@app.route("/bandwidth")
def bandwidth():
    return render_template("bandwidth.html")


@app.route("/beacons")
def beacons():
    return render_template("beacons.html", **demo_data.BEACONS)


@app.route("/beacons/slow")
def beacons_slow():
    return render_template("slow_beacons.html", payload=demo_data.SLOW_PAYLOAD)


@app.route("/suricata")
def suricata():
    return render_template("suricata.html", **demo_data.SURICATA)


@app.route("/suricata/rules")
def suricata_rules():
    return render_template("rules.html", **demo_data.RULES)


@app.route("/network")
def network():
    return render_template("network.html", intel=demo_data.NETWORK_INTEL)


@app.route("/assets")
def assets():
    return render_template("assets.html", **demo_data.ASSETS)


@app.route("/fps")
def fps():
    return render_template("fps.html", **demo_data.FPS)


@app.route("/health")
def health():
    return render_template("health.html", **demo_data.HEALTH)


@app.route("/backup")
def backup():
    return render_template("backup.html", **demo_data.BACKUP)


# ── Read-only API routes ──────────────────────────────────────────────────────

@app.route("/api/system")
def api_system():
    return jsonify(demo_data.SYSTEM_TIMESERIES)


@app.route("/api/bandwidth")
def api_bandwidth():
    return jsonify(demo_data.BANDWIDTH_DATA)


@app.route("/api/bandwidth/device-destinations")
def api_bandwidth_drilldown():
    return jsonify(demo_data.BANDWIDTH_DRILLDOWN)


@app.route("/api/alert-config", methods=["GET"])
def api_alert_config_get():
    return jsonify({"enabled": demo_data.ALERT_CONFIG})


@app.route("/api/teams-detector/config", methods=["GET"])
def api_teams_detector_config_get():
    return jsonify({
        "config": demo_data.TEAMS_DETECTOR_CONFIG,
        "report": demo_data.TEAMS_DETECTOR_REPORT,
    })


@app.route("/api/slack-message-count", methods=["GET"])
def api_slack_message_count():
    return jsonify({"count": 0})


# ── Stubbed mutator endpoints ─────────────────────────────────────────────────
# Every mutator returns success without changing state. The demo-mode banner
# in base.html makes this clear to anyone clicking around.

def _stub_ok(message="Demo mode — no changes persisted."):
    return jsonify({"ok": True, "message": message})


def _stub_redirect_back(endpoint="dashboard"):
    target = request.form.get("next") or request.args.get("next") or url_for(endpoint)
    flash("Demo mode — no changes persisted.", "info")
    return redirect(target)


@app.route("/api/pironman-fan", methods=["POST"])
def api_pironman_fan():
    return _stub_ok("Fan override simulated.")


@app.route("/api/alert-config", methods=["POST"])
def api_alert_config_set():
    return _stub_ok()


@app.route("/api/alert-test", methods=["POST"])
def api_alert_test():
    return _stub_ok("Demo mode — test alert simulated, no Slack message sent.")


@app.route("/api/slack-clear-channel", methods=["POST"])
def api_slack_clear_channel():
    return _stub_ok("Demo mode — Slack channel untouched.")


@app.route("/api/teams-detector/config", methods=["POST"])
def api_teams_detector_config_set():
    return _stub_ok()


@app.route("/api/display", methods=["POST"])
def api_display_toggle():
    return _stub_ok("Display toggle simulated.")


# False-positive workflow stubs — all redirect back with a flash message.
@app.route("/fps/add", methods=["POST"])
def fps_add():
    return _stub_redirect_back("fps")


@app.route("/fps/remove", methods=["POST"])
def fps_remove():
    return _stub_redirect_back("fps")


@app.route("/fps/add-domain", methods=["POST"])
def fps_add_domain():
    return _stub_redirect_back("fps")


@app.route("/fps/remove-domain", methods=["POST"])
def fps_remove_domain():
    return _stub_redirect_back("fps")


@app.route("/fps/add-protocol", methods=["POST"])
def fps_add_protocol():
    return _stub_redirect_back("fps")


@app.route("/fps/remove-protocol", methods=["POST"])
def fps_remove_protocol():
    return _stub_redirect_back("fps")


# Suricata rule-management stubs.
@app.route("/suricata/rules/add", methods=["POST"])
def suricata_rules_add():
    return _stub_ok()


@app.route("/suricata/rules/toggle", methods=["POST"])
def suricata_rules_toggle():
    return _stub_ok()


@app.route("/suricata/rules/delete", methods=["POST"])
def suricata_rules_delete():
    return _stub_ok()


@app.route("/suricata/rules/update", methods=["POST"])
def suricata_rules_update():
    return _stub_ok("Ruleset update simulated.")


@app.route("/suricata/rules/search", methods=["GET"])
def suricata_rules_search():
    return jsonify([])


# Backup-workflow stubs.
@app.route("/backup/config/run", methods=["POST"])
def backup_config_run():
    return _stub_ok("Backup simulated.")


@app.route("/backup/config/status", methods=["GET"])
def backup_config_status():
    return jsonify({"active": "inactive", "log": []})


@app.route("/backup/clone/start", methods=["POST"])
def backup_clone_start():
    return _stub_ok("USB clone simulated.")


@app.route("/backup/clone/status", methods=["GET"])
def backup_clone_status():
    return jsonify(demo_data.BACKUP["clone_state"])


@app.route("/backup/archive/run", methods=["POST"])
def backup_archive_run():
    return _stub_ok("Archive simulated.")


@app.route("/backup/archive/status", methods=["GET"])
def backup_archive_status():
    return jsonify(demo_data.BACKUP["archive_state"])


@app.route("/backup/download/<path:filename>")
def backup_download(filename):
    abort(404)


@app.route("/backup/archive/download/<path:filename>")
def backup_archive_download(filename):
    abort(404)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
