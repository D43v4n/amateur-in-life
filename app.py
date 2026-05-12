import os
from dotenv import load_dotenv
load_dotenv()
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from validators import validate_ip, validate_port, get_ip_type
from app_id_data import get_suggestions
from osint import (check_insecure_ports, get_base_ip,
                   check_abuseipdb, check_virustotal, get_combined_verdict)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = "fw-approver-coke-2024"
app.config["SQLALCHEMY_DATABASE_URI"] = f'sqlite:///{os.path.join(BASE_DIR, "firewall_rules.db")}'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
app.jinja_env.globals["get_ip_type"] = get_ip_type


class FirewallRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_origen = db.Column(db.String(100), nullable=False)
    ip_destino = db.Column(db.String(100), nullable=False)
    puerto = db.Column(db.String(100), nullable=False)
    protocolo = db.Column(db.String(20), nullable=False)
    app_id = db.Column(db.String(200))
    accion = db.Column(db.String(20), nullable=False)
    direccion = db.Column(db.String(20), nullable=False)
    comentario = db.Column(db.Text)
    estado = db.Column(db.String(20), default="pending")
    reputation_verdict = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


with app.app_context():
    db.create_all()
    with db.engine.connect() as conn:
        try:
            conn.execute(db.text("ALTER TABLE firewall_rule ADD COLUMN reputation_verdict VARCHAR(20)"))
            conn.commit()
        except Exception:
            pass


def _validate_rule(d):
    errors = {}

    ip_origen = d.get("ip_origen", "").strip()
    if not ip_origen:
        errors["ip_origen"] = "Required field"
    else:
        ok, msg = validate_ip(ip_origen)
        if not ok:
            errors["ip_origen"] = msg

    ip_destino = d.get("ip_destino", "").strip()
    if not ip_destino:
        errors["ip_destino"] = "Required field"
    else:
        ok, msg = validate_ip(ip_destino)
        if not ok:
            errors["ip_destino"] = msg

    puerto = d.get("puerto", "").strip()
    if not puerto:
        errors["puerto"] = "Required field"
    else:
        ok, msg = validate_port(puerto)
        if not ok:
            errors["puerto"] = msg

    if d.get("protocolo", "") not in ("tcp", "udp", "icmp"):
        errors["protocolo"] = "Select a valid protocol"

    if d.get("accion", "") not in ("allow", "deny", "drop"):
        errors["accion"] = "Select an action"

    if d.get("direccion", "") not in ("unidirectional", "bidirectional"):
        errors["direccion"] = "Select a direction"

    return errors


@app.route("/", methods=["GET", "POST"])
def new_rule():
    if request.method == "POST":
        fields = ["ip_origen", "ip_destino", "puerto", "protocolo",
                  "app_id", "accion", "direccion", "comentario", "reputation_verdict"]
        lists = {f: request.form.getlist(f"{f}[]") for f in fields}
        count = len(lists["ip_origen"])

        rules_data = []
        for i in range(count):
            d = {f: (lists[f][i] if i < len(lists[f]) else "") for f in fields}
            d["errors"] = _validate_rule(d)
            rules_data.append(d)

        if all(not d["errors"] for d in rules_data):
            for d in rules_data:
                verdict = d.get("reputation_verdict", "").strip() or None
                db.session.add(FirewallRule(
                    ip_origen=d["ip_origen"].strip(),
                    ip_destino=d["ip_destino"].strip(),
                    puerto=d["puerto"].strip(),
                    protocolo=d["protocolo"],
                    app_id=d["app_id"].strip() or None,
                    accion=d["accion"],
                    direccion=d["direccion"],
                    comentario=d["comentario"].strip() or None,
                    reputation_verdict=verdict,
                ))
            db.session.commit()
            n = len(rules_data)
            flash(f"{'Request created' if n == 1 else f'{n} requests created'} successfully.", "success")
            return redirect(url_for("rules"))

        return render_template("new_rule.html", rules_data=rules_data)

    return render_template("new_rule.html", rules_data=[{}])


@app.route("/rules")
def rules():
    all_rules = FirewallRule.query.order_by(FirewallRule.created_at.desc()).all()
    return render_template("rules.html", rules=all_rules)


@app.route("/rules/<int:rule_id>/delete", methods=["POST"])
def delete_rule(rule_id):
    rule = FirewallRule.query.get_or_404(rule_id)
    db.session.delete(rule)
    db.session.commit()
    flash("Request deleted.", "warning")
    return redirect(url_for("rules"))


@app.route("/api/validate-rule", methods=["POST"])
def validate_rule_osint():
    from concurrent.futures import ThreadPoolExecutor

    data = request.get_json(silent=True) or {}
    ip_destino = data.get("ip_destino", "").strip()
    puerto     = data.get("puerto", "").strip()

    result = {
        "valid":          True,
        "verdict":        None,
        "errors":         [],
        "warnings":       [],
        "is_public_dest": False,
        "insecure_ports": [],
        "abuseipdb":      None,
        "virustotal":     None,
    }

    # ── Insecure port check (always) ─────────────────────────────────────
    if puerto:
        bad_ports = check_insecure_ports(puerto)
        if bad_ports:
            result["insecure_ports"] = bad_ports
            names = ", ".join(f"{p['port']} ({p['name']})" for p in bad_ports)
            result["errors"].append(
                f"Plaintext/insecure port(s) detected: {names}. "
                f"Use encrypted equivalents (e.g. 443, 22, 587/TLS)."
            )
            result["valid"] = False

    # ── Reputation check for public destination IPs ───────────────────────
    if ip_destino and get_ip_type(ip_destino) == "public":
        result["is_public_dest"] = True
        base_ip = get_base_ip(ip_destino)

        has_abuse_key = bool(os.environ.get("ABUSEIPDB_API_KEY"))
        has_vt_key    = bool(os.environ.get("VIRUSTOTAL_API_KEY"))

        if not has_abuse_key and not has_vt_key:
            result["warnings"].append(
                "Reputation check skipped — configure ABUSEIPDB_API_KEY and/or "
                "VIRUSTOTAL_API_KEY to enable threat intelligence lookups."
            )
        else:
            # Run both queries in parallel
            with ThreadPoolExecutor(max_workers=2) as pool:
                f_abuse = pool.submit(check_abuseipdb, base_ip) if has_abuse_key else None
                f_vt    = pool.submit(check_virustotal, base_ip) if has_vt_key    else None
                abuse_data = f_abuse.result() if f_abuse else None
                vt_data    = f_vt.result()    if f_vt    else None

            result["abuseipdb"]  = abuse_data
            result["virustotal"] = vt_data

            verdict = get_combined_verdict(abuse_data, vt_data)
            result["verdict"] = verdict

            if verdict == "malicious":
                result["valid"] = False
                result["errors"].append(
                    f"IP {base_ip} is flagged as MALICIOUS by threat intelligence sources. "
                    f"Request blocked."
                )
            elif verdict == "suspicious":
                result["warnings"].append(
                    f"IP {base_ip} is flagged as SUSPICIOUS by threat intelligence sources. "
                    f"Review carefully before approving."
                )

    return jsonify(result)


@app.route("/api/app-id-suggestions")
def app_id_suggestions():
    return jsonify(get_suggestions(request.args.get("puerto", "")))


if __name__ == "__main__":
    app.run(debug=True)
