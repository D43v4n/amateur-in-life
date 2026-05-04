import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from validators import validate_ip, validate_port, get_ip_type
from app_id_data import get_suggestions
from osint import check_insecure_ports, get_base_ip, check_abuseipdb, OSINT_BLOCK_SCORE

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


with app.app_context():
    db.create_all()


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
                  "app_id", "accion", "direccion", "comentario"]
        lists = {f: request.form.getlist(f"{f}[]") for f in fields}
        count = len(lists["ip_origen"])

        rules_data = []
        for i in range(count):
            d = {f: (lists[f][i] if i < len(lists[f]) else "") for f in fields}
            d["errors"] = _validate_rule(d)
            rules_data.append(d)

        if all(not d["errors"] for d in rules_data):
            for d in rules_data:
                db.session.add(FirewallRule(
                    ip_origen=d["ip_origen"].strip(),
                    ip_destino=d["ip_destino"].strip(),
                    puerto=d["puerto"].strip(),
                    protocolo=d["protocolo"],
                    app_id=d["app_id"].strip() or None,
                    accion=d["accion"],
                    direccion=d["direccion"],
                    comentario=d["comentario"].strip() or None,
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
    data = request.get_json(silent=True) or {}
    ip_destino = data.get("ip_destino", "").strip()
    puerto = data.get("puerto", "").strip()

    result = {
        "valid": True,
        "errors": [],
        "warnings": [],
        "is_public_dest": False,
        "insecure_ports": [],
        "osint": None,
    }

    # Insecure port check (always, for any destination)
    if puerto:
        bad_ports = check_insecure_ports(puerto)
        if bad_ports:
            result["insecure_ports"] = bad_ports
            names = ", ".join(f"{p['port']} ({p['name']})" for p in bad_ports)
            result["errors"].append(
                f"Plaintext/insecure port(s) detected: {names}. Use encrypted equivalents (e.g. 443, 22, 587/TLS)."
            )
            result["valid"] = False

    # OSINT check only for public destination IPs
    if ip_destino and get_ip_type(ip_destino) == "public":
        result["is_public_dest"] = True
        base_ip = get_base_ip(ip_destino)
        osint = check_abuseipdb(base_ip)

        if osint is None:
            if not os.environ.get("ABUSEIPDB_API_KEY"):
                result["warnings"].append(
                    "OSINT check skipped — set ABUSEIPDB_API_KEY environment variable to enable AbuseIPDB lookups."
                )
        else:
            result["osint"] = osint
            score = osint["score"]
            if score >= OSINT_BLOCK_SCORE:
                result["errors"].append(
                    f"AbuseIPDB confidence score is {score}% for {base_ip} — IP flagged as malicious. Request blocked."
                )
                result["valid"] = False
            elif score > 0:
                result["warnings"].append(
                    f"AbuseIPDB reports {osint['reports']} incident(s) for {base_ip} (confidence {score}%). Review before approving."
                )

    return jsonify(result)


@app.route("/api/app-id-suggestions")
def app_id_suggestions():
    return jsonify(get_suggestions(request.args.get("puerto", "")))


if __name__ == "__main__":
    app.run(debug=True)
