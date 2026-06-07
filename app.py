from flask import Flask, render_template, request, jsonify
import subprocess
import os
import uuid

app = Flask(__name__)

@app.route('/')
def index():
    # Serves the HTML frontend from the templates/ directory
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan():
    # Receives data from the frontend
    data = request.json
    target = data.get('target')
    mode = data.get('mode', 'quick')

    if not target:
        return jsonify({"error": "Target IP/Domain is required"}), 400

    # Generate a unique filename for this specific scan session to prevent file collisions
    unique_report_name = f"recon_report_{uuid.uuid4().hex}.md"

    try:
        # Securely call the net_auditor.py script
        # Passing the unique filename via the -o flag
        process = subprocess.run(
            ['python3', 'net_auditor.py', '-t', target, '-m', mode, '-o', unique_report_name],
            capture_output=True,
            text=True
        )

        # Check if the script successfully created the unique markdown report
        if os.path.exists(unique_report_name):
            with open(unique_report_name, 'r') as f:
                report_content = f.read()
            
            # Clean up the file after reading it into memory to keep the directory clean
            os.remove(unique_report_name)
            
            return jsonify({
                "report": report_content, 
                "logs": process.stdout
            })
        else:
            # If the file wasn't created, something went wrong inside net_auditor.py
            return jsonify({
                "error": "Scan failed or report was not generated.", 
                "logs": process.stderr or process.stdout
            }), 500

    except Exception as e:
        # Catch any system or execution errors
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Runs the web server on http://127.0.0.1:5000
    app.run(debug=True, port=5000)
