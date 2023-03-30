from flask import Flask, request, jsonify
from pprint import pprint

app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json
    print(f"Webhook received:\n")
    pprint(data)
    print(f"\n")

    return jsonify({'status': 'success'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)