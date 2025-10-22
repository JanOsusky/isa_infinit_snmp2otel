from flask import Flask, request

app = Flask(__name__)
@app.route('/v1/metrics', methods=['POST'])
def result():
    print(request.json)
    return "Recieved!" , 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=4318)