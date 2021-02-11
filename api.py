from flask import Flask, jsonify, request, make_response
import jwt
import datetime
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token') #http://127.0.0.1:5000/route?token=alshfjfjdklsfj89549834ur

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 403

        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'message' : 'Token is invalid!'}), 403

        return f(*args, **kwargs)

    return decorated


@app.route('/unprotected')
def unprotected():
    return jsonify({'message': 'Anyone can view this'})


@app.route('/protected')
@token_required
def protected ():
    return jsonify({'message': 'Hello World. Successfully authenticated.'})


@app.route('/login')
def login():
    auth = request.authorization

    if auth and auth.password == 'secret':
        token = jwt.encode({'user' : auth.username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(seconds=120)}, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({'token' : token})

    return make_response('Could not verify!', 401, {'WWW-Authenticate' : 'Basic realm="Login Required"'})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=10001)