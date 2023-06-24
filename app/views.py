from flask import Flask
from flask import send_file
from flask import render_template
from flask import request, make_response
from flask import jsonify
from flask_cors import CORS
from datetime import datetime
from base64 import encodebytes
from bson.objectid import ObjectId

from . import app
from app.models import users
from app.models import lightningwallets
from app.models import lightningchallenges

#import docker
import pyqrcode
import secrets
import socket
import pymongo  # package for working with MongoDB
import logging
import jwt
import os
from sys import stdout

from functools import wraps

from app.bech import encode_string
from app.der import decode_signature

from app.ecc import elliptic_curve
from app.ecc import ecdsa
from app.ecc import point,hex_to_int

from settings import *

logger = logging.getLogger('simple_example')
logger.setLevel(logging.DEBUG)
console = logging.StreamHandler(stdout)
console.setLevel(level=logging.DEBUG)
formatter =  logging.Formatter('%(levelname)s : %(message)s')
console.setFormatter(formatter)
logger.addHandler(console)

# https://trstringer.com/logging-flask-gunicorn-the-manageable-way/
# does not work
#if __name__ != '__main__':
gunicorn_logger = logging.getLogger('gunicorn.debug')
logger.handlers = gunicorn_logger.handlers
logger.setLevel(gunicorn_logger.level)

#onion_address = "yri5o7gtfa4yabmroogtiyqbulw4g4to3zukuwezpf3er6ifhy5bwcyd.onion"

## move this to mongo
#challenges = []

G = point(
    hex_to_int("79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798"),
    hex_to_int("483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8")
)

secp256k1 = elliptic_curve(
    0,
    7,
    hex_to_int("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F"),
    hex_to_int("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"),
    G
)

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/api/data")
def get_data():
    return app.send_static_file("data.json")

@app.route("/auth")
def auth():
    logger.debug('Auth')
    #32 byte challenge k1
    k1 = secrets.token_hex(32)
    #host_address = socket.gethostbyname(socket.gethostname())
    host_address = "54.176.48.9"
    #client = docker.DockerClient()
    #container = client.containers.get('fplb')
    #host_address = container.attrs['NetworkSettings']['IPAddress']
    url = "http://"+host_address+"/signin?tag=login&k1="+k1
    print(url)

    #add k1 to challenges
    # store in db instead
    #challenges.append(k1)
    lightning_challenge_model = lightningchallenges.LightningChallenges()
    
    #bech32 encode string
    bech_32_url = encode_string(url)
    lightning_challenge_model.create({"k1": k1, "bech_32_url": bech_32_url})

    #response = {'lnurl': bech_32_url}
    return jsonify({'lnurl' : bech_32_url})

@app.route("/signin")
def signin():

    ## This gets called by the lightning network.

    user_model = users.Users()
    lightning_wallet_model = lightningwallets.LightningWallets()
    lightning_challneges_model = lightningchallenges.LightningChallenges()

    error = {
        "status" : False,
        "message" : None
    }

    #long hex string --> r: INT,Base 10: s: INT,Base 10
    der_sig = request.args.get("sig")
    #compressed public key needs to be encodeded
    public_key = ecdsa.compressed_to_point(request.args.get("key"),secp256k1)
    k1 = request.args.get("k1")
    logger.debug("sig k1: "+k1)
    if der_sig == None or public_key == None or k1 == None:
        error["status"] = True
        error["message"] = "P_K,Sig or k1 misssing"

    ## look up the k1 from the db
    ## we don't have the public key yet, so use the k1
    print(k1)
    print(public_key.__str__())
    pending_challenge = lightning_challneges_model.find_by_k1(k1)
    print(pending_challenge)

    if pending_challenge is None:
        print('Challenge not found')
        error["status"] = True
        error["message"] = "Invalid challenge"
    else:
        print('found challenge')
        ## do we really want to delete it?
        ## Yes this is just a challenge. Delete it.  But do it in the return area after we are done.
        # We do want to keep track of the public key here.

        ## Check to see if the public key is already registered.
        ##   If so, get the user for this key
        ##     If user exists, mark online
        ##     If not, prompt the user to connect to an email address, and begin email verification 
        ##   If no public key is found, create one, and begin email verification

        existing_wallet = lightning_wallet_model.find_by_publickey(public_key.__str__())
        print(existing_wallet)

        if existing_wallet is None:
            print('existing wallet not found - creating')

            new_wallet = lightning_wallet_model.create(
                {
                    "publickey": public_key.__str__(), 
                    "userid": "0",
                    "userconnected": False,
                    "emailaddress": "",
                    "emailvalidated": False,
                    "k1": k1,
                    "bech_32_url": pending_challenge["bech_32_url"],

                 }
            )
        else:
            print('found existing wallet')

            ## TODO update with this challenge's bech_32_url
            existing_wallet['bech_32_url'] = pending_challenge['bech_32_url']
            lightning_wallet_model.update(existing_wallet['_id'], existing_wallet)
            
            if existing_wallet['userconnected']:
                print('user connected')
                user = user_model.find_by_id(existing_wallet['userid'])

                
                if user:
                    ## do we need to do something with the user?
                    print('got user')

                else:
                    print('user not found')

                    ## TODO send out an email verification - but we don't have the email yet... 

            else:
                print('user not connected')

            

    try:
        sig = decode_signature(der_sig)
    except:
        sig = None
        error["status"] = True
        error["message"] = "signature not encoded right"

    try:
        sig_status = ecdsa.raw_verify(public_key,k1,sig,secp256k1)
        if sig_status == False:
            error["status"] = True
            error["message"] = "Signature is invalid"
    except:
        error["status"] = True
        error["message"] = "Signature validation failed"


    if error["status"] == True:
        return jsonify(
            status="ERROR",
            reason=error["message"]
        )
    else:
        # delete the pending challenge 
        lightning_challneges_model.delete(pending_challenge["_id"])
        return jsonify(
            status = "OK",
            event = "LOGGEDIN"
        )

@app.route("/generate_qr/<bech_32_url>")
def generate_qr(bech_32_url = None):
    #save as url code and send
    qr = pyqrcode.create(bech_32_url)
    qr.svg("ln-auth-challenge.svg",scale=8)
    return send_file("../ln-auth-challenge.svg",mimetype="image/svg+xml")

@app.route("/me")
def me():
    #print(request.__dict__)
    ## TODO look this wallet up from the database
    ## assuming here we have a pubkey, but we can use the challenge url again
    ## or maybe we can use session?

    ## for now, just using the intial bech_32_url aka challenge url
    bech_32_url = request.args.get("bech_32_url") # or ""
    print(bech_32_url)

    user_model = users.Users()
    lightning_wallet_model = lightningwallets.LightningWallets()
    lightning_challneges_model = lightningchallenges.LightningChallenges()

    this_wallet = lightning_wallet_model.find_by_bech_32_url(bech_32_url)

    if this_wallet == None:
        print('did not find wallet by bech_32_url')

    else:
        print('found wallet by bech_32_url')

        if this_wallet['userid'] == "0":
            print('user id set to zero')
            auth_token = lightning_wallet_model.encode_auth_token(str(this_wallet['_id']))
            print(auth_token)
            if auth_token:
                responseObject = {
                    'userid': 0,
                    'name': 'anonymous user',
                    'status': 'success',
                    'message': 'Successfully logged in.',
                    'auth_token': auth_token,
                    'do_email_validation': True
                }
                return make_response(jsonify(responseObject)), 200
        else:

            user = user_model.find_by_id(ObjectId(this_wallet['userid']))
            if user == None:
                print('user not found')
                auth_token = lightning_wallet_model.encode_auth_token(str(this_wallet['_id']))
                print(auth_token)
                if auth_token:
                    responseObject = {
                        'userid': 0,
                        'name': 'anonymous user',
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token,
                        'do_email_validation': True
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                print('found user')
                ## generate an auth token
                auth_token = lightning_wallet_model.encode_auth_token(str(this_wallet['_id']))
                print(auth_token)
                if auth_token:
                    responseObject = {
                        'userid': user['_id'],
                        'name': user['name'],
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token,
                        'do_email_validation': False
                    }
                    return make_response(jsonify(responseObject)), 200
        #except:
        #    logger.debug('did not find userid in wallet.  Is login complete?')
            
    responseObject = {
        'status': 'fail',
        'message': 'Login process incomplete'
        }
    return make_response(jsonify(responseObject)), 200


# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_model = users.Users()
        lightning_wallet_model = lightningwallets.LightningWallets()
        token = None
        # jwt is passed in the request header
        auth_header = request.headers.get('Authorization')
        if auth_header:
            print('found Auth header')
            token = auth_header.split(" ")[1]

        print(token)

        #if 'x-access-token' in request.headers:
        #    print('found x-access-token')
        #    token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        #try:
        # decoding the payload to fetch the stored details
        data = jwt.decode(token, JWT_SECRET_KEY, algorithms='HS256')

        print(data)

        wallet = lightning_wallet_model.find_by_id(data['sub'])
        if wallet:
            logger.debug('found wallet')
            current_user = user_model.find_by_id(wallet['userid'])
            if current_user:
                logger.debug('found current_user')

        #except:
        #    return jsonify({
        #        'message' : 'Token is invalid !!'
        #    }), 401
        # returns the current logged in users context to the routes
        return  f(current_user, *args, **kwargs)
  
    return decorated

## TODO Create admin_token_required wrapper

@app.route("/setup_database")
def setup_database():
    ## TODO check for admin superuser
    
    # first drop any previous entries
    ## todo remove this for production 
    ## This is not working in production - command dropDatabase requires authentication
    ## instead we can clean up manually
    #mongo_client = pymongo.MongoClient('mongodb://mongo:27017')
    #mongo_client.drop_database('customersdb');

    lightning_wallet_model = lightningwallets.LightningWallets()
    wallets = lightning_wallet_model.find({})
    for wallet in wallets:
        print('found wallet')
        lightning_wallet_model.delete(wallet['_id'])

    """

    # setup model(s)
    user_model = users.Users()

    user_list = [
    { "name": "Amy", "address": "Apple st 652"},
    { "name": "Hannah", "address": "Mountain 21"},
    { "name": "Michael", "address": "Valley 345"},
    { "name": "Sandy", "address": "Ocean blvd 2"},
    { "name": "Betty", "address": "Green Grass 1"},
    { "name": "Richard", "address": "Sky st 331"},
    { "name": "Susan", "address": "One way 98"},
    { "name": "Vicky", "address": "Yellow Garden 2"},
    { "name": "Ben", "address": "Park Lane 38"},
    { "name": "William", "address": "Central st 954"},
    { "name": "Chuck", "address": "Main Road 989"},
    { "name": "Viola", "address": "Sideway 1633"}
    ]
    for user_data in user_list:
        user_model.create(user_data)

    lightning_challneges_model = lightningchallenges.LightningChallenges()
    lightning_challneges_model.create({"k1": "1"})
    lightning_challneges_model.create({"k1": "2"})
    lightning_challneges_model.create({"k1": "3"})
    lightning_challneges_model.create({"k1": "4"})

    lightning_wallet_model = lightningwallets.LightningWallets()
    lightning_wallet_model.create({"publickey": "1"})
    """

    return jsonify({'success' : True})

@app.route("/user/email/<incoming_email>/start")
@token_required
def userEmailValidationStart(incoming_email = None):
    # start the email validation process.
    logger.debug(incoming_email)

    # get the email from the request
    # generate a verification code
    # save the verification code in the wallet
    # send an email containing the verification code and link
    return jsonify({'success' : True})

## Views for data validation and testing
## Todo - after roles and permissions are in, these should be protected by them

@app.route("/users/")
def users_list():
    # setup model(s)
    user_model = users.Users()
    return jsonify(user_model.find({})), 200

@app.route("/lightning/challenges")
def challenge_list():
    # setup model(s)
    lightning_challneges_model = lightningchallenges.LightningChallenges()
    return jsonify(lightning_challneges_model.find({})), 200

@app.route("/lightning/wallets")
def wallet_list():
    # setup model(s)
    lightning_wallet_model = lightningwallets.LightningWallets()
    return jsonify(lightning_wallet_model.find({})), 200

@app.after_request
def after_request(response):
  response.headers.add('Access-Control-Allow-Origin', '*')
  response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
  response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
  return response

