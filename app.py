from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import sqlite3
import json

sqlite_file = r'C:\Users\ilayb\Desktop\Stuff\PC\Backend\env\MainDB.db'

app = Flask(__name__)

cors = CORS(app, resources={
        r'/*': {
            'origins': '*',
            'methods': ["OPTIONS", "GET", "POST"],
            "allow_headers": ["Authorisation"]
            }
        })

app.config['CORS_HEADERS'] = 'Content-Type'

# [DataBases]
def CreateUser(email, password):
    conn = sqlite3.connect(sqlite_file, check_same_thread=False)
    db = conn.cursor()
    query = """INSERT INTO users VALUES('{email}', '{password}');""".format(email=email, password=password)
    print(query)
    db.execute(query)
    conn.commit()
    conn.close()

def RetrieveData(col_name, table_name, shouldUseWhere, whereCol = None, equalTo = None):
    conn = sqlite3.connect(sqlite_file, check_same_thread=False)
    db = conn.cursor()
    query = """SELECT {col} FROM {table}""".format(col=col_name,table=table_name)
    if(shouldUseWhere):
        query2 = """ WHERE {wherecol} == '{equalto}'""".format(wherecol = whereCol, equalto = equalTo)
        query = query+query2
    db.execute(query)
    data  = db.fetchall()
    conn.commit()
    conn.close()
    return data

def InsertData(client_email, email, password, website):
    conn = sqlite3.connect(sqlite_file, check_same_thread=False)
    db = conn.cursor()
    query = """INSERT INTO pass_db VALUES('{client_email}', '{email}', '{password}', '{website}');""".format(client_email=client_email, email=email, password=password, website=website)
    db.execute(query)
    data  = db.fetchall()
    conn.commit()
    conn.close()

def LaunchQuery(query):
    conn = sqlite3.connect(sqlite_file, check_same_thread=False)
    db = conn.cursor()
    db.execute(query)
    data  = db.fetchall()
    conn.commit()
    conn.close()
    return data


# Data security
key1 = 'mAj4SHe1sTW74EBM'
key2 = 'To1dONaDb1UfxVzE'
def Enc(txtToEnc, key):
        txtToEnc = pad(txtToEnc.encode(),16)
        cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
        return base64.b64encode(cipher.encrypt(txtToEnc))

def Dec(txtToDec, key):
        txtToDec = base64.b64decode(txtToDec)
        cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
        return unpad(cipher.decrypt(txtToDec),16)


# [Pages (Server Responses)]
@app.route('/login', methods=['OPTIONS', 'POST'])
@cross_origin()
def login_request():
    json_data = request.json
    email = json_data['Email']
    password = json_data['Pass']
    data = RetrieveData("password","users",True,"email",email)
    if str(data) != "[]":
        db_pass = str(data[0][0])
        if password == db_pass:
            return 'A'
    return 'R'


@app.route('/register', methods=['OPTIONS', 'POST'])
@cross_origin()
def register_request():
    json_data = request.json
    email = json_data['Email']
    password = json_data['Pass']
    data = RetrieveData("password","users",True,"email",email)
    if str(data) == "[]": #Checking if user exists.
        CreateUser(email, password)
        return "A" #Allow
    return "R" #Reject


@app.route('/pass_page', methods=['OPTIONS', 'POST'])
@cross_origin()
def pass_request():
    json_data = request.json
    clientEmail = json_data['ClientEmail']
    data = RetrieveData("site_name, username, password","pass_db",True, "ClientEmail", clientEmail)
    json_string = json.dumps(data)
    json_string = json_string.replace('"',"")
    json_string = json_string.replace(' ', '')
    json_string = json_string.replace('[', "")
    json_string = json_string.replace(']', "")
    print(json_string)
    return json_string


@app.route('/SignUpData', methods=['OPTIONS', 'POST'])
@cross_origin()
def signup_data():
    json_data = request.json
    clientEmail = json_data['ClientEmail']
    email = json_data['Email']
    password = json_data['Pass']
    website = json_data['Website']
    query = "SELECT username, password FROM pass_db WHERE ClientEmail = '{clientEmail}' and site_name = '{website}';".format(clientEmail=clientEmail, website=website)
    data = LaunchQuery(query)
    json_string = json.dumps(data)
    print("message:")
    print(json_string)
    if(json_string == "[]"):
        InsertData(clientEmail, email, password, website)
        return "Added"
    return "Not Added"

@app.route('/ReturnWebsiteInfo', methods=['OPTIONS', 'POST'])
@cross_origin()
def ReturnWebsiteInfo():
    json_data = request.json
    clientEmail = json_data['ClientEmail']
    website = json_data['Website']
    query = "SELECT username, password FROM pass_db WHERE ClientEmail = '{clientEmail}' AND site_name = '{website}';".format(clientEmail=clientEmail, website=website)
    print(query)
    data = LaunchQuery(query)
    json_string = json.dumps(data)
    print("string " + json_string)
    json_string = json_string[2:-2]
    json_string = json_string.replace('"', '')
    json_string = json_string.replace(' ', '')
    return json_string

@app.route('/RemoveRow', methods=['OPTIONS', 'POST'])
@cross_origin()
def RemoveRow():
    json_data = request.json
    clientEmail = json_data['ClientEmail']
    website = json_data['Website']
    query = "DELETE FROM pass_db WHERE ClientEmail = '{clientEmail}' AND site_name = '{website}';".format(clientEmail=clientEmail, website=website)
    print(query)
    data = LaunchQuery(query)
    json_string = json.dumps(data)
    print("string " + json_string)
    return json_string

#Functions

def ValidReturn(value):
    data = jsonify({"data":value})
    data.headers.add('Access-Control-Allow-Origin', '*')
    return data


app.run()

