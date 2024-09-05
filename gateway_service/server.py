from flask import Flask, request, Response, redirect, session, render_template, send_file
import requests
from pymongo import MongoClient
import os
import gridfs
import json

server = Flask(__name__, template_folder='templates', static_folder='static')

@server.route("/", methods = ["GET"])
def home():
    if session:
        return redirect("/main")
    return render_template("home.html")

@server.route("/main", methods=["GET"])
def main():
    if not session:
        return redirect("http://127.0.0.1:8080/")
    data = [
        {
            'email': session['email']
        }
    ]
    return render_template('main.html', data = data)

@server.route("/download", methods=["GET"])
def download():
    return send_file('static/event_template.xlsx', as_attachment = True)

@server.route("/upload", methods=["POST"])
def upload():
    try:
        # Get the uploaded file from the request
        uploaded_file = request.files.get("file")
        if uploaded_file:
            #uploaded_file.save(os.path.join(os.getcwd(), uploaded_file.filename))
            if not uploaded_file.filename.lower().endswith(('.xlsx', '.xls')):
                return Response("Invalid file type. Only .xlsx and .xls files are allowed.", status=400)
            # take file from request
            # Check file size
            
            # init mongo client
            client = MongoClient("mongodb://localhost:27017")
            event_req_coll = client['event_automation']
            if not client:
                print("Mongo client not found")
                return Response("Mongo client not found", 500)
            fs = gridfs.GridFS(event_req_coll) 
            # call mongo service for upload
            fid = fs.put(uploaded_file)
            # send obj to msg_service publisher to eventQ
            response = requests.post("http://127.0.0.1:9989/publish_event", json = {'fid': str(fid), 'jwt':session['Authorization'].split(' ')[1], 'email': session['email']})
            if response.status_code != 200:
                print("Error posting to eventQ:",response)
                return Response(f"Error posting to EventQ:{response}", status = 500)
        return Response("Success", status=200)
    except Exception as e:
        print(f"Error: {str(e)}")
        return Response(f"Error: {str(e)}", status=500)   

@server.route("/consume", methods=["POST"])
def consume():
    # call event_service
    pass

@server.route("/login", methods = ["GET"])
def login():
    return redirect("http://127.0.0.1:5000/login")

if __name__ == "__main__":
    server.secret_key = "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"
    server.run(host="127.0.0.1", port = 8080) 