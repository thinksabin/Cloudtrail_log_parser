#
# web api for cloudtrail parser
#

from flask import Flask, request
from flask_restful import Resource, Api, reqparse
from json import dumps
from cloudtrail_logparser import *
import werkzeug, os


app = Flask(__name__)
api = Api(app)



class iamusers(Resource):
    def get(self):
        cloudtrail_lp = CloudTrailLogParser()
        results = cloudtrail_lp.getCompleteJson()
        iamusers = cloudtrail_lp.getIamUser(results)
        return iamusers


class userTriggeredEvents(Resource):
    def get(self):
        cloudtrail_lp = CloudTrailLogParser()
        results = cloudtrail_lp.getCompleteJson()
        eventTriggeredPerUsers = cloudtrail_lp.getUserEventTriggered(results,cloudtrail_lp.getIamUser(results))
        return eventTriggeredPerUsers

class uploadfile(Resource):
    decorators = []

    def post(self):
        UPLOAD_FOLDER = 'cloudtrail/logs'
        parser = reqparse.RequestParser()
        parser.add_argument('file', type=werkzeug.datastructures.FileStorage, location='files')
        parser.add_argument('output')
        data = parser.parse_args()
        #print(data)

        if data['file'] == "" or data['file'] == 'None':
            return {
                'data': '',
                'message': 'No file found',
                'status': 'error'
            }

        json_file = data['file']
        outout = data['output']
        if data['output'] == 'listusers':
            datastore = json.load(data['file'])
            print(datastore)
            cloudtrail_lp = CloudTrailLogParser()
            iamusers = cloudtrail_lp.getIamUser(datastore)
            return iamusers

        elif data['output'] == 'userevents':
            datastore = json.load(data['file'])
            print(datastore)
            cloudtrail_lp = CloudTrailLogParser()
            eventTriggeredPerUsers = cloudtrail_lp.getUserEventTriggered(datastore, cloudtrail_lp.getIamUser(datastore))
            return eventTriggeredPerUsers
        else:
            return ('Unknown Function')

api.add_resource(iamusers, '/iamusers')
api.add_resource(userTriggeredEvents, '/usertriggeredevents')
api.add_resource(uploadfile,'/upload')

if __name__ == '__main__':
    app.run(port='5002')
