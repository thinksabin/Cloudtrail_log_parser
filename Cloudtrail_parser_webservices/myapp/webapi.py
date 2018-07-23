#
# web api for cloudtrail parser
#

from flask import Flask, request
from flask_restful import Resource, Api
from json import dumps
from cloudtrail_logparser import *


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



api.add_resource(iamusers, '/iamusers')
api.add_resource(userTriggeredEvents, '/usertriggeredevents')

if __name__ == '__main__':
    app.run(port='5002')
