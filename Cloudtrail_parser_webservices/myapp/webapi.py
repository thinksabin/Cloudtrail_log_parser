#
# web api for cloudtrail parser
#

from flask import Flask, request
from flask_restful import Resource, Api, reqparse
from cloudtrail_logparser import *
import werkzeug, os


app = Flask(__name__)
api = Api(app)


class uploadfile(Resource):

    def post(self):

        parser = reqparse.RequestParser()
        parser.add_argument('file', type=werkzeug.datastructures.FileStorage, location='files')
        parser.add_argument('output')
        data = parser.parse_args()

        gzip_json_file = data['file']
        output = data['output']

        filename = gzip_json_file.filename


        if output == 'listusers':
            try:
                cloudtrail_lp = CloudTrailLogParser()
                try:
                    output_gzip_extract = cloudtrail_lp.getCompleteJson(gzip_json_file)
                except:
                    return ('invalid gz file')
                iamusers = cloudtrail_lp.getIamUser(output_gzip_extract)

                return iamusers

            except Exception as e:
                print(e)
                return ('Failed to list users')

        elif output == 'userevents':
            try:
                cloudtrail_lp = CloudTrailLogParser()
                output_gzip_extract = cloudtrail_lp.getCompleteJson(gzip_json_file)
                eventTriggeredPerUsers = cloudtrail_lp.getUserEventTriggered(output_gzip_extract,
                                                                             cloudtrail_lp.getIamUser(output_gzip_extract))
                return eventTriggeredPerUsers

            except Exception as e:
                print(e)
                return ('Failed to list user events')

        else:
            return ('Unknown Function')


api.add_resource(uploadfile,'/upload')

if __name__ == '__main__':
    app.run(port='5002')
