#
# Parse the cloudtrail log
#
#

import json
import gzip

class CloudTrailLogParser(object):

    #loads the gzip file and returns json
    def getCompleteJson(self,gzipfile):
        filename = gzipfile
        try:
            with gzip.open(filename, 'r') as g_file:
                zip_extract = json.load(g_file)
            return zip_extract

        except:
            return('error loading the gzip file')


    # list all the iam users in the json file
    def getIamUser(self, datastore):
        try:
            records = datastore['Records']
        except Exception as e :
            print(e)
            return('Couldnt find key Records. Valid Logs ? ')
        user_list = []
        try:
            for rec in records:

                iamuser = rec['userIdentity']

                if iamuser.get('type') == 'IAMUser':
                    #print(iamuser.get('userName'), rec.get('eventName'), rec.get('eventSource'))

                    user = iamuser.get('userName')
                    if user not in user_list:
                        user_list.append(user)
            return user_list
        except:
            return('Error loading users')


    # list the iam users and the list of unique events they triggered according to cloudtrail log
    def getUserEventTriggered(self, datastore, userlist):
        user_events_dictionary = {}
        try:
            records = datastore['Records']
        except:
            return('Couldnt find key Records. Valid Logs ? ')

        try:
            for user in userlist:
                user_event_list = []

                for rec in records:

                    iamuser = rec['userIdentity']
                    if user == iamuser.get('userName'):

                        user_eventname = rec.get('eventName')
                        if user_eventname not in user_event_list:
                            user_event_list.append(user_eventname)

                user_events_dictionary[user] = user_event_list

            return user_events_dictionary

        except:
            return('Error loading user events')