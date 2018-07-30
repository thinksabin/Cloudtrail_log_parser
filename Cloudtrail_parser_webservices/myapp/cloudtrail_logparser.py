#
# Parse the cloudtrail log
#
#

import json


class CloudTrailLogParser(object):

    #loads the json file and returns
    # def getCompleteJson(self):
    #     filename = 'sanitized_cloudtrail_example.json'
    #     try:
    #         with open(filename, 'r') as json_file:
    #             datastore = json.load(json_file)
    #         return datastore
    #
    #     except:
    #         print('error loading the json file')

    # list all the iam users in the json file
    def getIamUser(self, datastore):
        records = datastore['Records']
        user_list = []
        for rec in records:
            #print(rec)
            iamuser = rec['userIdentity']

            if iamuser.get('type') == 'IAMUser':
                #print(iamuser.get('userName'), rec.get('eventName'), rec.get('eventSource'))
                user = iamuser.get('userName')
                if user not in user_list:
                    user_list.append(user)
        return user_list

    # list the iam users and the list of unique events they triggered according to cloudtrail log
    def getUserEventTriggered(self, datastore, userlist):
        records = datastore['Records']
        user_events_dictionary = {}
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

#
# if __name__ == '__main__':
#     cloudtrail_lp= CloudTrailLogParser()
#     datastore = cloudtrail_lp.getCompleteJson()
#     userlist = cloudtrail_lp.getIamUser(datastore)
#     print(userlist)
#
#     user_events = cloudtrail_lp.getUserEventTriggered(datastore, userlist)
#     print(user_events)