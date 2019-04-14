import csv
import json
import requests

url_projects = "https://172.16.206.249/pro/api/projects"
url_nodes = "https://172.16.206.249/pro/api/nodes"
url_postNodes = "https://172.16.206.249/pro/api/"
token = "PuycKGjOiD6r0kC_ajbqG4cf"
headers = {'Authorization': 'Token token='+token, 'Content-Type': 'application/json', 'Dradis-Project-Id': '2'}

#json.loads provides a list of dict.  This enumerates the list so we can search by dict.
def findProjects(values, projectName):
    for x in values:
        if x['name'] == projectName:
            return x['id']
    return None

#Requests list of projects from API
projects = requests.get(url_projects, headers=headers, verify=False)

#Create List of Dictionaries from JSON.
projectsJSON = json.loads(projects.text)

#Find your project number.
project = str(findProjects(projectsJSON, 'TPIN'))

headers = {'Authorization': 'Token token='+token, 'Content-Type': 'application/json', 'Dradis-Project-Id': project}

nodes = requests.post(url_postNodes, headers=headers, data=table  verify=False)

