import requests
import json
import csv
import argparse

token = "PuycKGjOiD6r0kC_ajbqG4cf"

rule_title = "title"
vuln_id = "V-72841"
ipAddress = "192.168.112.10"
vuln_id_severity = "medium"
group_title	 = "SRG-APP-000142-DB-000094"
rule_id	= "SV-87493r2_rule"
stig_id	= "PGS9-00-000100"
discussion = "Discussion stuff"
check_content = "Check Content Stuff"
fix_text = "Fix stuff"
mitigations = "Insert mitigations here if this is a finding."
status = "open"

def findJSON(values, searchName):
    for x in values:
        if x['name'] == searchName:
            return x['id']
    return None

def getIP(stigFile):
    ipList= []
    with open (stigFile) as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            for x in ipList:
                if row['IPAddress'] != x:
                    ipList.append(row['IPAddress'])
    return ipList


def getProjects(projectName):
    url_projects = "https://172.16.206.249/pro/api/projects"
    headers = {'Authorization': 'Token token='+token, 'Content-Type': 'application/json'}
    projects = requests.get(url_projects, headers=headers, verify=False)
    projectsJSON = json.loads(projects.text)
    project = str(findJSON(projectsJSON, projectName))
    return project

def getNode(projectNum):
    headers = {'Authorization': 'Token token='+token, 'Content-Type': 'application/json', 'Dradis-Project-Id': str(projectNum)}
    node = requests.get("https://172.16.206.249/pro/api/nodes", headers=headers, verify=False)
    nodeJSON = json.loads(node.text)
    project = str(findJSON(nodeJSON, projectNum))
    return project

def addNode(projectNum, ipList):
    headers = {'Authorization': 'Token token='+token, 'Content-Type': 'application/json', 'Dradis-Project-Id': str(projectNum)}
    nodeJSON = json.dumps({
        "node":{"label":"STIG Checklist", "type_id": 1, "parent_id": null}
    })
    node = requests.post("https://172.16.206.249/pro/api/nodes", data=nodeJSON, headers=headers, verify=False)
    for x in ipList:

        node = requests.post("https://172.16.206.249/pro/api/nodes", headers=headers, verify=False)

def uploadSTIG(stigFile, projectNum, table):
    headers = {'Authorization': 'Token token='+token, 'Content-Type': 'application/json', 'Dradis-Project-Id': str(projectNum)}
    with open (stigFile) as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            rule_title = row['Rule Title']
            vuln_id = row['Vuln ID']
            ipAddress = row['IPAddress']
            vuln_id_severity = row["Severity"]
            group_title = row["Group Title"]
            rule_id = row["Rule ID"]
            stig_id = row['STIG ID']
            discussion = row['Discussion']
            check_content = row['Check Content']
            fix_text = row['Fix Text']
            status = row['Status']

            #build JSON request
            issue = json.dumps({
                "issue":{
                    "text": "#[Title]#\r\n"+vuln_id+"\r\n\r\n#[Rule-ID]#\r\n"+rule_title+"\r\n\r\n#[Severity]#\r\n"+vuln_id_severity+"\r\n\r\n#[Group_Title]#\r\n"+group_title+"\r\n\r\n#[Rule-ID]#\r\n"+rule_id+"\r\n\r\n#[STIG-ID]#\r\n"+stig_id+"\r\n\r\n#[Discussion]#\r\n"+discussion+"\r\n\r\n#[Check_Content]#\r\n"+check_content+"\r\n\r\n#[Fix_Text]#\r\n"+fix_text+"\r\n\r\n#[Status]#\r\n"+status+"\r\n\r\n"
                }
            })
            #Post requests
            requests.post("https://172.16.206.249/pro/api/issues", data=issue, headers=headers, verify=False)


def addTable(stigFile, projectNum, node):
    vuln_id_severity = "medium"
    status = "open"
    ipAddress = "0.0.0.0"

    cat1_open = 0
    cat2_open = 0
    cat3_open = 0

    cat1_pass = 0
    cat2_pass = 0
    cat3_pass = 0 

    cat1_na = 0
    cat2_na = 0
    cat3_na = 0
    
    with open (stigFile) as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            ipAddress = row['IPAddress']
            vuln_id_severity = row["Severity"]
            status = row['Status']
            if status == 'Open':
                if vuln_id_severity == 'high':
                    cat1_open += 1
                elif vuln_id_severity == 'medium':
                    cat2_open += 1
                elif vuln_id_severity == 'low':
                    cat3_open += 1
            
            elif status == 'Not A Finding':
                if vuln_id_severity == 'high':
                    cat1_pass += 1
                elif vuln_id_severity == 'medium':
                    cat2_pass += 1
                elif vuln_id_severity == 'low':
                    cat3_pass += 1
            elif status == 'Not Applicable':
                if vuln_id_severity == 'high':
                    cat1_na += 1
                elif vuln_id_severity == 'medium':
                    cat2_na += 1
                elif vuln_id_severity == 'low':
                    cat3_na += 1

    #build table

    stigTable = json.dumps({"note":{"text": "#[Title]#\r\nSTIG Table\r\n\r\n#[Table]#\r\n|_. |_. Pass |_. Fail |_. Not Applicable |\r\n|CAT I |"+str(cat1_pass)+"|"+str(cat1_open)+"|"+str(cat1_na)+"|\r\n|CAT II |"+str(cat2_pass)+"|"+str(cat2_open)+"|"+str(cat2_na)+"|\r\n|CAT III |"+str(cat3_pass)+"|"+str(cat3_open)+"|"+str(cat2_na)+"|\r\n\r\n"}})

    note = requests.post("https://172.16.206.249/pro/api/nodes/"+node+"/notes", data=stigTable, headers=headers, verify=False)
    print(note.status_code)
    print(note.json)

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Location of STIG csv file", action="store")
    parser.add_argument("project", help="Name of Project To Upload to", action="store")
    parser.add_argument("-t","--table", help="Create table", action="store_true")
    args = parser.parse_args()

    uploadSTIG(args.file, getProjects(args.project), args.table)

if __name__ == "__main__":
    main()