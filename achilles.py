#!/usr/bin/env python3

import argparse
import requests
import validators
import yaml
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment

parser = argparse.ArgumentParser(description="The Achilles HTML Vulnerability Analyser Version 1.0")

parser.add_argument("-v", "--version", action="version", version="%(prog)s 1.0")
parser.add_argument("url", type=str, help="The URL of the website to analyze")
parser.add_argument("--config", help="Path to configuration file")
parser.add_argument("-o", "--output", help="Report file output path")

args = parser.parse_args()

config = {'forms': True, 'comments': True, 'password_inputs': True}
if(args.config):
	print("Using config file: " + args.config + "\n")
	configFile = open(args.config, "r")
	configFromFile = yaml.load(configFile, Loader=yaml.SafeLoader)
	if(configFromFile):
		config = {**config, **configFromFile}

report = ""
url = args.url

if(validators.url(url)):
	result_html = requests.get(url).text
	parsed_html = BeautifulSoup(result_html, "html.parser")

	forms = (parsed_html.find_all('form'))
	comments = parsed_html.find_all(string=lambda text:isinstance(text,Comment))
	password_inputs = parsed_html.find_all('input', {"name":"password"})

	if(config["forms"]):
		for form in forms:
			if(form.get("action").find("https") < 0 and urlparse(url).scheme != "https"):
				report += "Form Issue: Insecure form action " + form.get("action") + " found in document\n"

	if(config["comments"]):
		for comment in comments:
			if(comment.find("key: ") > -1):
				report += "Comment Issue: Key is found in the HTML comments, please remove\n"

	if(config["password_inputs"]):
		for password_input in password_inputs:
			if(password_input.get("type") != "password"):
				report += "Input Issue: Password in plain text\n"

else: print("Invalid URL")

if(report == ""):
	report += "Nice job! Your HTML is secure!\n"
else:
	header = "VULNERABILITY REPORT\n"
	header += "====================\n"
	report = header + report

print(report)

if(args.output):
	f = open(args.output, "w")
	f.write(report)
	f.close()
	print("Report saved to: " + args.output)