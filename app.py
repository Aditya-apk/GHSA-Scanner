from flask import Flask, render_template, request, jsonify
from github import Github
import requests
import os
from dotenv import load_dotenv
import json

load_dotenv()

app = Flask(__name__)

# Initialize GitHub client
g = Github(os.getenv('GITHUB_TOKEN'))

# GitHub GraphQL API endpoint and headers
query_url = 'https://api.github.com/graphql'
headers = {
    'Authorization': f'Bearer {os.getenv("GITHUB_TOKEN")}',
    'Content-Type': 'application/json',
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search_cve', methods=['POST'])
def search_cve():
    cve_id = request.form.get('cve_id')
    
    query = """
    query {
        securityAdvisories(first: 10, identifier: {type: CVE, value: "%s"}) {
            nodes {
                identifiers {
                    type
                    value
                }
                summary
                description
                severity
                cvss {
                    score
                    vectorString
                }
                publishedAt
                vulnerabilities(first: 1) {
                    nodes {
                        package {
                            name
                            ecosystem
                        }
                        vulnerableVersionRange
                    }
                }
            }
        }
    }
    """ % cve_id
    
    try:
        response = requests.post(query_url, json={'query': query}, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        
        if not data.get('data', {}).get('securityAdvisories', {}).get('nodes'):
            return jsonify({'error': 'CVE not found'})
        
        advisory_data = data['data']['securityAdvisories']['nodes'][0]
        if not advisory_data.get('vulnerabilities', {}).get('nodes'):
            return jsonify({'error': 'No package information found'})
            
        vuln_data = advisory_data['vulnerabilities']['nodes'][0]
        package_name = vuln_data['package']['name']
        
        if not package_name:
            return jsonify({'error': 'No package information found'})
        
        # Get repository information
        repo = g.search_repositories(f"{package_name} in:name")[0]
        
        tags = [tag.name for tag in repo.get_tags()]
        releases = [release.tag_name for release in repo.get_releases()]
        
        commits = [{
            'sha': commit.sha,
            'short_sha': commit.sha[:7],
            'message': commit.commit.message,
            'date': commit.commit.author.date.strftime('%Y-%m-%d'),
            'author': commit.commit.author.name,
            'html_url': commit.html_url
        } for commit in repo.get_commits()[:30]]
        
        return jsonify({
            'package_name': package_name,
            'tags': tags,
            'releases': releases,
            'commits': commits,
            'summary': advisory_data.get('summary', ''),
            'description': advisory_data.get('description', ''),
            'severity': advisory_data.get('severity', ''),
            'cvss': advisory_data.get('cvss', {}),
            'cvss4': advisory_data.get('cvss4', {}),
            'published_at': advisory_data.get('published_at', '')
        })
        
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Network error: {str(e)}'})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/get_commits', methods=['POST'])
def get_commits():
    try:
        release = request.form.get('release')
        tag = request.form.get('tag')
        package_name = request.form.get('package_name')
        
        if not package_name:
            return jsonify({'error': 'Please search for a CVE first'})
            
        repo = g.search_repositories(f"{package_name} in:name")[0]
        reference = release or tag
        
        commits = [{
            'sha': commit.sha,
            'short_sha': commit.sha[:7],
            'message': commit.commit.message,
            'date': commit.commit.author.date.strftime('%Y-%m-%d'),
            'author': commit.commit.author.name,
            'html_url': commit.html_url
        } for commit in repo.get_commits(sha=reference)[:30]]
        
        return jsonify({'commits': commits})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)